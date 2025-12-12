#!/usr/bin/env python3
"""
Remediation Module for OWASP Dependency Check Scanner
Generates upgrade suggestions for Maven dependencies by querying the H2 database.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Set
from time import sleep

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Install with: pip install requests")
    exit(1)

try:
    import jaydebeapi
except ImportError:
    print("Error: 'JayDeBeApi' library not found. Install with: pip install JayDeBeApi")
    exit(1)


@dataclass
class Dependency:
    """Represents a Maven dependency"""
    group_id: str
    artifact_id: str
    version: str
    pom_path: Path

@dataclass
class VulnerableRange:
    """Represents a vulnerable version range from the ODC database."""
    start_including: Optional[str] = None
    start_excluding: Optional[str] = None
    end_including: Optional[str] = None
    end_excluding: Optional[str] = None

class SemanticVersion:
    """Parse and compare semantic versions"""

    VERSION_PATTERN = re.compile(r'^(\d+)\.(\d+)(?:\.(\d+))?')

    def __init__(self, version_string: str):
        self.original = version_string
        self.major = 0
        self.minor = 0
        self.patch = 0
        self.valid = False
        clean = self._clean_version(version_string)
        match = self.VERSION_PATTERN.match(clean)
        if match:
            self.major = int(match.group(1))
            self.minor = int(match.group(2))
            self.patch = int(match.group(3) or 0)
            self.valid = True

    def _clean_version(self, version: str) -> str:
        for delimiter in ['-', '_']:
            version = version.split(delimiter)[0]
        for suffix in ['.RELEASE', '.FINAL', '.GA']:
            version = version.replace(suffix, '')
        return version

    def __str__(self) -> str:
        return self.original

    def __repr__(self) -> str:
        return f"SemanticVersion({self.original})"

    def __eq__(self, other: 'SemanticVersion') -> bool:
        if not isinstance(other, SemanticVersion):
            return False
        return (self.major == other.major and
                self.minor == other.minor and
                self.patch == other.patch)

    def __lt__(self, other: 'SemanticVersion') -> bool:
        if not isinstance(other, SemanticVersion):
            return False
        if self.major != other.major:
            return self.major < other.major
        if self.minor != other.minor:
            return self.minor < other.minor
        return self.patch < other.patch

    def __le__(self, other: 'SemanticVersion') -> bool:
        return self == other or self < other

    def __gt__(self, other: 'SemanticVersion') -> bool:
        return not self <= other

    def __ge__(self, other: 'SemanticVersion') -> bool:
        return not self < other

    def is_same_major(self, other: 'SemanticVersion') -> bool:
        return self.major == other.major


class RemediationGenerator:
    """
    Generates remediation suggestions by querying Maven repositories
    and checking for vulnerabilities in the ODC H2 database.
    """

    UNSTABLE_PATTERNS = [
        'SNAPSHOT', 'alpha', 'beta', 'RC', 'M1', 'M2', 'M3', 'M4', 'M5',
        'CR', 'BUILD', 'dev', 'preview', 'incubating'
    ]

    def __init__(self, maven_repo_url: Optional[str] = None, odc_data_dir: Optional[str] = None, allow_major_upgrade: bool = False, transitive_depth: int = 0):
        self.maven_repo_url = maven_repo_url or os.getenv('MAVEN_REPO_URL', 'https://repo1.maven.org/maven2/')
        if not self.maven_repo_url.endswith('/'):
            self.maven_repo_url += '/'
        self._metadata_cache = {}
        self._vulnerability_cache = {}
        self._pom_cache = {}  # Cache for POM dependencies: (group, artifact, version) -> List[dependencies]
        self.allow_major_upgrade = allow_major_upgrade
        self.transitive_depth = transitive_depth

        self.odc_data_dir = odc_data_dir or os.getenv('DEPENDENCY_CHECK_DATA', '/usr/share/dependency-check/data')
        db_path_for_jdbc = os.path.abspath(os.path.join(self.odc_data_dir, 'odc'))
        db_file_path = f"{db_path_for_jdbc}.mv.db"

        if not os.path.exists(db_file_path):
            print(f"\n[DB] FATAL ERROR: ODC database file not found at {db_file_path}\n")
            raise FileNotFoundError(f"H2 database file not found at {db_file_path}")

        self.db_conn_string = f"jdbc:h2:file:{db_path_for_jdbc}"
        self.db_user = "sa"
        self.db_password = "password"
        self.h2_jar_path = self._find_h2_driver()

        if not self.h2_jar_path:
            print("\n[DB] WARNING: H2 driver (h2-*.jar) not found. Vulnerability checks will be SKIPPED.\n")

    def _find_h2_driver(self) -> Optional[str]:
        local_jars = glob.glob('./h2-*.jar')
        if local_jars: return os.path.abspath(local_jars[0])
        dc_home = os.getenv('DEPENDENCY_CHECK_HOME')
        if dc_home:
            dc_jars = glob.glob(os.path.join(dc_home, 'lib', 'h2-*.jar'))
            if dc_jars: return os.path.abspath(dc_jars[0])
        return None

    def is_bom_package(self, artifact_id: str) -> bool:
        """Check if artifact is a BOM/meta package"""
        bom_patterns = ['starter', 'bom', 'dependencies', 'platform']
        return any(pattern in artifact_id.lower() for pattern in bom_patterns)

    def fetch_bom_dependencies(self, group_id: str, artifact_id: str, version: str) -> List[Tuple[str, str, str]]:
        """
        Download BOM package POM and extract managed dependencies.
        Returns: [(groupId, artifactId, version), ...]
        """
        group_path = group_id.replace('.', '/')
        url = f"{self.maven_repo_url}{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''

                # Look for dependencyManagement section
                dep_mgmt = root.find(f'{namespace}dependencyManagement')
                if not dep_mgmt:
                    # Also check regular dependencies section for some BOMs
                    deps_element = root.find(f'{namespace}dependencies')
                    if deps_element:
                        dependencies = []
                        for dep in deps_element.findall(f'{namespace}dependency'):
                            g = dep.find(f'{namespace}groupId')
                            a = dep.find(f'{namespace}artifactId')
                            v = dep.find(f'{namespace}version')
                            if g is not None and a is not None and v is not None:
                                if '${' not in v.text:  # Skip property references
                                    dependencies.append((g.text, a.text, v.text))
                        return dependencies
                    return []

                dependencies = []
                deps_element = dep_mgmt.find(f'{namespace}dependencies')
                if deps_element:
                    for dep in deps_element.findall(f'{namespace}dependency'):
                        g = dep.find(f'{namespace}groupId')
                        a = dep.find(f'{namespace}artifactId')
                        v = dep.find(f'{namespace}version')
                        if g is not None and a is not None and v is not None:
                            if '${' not in v.text:  # Skip property references
                                dependencies.append((g.text, a.text, v.text))
                return dependencies
        except Exception as e:
            print(f"      Warning: Could not fetch BOM dependencies for {group_id}:{artifact_id}:{version}: {e}")
        return []

    def is_bom_version_safe(self, group_id: str, artifact_id: str, version: str, depth: int = 0, check_log: Optional[List[Dict]] = None) -> bool:
        """
        Check if a BOM version is safe by verifying all its managed dependencies.
        Recursively checks nested BOM packages.
        Returns True if ALL managed dependencies are safe.

        Args:
            depth: Recursion depth for tracking (max 5 levels to prevent infinite loops)
            check_log: Optional list to collect H2 query logs
        """
        if depth > 5:
            print(f"      ⚠ Max recursion depth reached for {artifact_id}")
            return False

        bom_deps = self.fetch_bom_dependencies(group_id, artifact_id, version)
        if not bom_deps:
            # If we can't fetch dependencies, consider it unsafe to be conservative
            return False

        indent = "  " * depth
        print(f"{indent}    Checking {len(bom_deps)} managed dependencies in BOM {artifact_id}:{version}")

        for dep_group, dep_artifact, dep_version in bom_deps:
            # If this is also a BOM package, recursively check it
            if self.is_bom_package(dep_artifact):
                print(f"{indent}      → Recursively checking nested BOM: {dep_artifact}:{dep_version}")
                if not self.is_bom_version_safe(dep_group, dep_artifact, dep_version, depth + 1, check_log):
                    print(f"{indent}      ✗ Nested BOM {dep_artifact}:{dep_version} is not safe")
                    return False
                continue

            # Check regular dependency
            ranges = self.get_vulnerable_ranges(dep_group, dep_artifact, check_log)
            if ranges and self.is_version_in_ranges(dep_version, ranges):
                print(f"{indent}      ✗ Managed dependency {dep_group}:{dep_artifact}:{dep_version} is vulnerable")
                return False

        print(f"{indent}    ✓ All managed dependencies are safe")
        return True

    def fetch_direct_dependencies_from_pom(self, group_id: str, artifact_id: str, version: str) -> List[Tuple[str, str, str]]:
        """
        Download package POM and extract direct dependencies (compile + runtime scope).
        This is different from fetch_bom_dependencies() which reads dependencyManagement section.
        This reads the regular dependencies section.

        Returns:
            List of (groupId, artifactId, version) tuples
        """
        # Check cache first
        cache_key = (group_id, artifact_id, version)
        if cache_key in self._pom_cache:
            return self._pom_cache[cache_key]

        group_path = group_id.replace('.', '/')
        url = f"{self.maven_repo_url}{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

        dependencies = []
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            root = ET.fromstring(response.content)
            namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''

            # Look for regular dependencies section (not dependencyManagement)
            deps_element = root.find(f'{namespace}dependencies')
            if deps_element is None:
                self._pom_cache[cache_key] = dependencies
                return dependencies

            for dep in deps_element.findall(f'{namespace}dependency'):
                dep_group = dep.find(f'{namespace}groupId')
                dep_artifact = dep.find(f'{namespace}artifactId')
                dep_version = dep.find(f'{namespace}version')
                dep_scope = dep.find(f'{namespace}scope')
                dep_optional = dep.find(f'{namespace}optional')

                # Skip if missing required fields
                if dep_group is None or dep_artifact is None or dep_version is None:
                    continue

                # Skip property references like ${log4j.version}
                # These need parent POM resolution - too complex, skip for now
                if '${' in dep_version.text:
                    continue

                # Only include compile + runtime scope (default = compile)
                # Skip test, provided, system
                if dep_scope is not None and dep_scope.text in ['test', 'provided', 'system']:
                    continue

                # Skip optional dependencies
                if dep_optional is not None and dep_optional.text.lower() == 'true':
                    continue

                dependencies.append((
                    dep_group.text.strip(),
                    dep_artifact.text.strip(),
                    dep_version.text.strip()
                ))

        except Exception as e:
            print(f"      ⚠ Could not fetch POM for {artifact_id}:{version}: {e}")

        # Cache the result (even if empty)
        self._pom_cache[cache_key] = dependencies
        return dependencies

    def build_dependency_tree(self, group_id: str, artifact_id: str, version: str,
                              max_depth: int, current_depth: int = 0,
                              visited: Optional[Set[str]] = None) -> List[Tuple[str, str, str, int]]:
        """
        Build dependency tree for a package up to max_depth levels.
        This recursively fetches all transitive dependencies up to the specified depth.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            version: Package version
            max_depth: Maximum depth to traverse (-1 = infinite, with safety limit of 10)
            current_depth: Current recursion depth
            visited: Set of already visited packages to avoid cycles

        Returns:
            List of (groupId, artifactId, version, depth) tuples for all dependencies in tree
        """
        if visited is None:
            visited = set()

        # Safety limit even for -1 (infinite)
        MAX_DEPTH_LIMIT = 10
        effective_max_depth = MAX_DEPTH_LIMIT if max_depth == -1 else max_depth

        # Check depth limit
        if current_depth >= effective_max_depth:
            return []

        # Avoid infinite loops (circular dependencies)
        package_key = f"{group_id}:{artifact_id}:{version}"
        if package_key in visited:
            return []
        visited.add(package_key)

        # Fetch direct dependencies for this package
        direct_deps = self.fetch_direct_dependencies_from_pom(group_id, artifact_id, version)

        all_deps = []
        for dep_group, dep_artifact, dep_version in direct_deps:
            # Add this dependency
            all_deps.append((dep_group, dep_artifact, dep_version, current_depth + 1))

            # Recursively fetch its dependencies
            transitive = self.build_dependency_tree(
                dep_group, dep_artifact, dep_version,
                max_depth, current_depth + 1, visited
            )
            all_deps.extend(transitive)

        return all_deps

    def is_dependency_tree_safe(self, group_id: str, artifact_id: str, version: str,
                                max_depth: int, check_log: Optional[List[Dict]] = None) -> bool:
        """
        Check if a package version is safe by verifying all dependencies in its tree.
        This provides comprehensive vulnerability checking beyond just the package itself.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            version: Package version to check
            max_depth: Depth to check (0=disabled/check only package itself, -1=infinite, >0=specific depth)
            check_log: Optional list to collect detailed check information

        Returns:
            True if package and ALL dependencies in tree (up to max_depth) are safe
        """
        # First check the package itself
        ranges = self.get_vulnerable_ranges(group_id, artifact_id, check_log)
        if ranges and self.is_version_in_ranges(version, ranges):
            print(f"      ✗ Package itself {artifact_id}:{version} is vulnerable")
            if check_log is not None:
                check_log.append({
                    "type": "package_self_check",
                    "package": f"{group_id}:{artifact_id}:{version}",
                    "vulnerable": True,
                    "reason": "Package version is in vulnerable range"
                })
            return False

        if check_log is not None:
            check_log.append({
                "type": "package_self_check",
                "package": f"{group_id}:{artifact_id}:{version}",
                "vulnerable": False,
                "reason": "Package version is safe"
            })

        # If transitive check disabled (depth=0), stop here
        if max_depth == 0:
            return True

        # Build dependency tree
        depth_str = f"{max_depth}" if max_depth > 0 else "∞"
        print(f"      Building dependency tree (depth={depth_str})...")
        tree = self.build_dependency_tree(group_id, artifact_id, version, max_depth)

        if not tree:
            print(f"      ℹ No dependencies found in tree")
            if check_log is not None:
                check_log.append({
                    "type": "transitive_check",
                    "package": f"{group_id}:{artifact_id}:{version}",
                    "depth": max_depth,
                    "dependencies_found": 0,
                    "dependencies": []
                })
            return True

        print(f"      Checking {len(tree)} dependencies in tree...")

        # Collect dependency info for log
        dep_log_entries = []

        # Check each dependency in tree
        for dep_group, dep_artifact, dep_version, depth in tree:
            dep_ranges = self.get_vulnerable_ranges(dep_group, dep_artifact, check_log)
            is_vulnerable = dep_ranges and self.is_version_in_ranges(dep_version, dep_ranges)

            dep_entry = {
                "groupId": dep_group,
                "artifactId": dep_artifact,
                "version": dep_version,
                "depth": depth,
                "vulnerable": is_vulnerable
            }
            dep_log_entries.append(dep_entry)

            if is_vulnerable:
                print(f"      ✗ Transitive dependency {dep_artifact}:{dep_version} (level {depth}) is vulnerable")
                if check_log is not None:
                    check_log.append({
                        "type": "transitive_check",
                        "package": f"{group_id}:{artifact_id}:{version}",
                        "depth": max_depth,
                        "dependencies_found": len(tree),
                        "dependencies": dep_log_entries,
                        "result": "VULNERABLE",
                        "vulnerable_dependency": f"{dep_group}:{dep_artifact}:{dep_version} (level {depth})"
                    })
                return False

        print(f"      ✓ All dependencies in tree are safe")
        if check_log is not None:
            check_log.append({
                "type": "transitive_check",
                "package": f"{group_id}:{artifact_id}:{version}",
                "depth": max_depth,
                "dependencies_found": len(tree),
                "dependencies": dep_log_entries,
                "result": "SAFE"
            })
        return True

    def _execute_h2_query(self, sql: str, params: tuple, query_log: Optional[List[Dict]] = None,
                          query_metadata: Optional[Dict] = None) -> List[Tuple]:
        if not self.h2_jar_path: raise RuntimeError("H2 driver not found.")

        try:
            conn = jaydebeapi.connect("org.h2.Driver", self.db_conn_string, [self.db_user, self.db_password], self.h2_jar_path)
            cursor = conn.cursor()
            cursor.execute(sql, params)
            results = cursor.fetchall()
            conn.close()

            # Log only results count, not raw results
            if query_log is not None and query_metadata is not None:
                query_metadata["results_count"] = len(results)

            return results
        except Exception as e:
            # Log query error
            if query_log is not None and query_metadata is not None:
                query_metadata["error"] = str(e)
            raise RuntimeError(f"Failed to query H2 database: {e}")

    def get_vulnerable_ranges(self, group_id: str, artifact_id: str, query_log: Optional[List[Dict]] = None) -> List[VulnerableRange]:
        """Fetch all vulnerable version ranges for a given component from the DB."""
        cache_key = (group_id, artifact_id)
        if cache_key in self._vulnerability_cache:
            cached_ranges = self._vulnerability_cache[cache_key]
            # Even when cached, add log entry to show it was checked
            if query_log is not None:
                # Format cached ranges
                formatted_ranges = []
                for r in cached_ranges:
                    start = r.start_including if r.start_including else (f">{r.start_excluding}" if r.start_excluding else "0.0.0")
                    end = r.end_including if r.end_including else (f"<{r.end_excluding}" if r.end_excluding else "∞")
                    if r.start_including and r.end_including:
                        range_str = f"[{start}, {end}]"
                    elif r.start_including and r.end_excluding:
                        range_str = f"[{start}, {end})"
                    elif r.start_excluding and r.end_including:
                        range_str = f"({start}, {end}]"
                    elif r.start_excluding and r.end_excluding:
                        range_str = f"({start}, {end})"
                    else:
                        range_str = f"[{start}, {end}]"
                    formatted_ranges.append(range_str)

                query_log.append({
                    "type": "database_query_cached",
                    "package": f"{group_id}:{artifact_id}",
                    "vulnerable_ranges_found": len(cached_ranges),
                    "version_ranges": formatted_ranges if formatted_ranges else []
                })
            return cached_ranges

        # Track all database queries for logging
        db_queries_performed = []

        # Build potential product name variations from artifact_id
        artifact_base = artifact_id.split('-')[0]  # Get first part before hyphen

        # Special product name mappings for known libraries with non-standard CPE names
        product_mappings = {
            'log4j-core': ['log4j2', 'log4j'],
            'log4j-api': ['log4j2', 'log4j'],
            'log4j-slf4j-impl': ['log4j2', 'log4j'],
            'log4j-1.2-api': ['log4j2', 'log4j'],
        }

        # Check if we have a special mapping for this artifact
        if artifact_id in product_mappings:
            artifact_variations = product_mappings[artifact_id].copy()
            # Also add standard variations
            artifact_variations.extend([
                artifact_id.replace('-', '_'),
                artifact_id,
            ])
        else:
            artifact_variations = [
                artifact_id.replace('-', '_'),  # spring-boot-starter-web -> spring_boot_starter_web
                artifact_id,                     # spring-boot-starter-web
                artifact_id.replace('_', '-'),  # if underscore exists
                artifact_base.replace('.', '_'), # First part: log4j-core -> log4j
            ]

            # For compound names like "spring-boot-*", also try "spring_boot"
            if '-' in artifact_id:
                parts = artifact_id.split('-')
                if len(parts) >= 2:
                    # spring-boot-starter-web -> spring_boot
                    compound = '_'.join(parts[:2])
                    artifact_variations.insert(0, compound)  # Try this first

        # Build potential vendor names from group_id
        # e.g. org.springframework.boot -> [springframework, spring, vmware, ...]
        # e.g. org.apache.logging.log4j -> [apache, logging, ...]
        group_parts = group_id.split('.')
        vendor_variations = []
        for part in group_parts:
            if part not in ['org', 'com', 'io', 'net']:
                vendor_variations.append(part)

        # Common vendor mappings for known frameworks
        vendor_mappings = {
            'springframework': ['vmware', 'pivotal', 'spring'],
            'apache': ['apache'],
            'fasterxml': ['fasterxml'],
        }

        for part in group_parts:
            if part in vendor_mappings:
                vendor_variations.extend(vendor_mappings[part])

        tried_combinations = set()

        # Strategy 1: Product-only search
        exact_product_matches = []
        sql_product_only = '''
        SELECT s."VERSIONSTARTINCLUDING", s."VERSIONSTARTEXCLUDING", s."VERSIONENDINCLUDING", s."VERSIONENDEXCLUDING"
        FROM "SOFTWARE" s
        JOIN "CPEENTRY" c ON s."CPEENTRYID" = c."ID"
        WHERE c."PRODUCT" = ?
        '''

        for art_var in artifact_variations[:3]:  # Limit to first 3 variations
            params = (art_var,)
            key = ('exact_product', art_var)
            if key not in tried_combinations:
                tried_combinations.add(key)
                try:
                    query_metadata = {"product": art_var, "vendor": None}
                    rows = self._execute_h2_query(sql_product_only, params, query_log, query_metadata)
                    db_queries_performed.append(query_metadata)
                    if rows:
                        print(f"[DEBUG] Found {len(rows)} ranges with exact product: {art_var}")
                        exact_product_matches.extend([VulnerableRange(*row) for row in rows])
                except RuntimeError as e:
                    print(f"[DEBUG] Query error for {art_var}: {e}")

        # Strategy 2: Product + Vendor (more specific, overrides Strategy 1)
        vendor_product_matches = []
        sql_product_vendor = '''
        SELECT s."VERSIONSTARTINCLUDING", s."VERSIONSTARTEXCLUDING", s."VERSIONENDINCLUDING", s."VERSIONENDEXCLUDING"
        FROM "SOFTWARE" s
        JOIN "CPEENTRY" c ON s."CPEENTRYID" = c."ID"
        WHERE c."PRODUCT" = ? AND c."VENDOR" = ?
        '''

        for art_var in artifact_variations[:3]:  # Limit to first 3
            for vendor_var in vendor_variations[:2]:  # Limit to first 2
                params = (art_var, vendor_var)
                key = ('product_vendor', art_var, vendor_var)
                if key not in tried_combinations:
                    tried_combinations.add(key)
                    try:
                        query_metadata = {"product": art_var, "vendor": vendor_var}
                        rows = self._execute_h2_query(sql_product_vendor, params, query_log, query_metadata)
                        db_queries_performed.append(query_metadata)
                        if rows:
                            print(f"[DEBUG] Found {len(rows)} ranges with product={art_var}, vendor={vendor_var}")
                            vendor_product_matches.extend([VulnerableRange(*row) for row in rows])
                    except RuntimeError as e:
                        print(f"[DEBUG] Query error for {art_var}/{vendor_var}: {e}")

        # Prefer vendor+product matches (more specific), fallback to product-only
        all_ranges = vendor_product_matches if vendor_product_matches else exact_product_matches

        # Deduplicate ranges
        unique_ranges = []
        seen = set()
        for r in all_ranges:
            key = (r.start_including, r.start_excluding, r.end_including, r.end_excluding)
            if key not in seen:
                seen.add(key)
                unique_ranges.append(r)

        if unique_ranges:
            print(f"[DEBUG] Total unique ranges for {group_id}:{artifact_id}: {len(unique_ranges)}")
            # Show ALL ranges with details for spring-boot (to debug)
            show_all = 'spring-boot' in artifact_id or 'spring_boot' in artifact_id
            limit = len(unique_ranges) if show_all else 5
            for i, r in enumerate(unique_ranges[:limit]):
                print(f"[DEBUG]   Range {i+1}: [{r.start_including or r.start_excluding or '0'} - {r.end_including or r.end_excluding or '∞'}] (inc_start={r.start_including is not None}, inc_end={r.end_including is not None})")

        # Add database query summary to log
        if query_log is not None:
            self._add_database_query_summary(query_log, group_id, artifact_id, db_queries_performed, unique_ranges)

        self._vulnerability_cache[cache_key] = unique_ranges
        return unique_ranges

    def _add_database_query_summary(self, query_log: List[Dict], group_id: str, artifact_id: str,
                                     queries: List[Dict], ranges: List[VulnerableRange]) -> None:
        """Add a readable database query summary to the log"""
        # Format version ranges in a readable way
        formatted_ranges = []
        for r in ranges:
            start = r.start_including if r.start_including else (f">{r.start_excluding}" if r.start_excluding else "0.0.0")
            end = r.end_including if r.end_including else (f"<{r.end_excluding}" if r.end_excluding else "∞")

            # Determine if boundaries are inclusive or exclusive
            if r.start_including and r.end_including:
                range_str = f"[{start}, {end}]"
            elif r.start_including and r.end_excluding:
                range_str = f"[{start}, {end})"
            elif r.start_excluding and r.end_including:
                range_str = f"({start}, {end}]"
            elif r.start_excluding and r.end_excluding:
                range_str = f"({start}, {end})"
            else:
                range_str = f"[{start}, {end}]"

            formatted_ranges.append(range_str)

        # Create summary entry
        summary = {
            "type": "database_query",
            "package": f"{group_id}:{artifact_id}",
            "queries_performed": len(queries),
            "search_parameters": queries,
            "vulnerable_ranges_found": len(ranges),
            "version_ranges": formatted_ranges if formatted_ranges else []
        }

        query_log.append(summary)

    def is_version_in_ranges(self, version_to_check: str, ranges: List[VulnerableRange]) -> bool:
        """Check if a given version falls into any of the vulnerable ranges."""
        try:
            sem_ver_to_check = SemanticVersion(version_to_check)
            if not sem_ver_to_check.valid: return False
        except Exception:
            return False

        for r in ranges:
            # Skip ranges with all NULL values (invalid/incomplete CPE data)
            if not any([r.start_including, r.start_excluding, r.end_including, r.end_excluding]):
                continue

            # Check start range
            starts_after = True
            if r.start_including:
                starts_after = sem_ver_to_check >= SemanticVersion(r.start_including)
            elif r.start_excluding:
                starts_after = sem_ver_to_check > SemanticVersion(r.start_excluding)
            # If no start condition, assume starts from beginning (version 0.0.0)

            # Check end range
            ends_before = True
            if r.end_including:
                ends_before = sem_ver_to_check <= SemanticVersion(r.end_including)
            elif r.end_excluding:
                ends_before = sem_ver_to_check < SemanticVersion(r.end_excluding)
            # If no end condition, assume extends to infinity (unfixed vulnerability)

            if starts_after and ends_before:
                return True # It's in a vulnerable range

        return False # Not in any vulnerable range

    def has_vulnerabilities(self, group_id: str, artifact_id: str, version: str) -> bool:
        if not self.h2_jar_path: return False
        
        ranges = self.get_vulnerable_ranges(group_id, artifact_id)
        if not ranges:
            return False # No ranges found, assume safe
            
        return self.is_version_in_ranges(version, ranges)

    def find_remediation_version(self, group_id: str, artifact_id: str, available_versions: List[str],
                                 check_log: Optional[List[Dict]] = None) -> Optional[str]:
        if not available_versions:
            return None
        if not self.h2_jar_path:
            return available_versions[0]

        # Check if this is a BOM package
        if self.is_bom_package(artifact_id):
            print(f"      Detected BOM package: {artifact_id}")
            for version in available_versions:
                bom_deps = self.fetch_bom_dependencies(group_id, artifact_id, version)

                # Create a separate log for this BOM check to collect DB queries
                bom_check_log = []
                is_safe = self.is_bom_version_safe(group_id, artifact_id, version, 0, bom_check_log)

                if is_safe:
                    print(f"      ✓ Safe BOM version found: {version}")
                    if check_log is not None:
                        check_log.append({
                            "type": "bom_check",
                            "package": f"{group_id}:{artifact_id}:{version}",
                            "managed_dependencies_count": len(bom_deps),
                            "result": "SAFE",
                            "managed_dependencies_checks": bom_check_log
                        })
                    return version
                else:
                    print(f"      ✗ BOM version {version} has vulnerable managed dependencies")
                    if check_log is not None:
                        check_log.append({
                            "type": "bom_check",
                            "package": f"{group_id}:{artifact_id}:{version}",
                            "managed_dependencies_count": len(bom_deps),
                            "result": "VULNERABLE - has vulnerable managed dependencies",
                            "managed_dependencies_checks": bom_check_log
                        })
            print(f"      ✗ No safe BOM upgrade found")
            return None

        # Regular package handling
        vulnerable_ranges = self.get_vulnerable_ranges(group_id, artifact_id, check_log)
        if not vulnerable_ranges:
            print(f"      ✓ No vulnerability ranges found for {group_id}:{artifact_id}. Assuming all are safe.")
            if check_log is not None:
                check_log.append({
                    "type": "no_vulnerability_data",
                    "package": f"{group_id}:{artifact_id}",
                    "result": "SAFE (no vulnerability ranges found in database)"
                })
            return available_versions[0]

        # Check each version with transitive dependency tree if enabled
        for version in available_versions:
            if self.is_dependency_tree_safe(group_id, artifact_id, version, self.transitive_depth, check_log):
                print(f"      ✓ Safe version found: {version}")
                return version
            else:
                if self.transitive_depth > 0:
                    print(f"      ✗ Version {version} or its dependencies are vulnerable")
                else:
                    print(f"      ✗ Version {version} is in a vulnerable range")

        print(f"      ✗ No safe upgrade found for {group_id}:{artifact_id} in the same major version line.")
        return None
        
    # --- Other methods (parse_direct_dependencies, fetch_maven_metadata, etc.) remain the same ---
    def parse_direct_dependencies(self, pom_path: Path) -> List[Dependency]:
        dependencies = []
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''
            dependencies_element = root.find(f'{namespace}dependencies')
            if dependencies_element is None: return dependencies
            for dep_element in dependencies_element.findall(f'{namespace}dependency'):
                group_id_elem = dep_element.find(f'{namespace}groupId')
                artifact_id_elem = dep_element.find(f'{namespace}artifactId')
                version_elem = dep_element.find(f'{namespace}version')
                if group_id_elem is None or artifact_id_elem is None or version_elem is None or '${' in version_elem.text: continue
                dependencies.append(Dependency(group_id_elem.text, artifact_id_elem.text, version_elem.text, pom_path))
        except Exception as e:
            print(f"Warning: Failed to parse {pom_path}: {e}")
        return dependencies

    def fetch_maven_metadata(self, group_id: str, artifact_id: str) -> Optional[ET.Element]:
        cache_key = (group_id, artifact_id)
        if cache_key in self._metadata_cache: return self._metadata_cache[cache_key]
        group_path = group_id.replace('.', '/')
        url = f"{self.maven_repo_url}{group_path}/{artifact_id}/maven-metadata.xml"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                self._metadata_cache[cache_key] = root
                return root
        except (requests.exceptions.RequestException, ET.ParseError) as e:
            print(f"Warning: Could not get metadata for {group_id}:{artifact_id}: {e}")
        self._metadata_cache[cache_key] = None
        return None

    def extract_versions_from_metadata(self, metadata: ET.Element) -> List[str]:
        versions = []
        try:
            namespace = metadata.tag.split('}')[0] + '}' if '}' in metadata.tag else ''
            versioning = metadata.find(f'{namespace}versioning')
            if versioning:
                versions_element = versioning.find(f'{namespace}versions')
                if versions_element:
                    versions.extend(v.text for v in versions_element.findall(f'{namespace}version') if v.text)
        except Exception as e:
            print(f"Warning: Failed to extract versions from metadata: {e}")
        return versions

    def filter_stable_versions(self, versions: List[str]) -> List[str]:
        return [v for v in versions if not any(p.upper() in v.upper() for p in self.UNSTABLE_PATTERNS)]

    def filter_compatible_versions(self, current: str, available: List[str]) -> List[str]:
        """
        Filter available versions based on compatibility with current version.

        Args:
            current: Current version string
            available: List of available version strings

        Returns:
            List of compatible versions (filtered by allow_major_upgrade setting)
        """
        compatible = []
        current_sem = SemanticVersion(current)
        if not current_sem.valid: return available

        for version in available:
            candidate = SemanticVersion(version)
            if not candidate.valid or candidate <= current_sem:
                continue

            if self.allow_major_upgrade:
                # Allow all upgrades (including major version changes)
                compatible.append(version)
            else:
                # Only allow same major version upgrades (e.g., 1.8.3 -> 1.9.x)
                if current_sem.is_same_major(candidate):
                    compatible.append(version)

        return compatible

    def sort_versions_semantically(self, versions: List[str]) -> List[str]:
        parsed = [SemanticVersion(v) for v in versions if SemanticVersion(v).valid]
        parsed.sort()
        return [str(v) for v in parsed]

    def generate_remediation_report_for_pom(self, pom_file: Path, save_transitive_logs: bool = False) -> List[Dict]:
        """
        Generate remediation report for a single POM file

        Args:
            pom_file: Path to the POM file
            save_transitive_logs: If True, save individual transitive check logs per dependency

        Returns:
            List of remediation results
        """
        results = []
        print(f"  Processing: {pom_file}")
        dependencies = self.parse_direct_dependencies(pom_file)

        # Create transitive log directory if needed
        transitive_log_dir = pom_file.parent / 'target' / 'transitive'
        if save_transitive_logs and dependencies:
            transitive_log_dir.mkdir(parents=True, exist_ok=True)

        for dep in dependencies:
            print(f"    Querying: {dep.group_id}:{dep.artifact_id}:{dep.version}")
            metadata = self.fetch_maven_metadata(dep.group_id, dep.artifact_id)
            if not metadata: continue
            all_versions = self.extract_versions_from_metadata(metadata)
            stable_versions = self.filter_stable_versions(all_versions)
            compatible_versions = self.filter_compatible_versions(dep.version, stable_versions)
            sorted_versions = self.sort_versions_semantically(compatible_versions)

            # Create check log for this dependency
            dep_check_log = []
            remediation_version = self.find_remediation_version(dep.group_id, dep.artifact_id, sorted_versions, dep_check_log)

            results.append({
                "groupId": dep.group_id, "artifactId": dep.artifact_id, "currentVersion": dep.version,
                "availableVersions": sorted_versions, "remediationVersion": remediation_version
            })

            # Save individual transitive check log if enabled (even if empty, to show what was checked)
            if save_transitive_logs:
                # Sanitize filename: replace dots with underscores, remove special chars
                safe_group = dep.group_id.replace('.', '_')
                safe_artifact = dep.artifact_id.replace('-', '_')
                log_filename = f"{safe_group}_{safe_artifact}.json"
                log_path = transitive_log_dir / log_filename

                log_data = {
                    "dependency": f"{dep.group_id}:{dep.artifact_id}:{dep.version}",
                    "remediationVersion": remediation_version,
                    "checks": dep_check_log if dep_check_log else []
                }

                try:
                    if self.save_to_json([log_data], log_path):
                        print(f"      📝 Saved transitive check log: {log_path.relative_to(pom_file.parent)}")
                    else:
                        print(f"      ❌ Failed to save transitive log for {dep.artifact_id}")
                except Exception as e:
                    print(f"      ❌ Error saving transitive log for {dep.artifact_id}: {e}")

        return results

    def generate_remediation_report(self, pom_files: List[Path]) -> List[Dict]:
        """Generate remediation report for all POM files (deduplicated)"""
        results = []
        processed_deps = set()
        for pom_file in pom_files:
            print(f"  Processing: {pom_file}")
            dependencies = self.parse_direct_dependencies(pom_file)
            for dep in dependencies:
                dep_key = (dep.group_id, dep.artifact_id)
                if dep_key in processed_deps: continue
                processed_deps.add(dep_key)
                print(f"    Querying: {dep.group_id}:{dep.artifact_id}:{dep.version}")
                metadata = self.fetch_maven_metadata(dep.group_id, dep.artifact_id)
                if not metadata: continue
                all_versions = self.extract_versions_from_metadata(metadata)
                stable_versions = self.filter_stable_versions(all_versions)
                compatible_versions = self.filter_compatible_versions(dep.version, stable_versions)
                sorted_versions = self.sort_versions_semantically(compatible_versions)
                remediation_version = self.find_remediation_version(dep.group_id, dep.artifact_id, sorted_versions)
                results.append({
                    "groupId": dep.group_id, "artifactId": dep.artifact_id, "currentVersion": dep.version,
                    "availableVersions": sorted_versions, "remediationVersion": remediation_version
                })
        return results

    def save_to_json(self, report: List[Dict], output_path: Path) -> bool:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error: Failed to save JSON to {output_path}: {e}")
            return False

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='OWASP Dependency Check Remediation Generator')
    parser.add_argument('--transitive', nargs='?', const=-1, type=int, default=0,
                        help='Check transitive dependencies. N=depth (0=disabled [default], -1=infinite, >0=specific depth level)')
    args = parser.parse_args()

    print("Starting Remediation Generator...")
    search_dir = os.getenv('SCAN_PATH', '.')
    output_mode = os.getenv('OUTPUT_MODE', 'per-module')  # 'per-module' or 'single'
    odc_data = os.getenv('DEPENDENCY_CHECK_DATA', '/usr/share/dependency-check/data')
    allow_major_upgrade = os.getenv('ALLOW_MAJOR_UPGRADE', 'false').lower() in ('true', '1', 'yes')

    # Transitive depth: Command-line arg takes precedence over environment variable
    transitive_depth = int(os.getenv('TRANSITIVE_DEPTH', str(args.transitive)))

    if allow_major_upgrade:
        print("⚠️  ALLOW_MAJOR_UPGRADE enabled: Will include major version upgrades in recommendations")
    else:
        print("ℹ️  ALLOW_MAJOR_UPGRADE disabled: Only same-major-version upgrades will be recommended")

    if transitive_depth > 0:
        print(f"🔍 TRANSITIVE_DEPTH={transitive_depth}: Will check transitive dependencies up to {transitive_depth} level(s)")
    elif transitive_depth == -1:
        print(f"🔍 TRANSITIVE_DEPTH=infinite: Will check all transitive dependencies (up to 10 levels)")
    else:
        print("ℹ️  TRANSITIVE_DEPTH=0: Only checking direct package vulnerability (transitive checking disabled)")

    pom_paths = list(Path(search_dir).rglob('pom.xml'))
    if not pom_paths:
        print("No pom.xml files found.")
        exit(0)
    print(f"Found {len(pom_paths)} pom.xml file(s).")

    try:
        generator = RemediationGenerator(odc_data_dir=odc_data, allow_major_upgrade=allow_major_upgrade, transitive_depth=transitive_depth)

        if output_mode == 'per-module':
            # Generate separate remediation.json for each module
            success_count = 0
            # Enable transitive log saving if transitive check is enabled
            save_transitive_logs = transitive_depth != 0

            for pom_file in pom_paths:
                report_data = generator.generate_remediation_report_for_pom(pom_file, save_transitive_logs=save_transitive_logs)
                if report_data:  # Only save if there are dependencies
                    # Save to target/remediation.json relative to the POM
                    output_path = pom_file.parent / 'target' / 'remediation.json'
                    if generator.save_to_json(report_data, output_path):
                        print(f"  ✅ Saved to: {output_path}")
                        success_count += 1
                    else:
                        print(f"  ❌ Failed to save: {output_path}")

            print(f"\n✅ Generated {success_count} remediation reports")
        else:
            # Generate single remediation_report.json (legacy mode)
            output_file = Path('remediation_report.json')
            report_data = generator.generate_remediation_report(pom_paths)
            if generator.save_to_json(report_data, output_file):
                print(f"\n✅ Remediation report saved to: {output_file.resolve()}")
            else:
                print("\n❌ Failed to save remediation report.")

    except FileNotFoundError as e:
        print("Exiting due to missing database file.")
        exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        exit(1)
