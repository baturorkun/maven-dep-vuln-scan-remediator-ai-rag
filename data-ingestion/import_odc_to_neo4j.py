#!/usr/bin/env python3
"""
OWASP Dependency Check to Neo4j Importer (Advanced)

Imports ODC JSON reports and DOT dependency trees into Neo4j with hierarchy:
Project -> Module -> Dependency -> Vulnerability -> ArtifactVersion

DOT format is used instead of GraphML because it captures phantom packages
(like spring-boot-starter-web) that don't produce jar files but are declared
as direct dependencies in pom.xml.

Graph Schema (Plan1.md Yöntem 2 + Multi-Project Context):
- (Project)-[:HAS_MODULE]->(Module)
- (Module)-[:USES_DEPENDENCY]->(Dependency)
- (Dependency)-[:HAS_VULNERABILITY]->(Vulnerability)
- (Dependency)-[:CURRENT_VERSION {project, module}]->(ArtifactVersion)
- (Dependency)-[:RECOMMENDED_VERSION {project, module}]->(ArtifactVersion)
- (Dependency)-[:AVAILABLE_VERSION {project, module}]->(ArtifactVersion)
- (ArtifactVersion)-[:UPGRADES_TO]->(ArtifactVersion)

Features:
- Phantom package detection (spring-boot-starter-*, BOM dependencies)
- Direct Dependency -> ArtifactVersion relationships (simple 2-layer model)
- Version nodes with CVE enrichment (hasCVE, cveCount, highSeverityCVECount)
- Version ordering properties (majorVersion, minorVersion, patchVersion)
- Upgrade path tracking (UPGRADES_TO relationships)
- Multi-project context preservation (project/module in relationships)
- Handles multiple modules
- Re-runnable (idempotent)
- Deduplicates dependencies and versions across modules
"""

import json
import os
import sys
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional, Set
from neo4j import GraphDatabase


class Colors:
    """ANSI color codes"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_success(msg: str):
    print(f"{Colors.GREEN}✓ {msg}{Colors.RESET}")


def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.RESET}")


def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.RESET}")


def print_error(msg: str):
    print(f"{Colors.RED}✗ {msg}{Colors.RESET}", file=sys.stderr)


def print_header(msg: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")


class ModuleData:
    """Data container for a single module"""
    def __init__(self, module_name: str, odc_json_path: Path, dot_path: Optional[Path] = None,
                 remediation_json_path: Optional[Path] = None, pom_path: Optional[Path] = None):
        self.module_name = module_name
        self.odc_json_path = odc_json_path
        self.dot_path = dot_path
        self.remediation_json_path = remediation_json_path
        self.pom_path = pom_path
        self.dependencies = []
        self.vulnerabilities = []
        self.dependency_tree = {}  # GraphML data


def find_odc_reports(target_dir: str) -> List[ModuleData]:
    """
    Find all ODC JSON reports and corresponding DOT dependency tree files

    Args:
        target_dir: Root directory to search

    Returns:
        List of ModuleData objects
    """
    modules = []
    target_path = Path(target_dir)

    # Search for dependency-check-report.json files
    for json_file in target_path.rglob('dependency-check-report.json'):
        # Determine module name from path
        # Handle two possible structures:
        # 1. .../module-name/target/dependency-check-report.json
        # 2. .../module-name/target/dependency-check-report/dependency-check-report.json

        # Check if parent is 'dependency-check-report' directory
        if json_file.parent.name == 'dependency-check-report':
            # Case 2: Extra directory level
            maven_target_dir = json_file.parent.parent  # Go to 'target'
            module_dir = maven_target_dir.parent        # Go to module
        else:
            # Case 1: Direct in target
            maven_target_dir = json_file.parent         # Already in 'target'
            module_dir = maven_target_dir.parent        # Go to module

        module_name = module_dir.name

        # Skip parent/aggregator projects (they have child modules with target dirs)
        # Check if this module directory contains other directories with 'target' subdirs
        child_targets = [d for d in module_dir.iterdir()
                        if d.is_dir() and d.name != 'target' and (d / 'target').exists()]
        if child_targets:
            print_warning(f"Skipping parent/aggregator module: {module_name} (has {len(child_targets)} child modules)")
            continue

        # Look for corresponding DOT file (always in target dir, not in subdirectory)
        # DOT format includes phantom packages like spring-boot-starter-web
        dot_file = maven_target_dir / 'dependency-graph.dot'
        if not dot_file.exists():
            dot_file = None
            print_warning(f"No DOT file found for module: {module_name}")

        # Look for remediation.json produced by version-scanner
        remediation_file = maven_target_dir / 'remediation.json'
        if not remediation_file.exists():
            remediation_file = None

        # Look for pom.xml to extract direct dependencies (including BOM/starter packages)
        pom_file = module_dir / 'pom.xml'
        if not pom_file.exists():
            pom_file = None
            print_warning(f"No pom.xml found for module: {module_name}")

        module_data = ModuleData(
            module_name=module_name,
            odc_json_path=json_file,
            dot_path=dot_file,
            remediation_json_path=remediation_file,
            pom_path=pom_file
        )
        modules.append(module_data)

    return modules


def parse_dot(dot_path: Path) -> tuple[Dict[str, Dict], Set[str], List[Dict], Optional[str]]:
    """
    Parse DOT dependency tree and identify direct dependencies and all edges.

    DOT format captures phantom packages like spring-boot-starter-web that
    GraphML misses because they don't produce jar files.

    DOT format example:
    digraph "com.example:module1:jar:1.0-SNAPSHOT" {
        "com.example:module1:jar:1.0-SNAPSHOT" -> "org.springframework.boot:spring-boot-starter-web:jar:3.3.1:compile" ;
        "org.springframework.boot:spring-boot-starter-web:jar:3.3.1:compile" -> "org.springframework.boot:spring-boot-starter:pom:3.3.1:compile" ;
    }

    Args:
        dot_path: Path to DOT file

    Returns:
        Tuple of (dependency_map, direct_dependency_ids, edges_list, root_node_id)
        - dependency_map: Dictionary mapping dependency labels to their metadata
        - direct_dependency_ids: Set of labels that are direct dependencies
        - edges_list: List of all edges with source/target labels
        - root_node_id: Label of the root node (module itself)
    """
    import re

    dependency_map = {}
    direct_dependency_ids = set()
    edges_list = []
    root_node_id = None

    try:
        with open(dot_path, 'r') as f:
            content = f.read()

        # Extract root node from digraph declaration
        # Format: digraph "groupId:artifactId:type:version" { ... }
        digraph_match = re.search(r'digraph\s+"([^"]+)"', content)
        if digraph_match:
            root_node_id = digraph_match.group(1)
            # Add root node to dependency map
            dependency_map[root_node_id] = {'label': root_node_id}

        # Parse edges: "source" -> "target" ;
        # Pattern matches: "label1" -> "label2" with optional scope info
        edge_pattern = re.compile(r'"([^"]+)"\s*->\s*"([^"]+)"')

        for match in edge_pattern.finditer(content):
            source_label = match.group(1)
            target_label = match.group(2)

            # Add nodes to dependency map if not exists
            if source_label not in dependency_map:
                dependency_map[source_label] = {'label': source_label}
            if target_label not in dependency_map:
                dependency_map[target_label] = {'label': target_label}

            # Track direct dependencies (edges from root)
            if source_label == root_node_id:
                direct_dependency_ids.add(target_label)

            # Add edge to list
            edges_list.append({
                'source_id': source_label,
                'target_id': target_label,
                'source_label': source_label,
                'target_label': target_label
            })

        print_success(f"Parsed DOT: {len(dependency_map)} nodes, {len(direct_dependency_ids)} direct, {len(edges_list)} edges")

    except Exception as e:
        print_error(f"Failed to parse DOT {dot_path}: {e}")
        edges_list = []
        root_node_id = None

    return dependency_map, direct_dependency_ids, edges_list, root_node_id


def load_odc_json(json_path: Path) -> Optional[Dict]:
    """
    Load ODC JSON report

    Args:
        json_path: Path to JSON file

    Returns:
        Parsed JSON data or None if error
    """
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        print_success(f"Loaded ODC JSON: {json_path.name}")
        return data
    except Exception as e:
        print_error(f"Failed to load JSON {json_path}: {e}")
        return None


def load_remediation_json(json_path: Path) -> Optional[List[Dict]]:
    """Load remediation.json structure.

    Expected format (array of objects):
    [
      {
        "groupId": "org.example",
        "artifactId": "lib",
        "currentVersion": "1.0.0",
        "availableVersions": ["1.1.0", "1.2.0"],
        "remediationVersion": "1.2.0"
      }
    ]
    """
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        if isinstance(data, list):
            print_success(f"Loaded remediation JSON: {json_path.name} ({len(data)} items)")
            return data
        else:
            print_warning(f"Remediation JSON is not a list: {json_path}")
            return None
    except Exception as e:
        print_error(f"Failed to load remediation JSON {json_path}: {e}")
        return None


def parse_pom_dependencies(pom_path: Path) -> List[Dict]:
    """
    Parse POM file and extract direct dependencies.

    This captures ALL dependencies declared in the POM, including:
    - BOM/starter packages (like spring-boot-starter-web)
    - Regular jar dependencies
    - Dependencies with 'pom' packaging type

    These may not appear in OWASP Dependency Check or GraphML because they
    don't produce jar files, but they ARE direct dependencies from pom.xml.

    Args:
        pom_path: Path to pom.xml file

    Returns:
        List of dependency dicts with groupId, artifactId, version, scope
    """
    dependencies = []

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Handle Maven namespace
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

        # Try with namespace first, then without
        deps_elements = root.findall('.//m:dependencies/m:dependency', ns)
        if not deps_elements:
            deps_elements = root.findall('.//dependencies/dependency')

        for dep in deps_elements:
            # Try with namespace first
            group_id = dep.find('m:groupId', ns)
            artifact_id = dep.find('m:artifactId', ns)
            version = dep.find('m:version', ns)
            scope = dep.find('m:scope', ns)

            # Fallback to no namespace
            if group_id is None:
                group_id = dep.find('groupId')
            if artifact_id is None:
                artifact_id = dep.find('artifactId')
            if version is None:
                version = dep.find('version')
            if scope is None:
                scope = dep.find('scope')

            if group_id is not None and artifact_id is not None:
                dep_info = {
                    'groupId': group_id.text,
                    'artifactId': artifact_id.text,
                    'version': version.text if version is not None else None,
                    'scope': scope.text if scope is not None else 'compile'
                }
                dependencies.append(dep_info)

        print_success(f"Parsed POM: {pom_path.name} ({len(dependencies)} direct dependencies)")
        return dependencies

    except Exception as e:
        print_error(f"Failed to parse POM {pom_path}: {e}")
        return []


def map_graphml_node_to_sha256(node_label: str, odc_lookup: Dict[str, List[Dict]]) -> Optional[str]:
    """
    Map GraphML node label to SHA256 from ODC data

    Args:
        node_label: GraphML label like "com.fasterxml.jackson.core:jackson-databind:jar:2.9.8:compile"
        odc_lookup: Lookup map from build_odc_lookup_map()

    Returns:
        SHA256 or None if not found
    """
    if not node_label:
        return None

    # Parse GraphML label: "groupId:artifactId:type:version:scope"
    # Example: "com.fasterxml.jackson.core:jackson-databind:jar:2.9.8:compile"
    parts = node_label.split(':')

    group_id = None
    artifact_id = None
    version = None

    # Standard Maven format has 5 parts: groupId:artifactId:type:version:scope
    if len(parts) == 5:
        group_id = parts[0]      # com.fasterxml.jackson.core
        artifact_id = parts[1]   # jackson-databind
        # type_ = parts[2]       # jar (not used)
        version = parts[3]       # 2.9.8
        # scope = parts[4]       # compile (not used)
    elif len(parts) == 4:
        # Fallback: groupId:artifactId:version:scope (no type)
        group_id = parts[0]
        artifact_id = parts[1]
        version = parts[2]
        # scope = parts[3]
    elif len(parts) == 3:
        # Fallback: groupId:artifactId:version
        group_id = parts[0]
        artifact_id = parts[1]
        version = parts[2]
    elif len(parts) == 2:
        # Fallback: groupId:artifactId
        group_id = parts[0]
        artifact_id = parts[1]
    else:
        # Unsupported format
        return None

    if not group_id or not artifact_id:
        return None

    # Look up in ODC map
    key = f"{group_id}:{artifact_id}"
    candidates = odc_lookup.get(key, [])

    # Find exact version match first
    if version:
        for candidate in candidates:
            if candidate.get('version') == version:
                return candidate.get('sha256')

    # Fallback 1: If only one candidate exists, assume it is the match
    if len(candidates) == 1:
        return candidates[0].get('sha256')

    # Fallback 2: Try partial version match
    if version and candidates:
        for candidate in candidates:
            cand_ver = candidate.get('version')
            if cand_ver and (cand_ver.startswith(version) or version.startswith(cand_ver)):
                return candidate.get('sha256')

    # Fallback 3: Return first candidate if any exist (better than nothing)
    if candidates:
        return candidates[0].get('sha256')

    # No match found
    return None


class Neo4jImporter:
    """Handles Neo4j import operations"""

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_constraints(self):
        """Create uniqueness constraints"""
        with self.driver.session() as session:
            constraints = [
                "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Project) REQUIRE p.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Module) REQUIRE m.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Dependency) REQUIRE d.sha256 IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE",
                # Direct Dependency -> ArtifactVersion model (Plan1.md Yöntem 2)
                "CREATE CONSTRAINT IF NOT EXISTS FOR (av:ArtifactVersion) REQUIRE av.key IS UNIQUE"
            ]

            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    print_warning(f"Constraint creation: {e}")

        print_success("Created Neo4j constraints")

    def import_project(self, project_name: str, modules: List[ModuleData]):
        """
        Import entire project with modules

        Args:
            project_name: Project name/identifier
            modules: List of module data
        """
        with self.driver.session() as session:
            # Create/merge project node
            session.run("""
                MERGE (p:Project {name: $name})
                SET p.updated = datetime()
            """, name=project_name)
            print_success(f"Created/updated Project: {project_name}")

            # Import each module
            for module in modules:
                self._import_module(session, project_name, module)

            # Create upgrade paths between versions
            print_info("Creating version upgrade paths...")
            self._create_version_upgrade_paths(session)
            print_success("Version upgrade paths created")

    def _import_module(self, session, project_name: str, module: ModuleData):
        """Import a single module"""
        module_id = f"{project_name}:{module.module_name}"

        # Create/merge module node
        session.run("""
            MERGE (m:Module {id: $id})
            SET m.name = $name,
                m.project = $project,
                m.updated = datetime()
            WITH m
            MATCH (p:Project {name: $project})
            MERGE (p)-[:HAS_MODULE]->(m)
        """, id=module_id, name=module.module_name, project=project_name)

        print_info(f"Processing module: {module.module_name}")

        # Load ODC JSON
        odc_data = load_odc_json(module.odc_json_path)
        if not odc_data:
            return

        # Load DOT dependency tree if available
        dot_data = {}
        direct_dep_ids = set()
        dot_edges = []
        root_node_id = None
        if module.dot_path:
            dot_data, direct_dep_ids, dot_edges, root_node_id = parse_dot(module.dot_path)

        # Load remediation.json if available for this module
        remediation_map = {}
        if module.remediation_json_path:
            remediation_list = load_remediation_json(module.remediation_json_path)
            if remediation_list:
                for item in remediation_list:
                    gid = item.get('groupId')
                    aid = item.get('artifactId')
                    if gid and aid:
                        remediation_map[f"{gid}:{aid}"] = {
                            'availableVersions': item.get('availableVersions'),
                            'remediationVersion': item.get('remediationVersion'),
                            'currentVersion': item.get('currentVersion')
                        }
                print_info(f"  Loaded remediation entries: {len(remediation_map)}")

        # Import dependencies and vulnerabilities
        dependencies = odc_data.get('dependencies', [])
        print_info(f"  Found {len(dependencies)} dependencies")

        for dep in dependencies:
            self._import_dependency(session, module_id, dep, dot_data, remediation_map, direct_dep_ids)

        # Build ODC lookup map for GraphML edge matching and phantom detection
        odc_lookup = {}
        for dep in dependencies:
            packages = dep.get('packages', [])
            if packages:
                pkg = packages[0]
                pkg_id = pkg.get('id', '')

                if pkg_id.startswith('pkg:maven/'):
                    rest = pkg_id.replace('pkg:maven/', '', 1)
                    if '@' in rest:
                        artifact_part, version = rest.rsplit('@', 1)
                    else:
                        artifact_part = rest
                        version = None

                    parts = artifact_part.split('/')
                    if len(parts) >= 2:
                        group_id = '.'.join(parts[:-1])
                        artifact_id = parts[-1]
                        key = f"{group_id}:{artifact_id}"

                        if key not in odc_lookup:
                            odc_lookup[key] = []

                        odc_lookup[key].append({
                            'sha256': dep.get('sha256'),
                            'version': version
                        })

        # Import DOT edges as DEPENDS_ON relationships
        if dot_edges:
            print_info(f"  Importing DOT edges as DEPENDS_ON relationships...")
            # First, ensure all DOT nodes exist as Dependency nodes (even if not in ODC)
            # This includes phantom packages like spring-boot-starter-web
            self._ensure_dot_dependencies_exist(session, module_id, dot_data, direct_dep_ids, root_node_id)
            self._import_dot_edges(session, dot_edges, dot_data, odc_lookup, root_node_id)

        # Note: Phantom dependency import from POM is now handled via DOT file
        # DOT format includes phantom packages that GraphML missed
        # We keep POM parsing for backward compatibility and edge cases
        if module.pom_path:
            pom_dependencies = parse_pom_dependencies(module.pom_path)
            # Pass remediation_map so phantom nodes can get remediation/version info if available
            self._import_pom_phantom_dependencies(session, module_id, pom_dependencies, odc_lookup, remediation_map)

    def _import_pom_phantom_dependencies(self, session, module_id: str, pom_deps: List[Dict], odc_lookup: Dict, remediation_map: Dict = None):
        """
        Import dependencies declared in POM but not found in OWASP Dependency Check.

        These "phantom" dependencies are typically:
        - BOM (Bill of Materials) packages
        - Starter packages (like spring-boot-starter-*)
        - POM-type dependencies that aggregate other jars

        They are marked as isPhantomDependency=true and isDirectDependency=true.

        Also creates DEPENDS_ON relationships to related packages found in ODC
        based on groupId prefix matching (e.g., spring-boot-starter-web -> spring-*)
        """
        phantom_count = 0
        linked_count = 0
        project_code, module_name = module_id.split(':', 1)

        # Build a map of phantom dependencies for linking
        phantom_deps = []

        for pom_dep in pom_deps:
            gid = pom_dep.get('groupId')
            aid = pom_dep.get('artifactId')
            version = pom_dep.get('version')
            scope = pom_dep.get('scope', 'compile')

            if not gid or not aid:
                continue

            key = f"{gid}:{aid}"

            # Check if this dependency exists in ODC (has a sha256)
            if key in odc_lookup:
                # Already imported via ODC, skip
                continue

            # This is a phantom dependency - create it without sha256
            # IMPORTANT: MERGE on (groupId, artifactId, version) to match with DOT import
            # DOT import uses same key, so they will share the same node
            phantom_id = f"{gid}:{aid}:{version}" if version else f"{gid}:{aid}:unknown"

            session.run("""
                MERGE (d:Dependency {groupId: $gid, artifactId: $aid, detectedVersion: $version})
                SET d.phantomId = COALESCE(d.phantomId, $phantom_id),
                    d.scope = $scope,
                    d.isPhantomDependency = true,
                    d.hasRemediation = false,
                    d.description = 'POM/BOM/Starter dependency (no jar file)',
                    d.usedByModules = CASE
                        WHEN d.usedByModules IS NULL THEN [$module_name]
                        WHEN NOT $module_name IN d.usedByModules THEN d.usedByModules + $module_name
                        ELSE d.usedByModules
                    END,
                    d.usedByProjects = CASE
                        WHEN d.usedByProjects IS NULL THEN [$project_code]
                        WHEN NOT $project_code IN d.usedByProjects THEN d.usedByProjects + $project_code
                        ELSE d.usedByProjects
                    END
                WITH d
                MATCH (m:Module {id: $module_id})
                MERGE (m)-[r:USES_DEPENDENCY]->(d)
                SET r.addedDate = datetime(),
                    r.module = $module_name,
                    r.project = $project_code,
                    r.fromPom = true,
                    r.isDirectDependency = true
            """, phantom_id=phantom_id, gid=gid, aid=aid, version=version,
                 scope=scope, module_id=module_id, module_name=module_name, project_code=project_code)

            phantom_count += 1
            phantom_deps.append({'phantom_id': phantom_id, 'gid': gid, 'aid': aid})
            print_info(f"    + Phantom: {gid}:{aid}:{version or 'unknown'}")

            # If remediation exists for this phantom, create ArtifactVersion nodes/links
            rem_entry = None
            if remediation_map:
                rem_entry = remediation_map.get(f"{gid}:{aid}")

            if rem_entry:
                # Create CURRENT/RECOMMENDED/AVAILABLE ArtifactVersion nodes and relationships
                # Use the same structure as used for regular dependencies
                session.run("""
                    MATCH (d:Dependency {phantomId: $phantom_id})
                    MERGE (cur:ArtifactVersion { key: d.groupId + ':' + d.artifactId + ':' + $currentVersion })
                    ON CREATE SET
                      cur.gid = d.groupId,
                      cur.aid = d.artifactId,
                      cur.version = $currentVersion,
                      cur.majorVersion = toInteger(split($currentVersion, '.')[0]),
                      cur.minorVersion = CASE WHEN size(split($currentVersion, '.')) > 1 THEN toInteger(split($currentVersion, '.')[1]) ELSE 0 END,
                      cur.patchVersion = CASE WHEN size(split($currentVersion, '.')) > 2 THEN toInteger(split($currentVersion, '.')[2]) ELSE 0 END,
                      cur.created = datetime(),
                      cur.updated = datetime()
                    ON MATCH SET cur.updated = datetime()

                    MERGE (d)-[rcur:CURRENT_VERSION {project: $project_code, module: $module_name}]->(cur)
                    ON CREATE SET rcur.detectedAt = datetime()

                    FOREACH (_ IN CASE WHEN $remediationVersion IS NULL THEN [] ELSE [1] END |
                      MERGE (rec:ArtifactVersion { key: d.groupId + ':' + d.artifactId + ':' + $remediationVersion })
                      ON CREATE SET
                        rec.gid = d.groupId,
                        rec.aid = d.artifactId,
                        rec.version = $remediationVersion,
                        rec.majorVersion = toInteger(split($remediationVersion, '.')[0]),
                        rec.minorVersion = CASE WHEN size(split($remediationVersion, '.')) > 1 THEN toInteger(split($remediationVersion, '.')[1]) ELSE 0 END,
                        rec.patchVersion = CASE WHEN size(split($remediationVersion, '.')) > 2 THEN toInteger(split($remediationVersion, '.')[2]) ELSE 0 END,
                        rec.hasCVE = false,
                        rec.cveCount = 0,
                        rec.created = datetime(),
                        rec.updated = datetime()
                      ON MATCH SET rec.updated = datetime()

                      MERGE (d)-[rrec:RECOMMENDED_VERSION {project: $project_code, module: $module_name}]->(rec)
                      ON CREATE SET rrec.detectedAt = datetime()
                    )

                    FOREACH (v IN COALESCE($availableVersions, []) |
                      MERGE (av:ArtifactVersion { key: d.groupId + ':' + d.artifactId + ':' + v })
                      ON CREATE SET
                        av.gid = d.groupId,
                        av.aid = d.artifactId,
                        av.version = v,
                        av.majorVersion = toInteger(split(v, '.')[0]),
                        av.minorVersion = CASE WHEN size(split(v, '.')) > 1 THEN toInteger(split(v, '.')[1]) ELSE 0 END,
                        av.patchVersion = CASE WHEN size(split(v, '.')) > 2 THEN toInteger(split(v, '.')[2]) ELSE 0 END,
                        av.created = datetime(),
                        av.updated = datetime()
                      ON MATCH SET av.updated = datetime()

                      MERGE (d)-[rav:AVAILABLE_VERSION {project: $project_code, module: $module_name}]->(av)
                      ON CREATE SET rav.detectedAt = datetime()
                    )

                    SET d.hasRemediation = true
                """, phantom_id=phantom_id, currentVersion=rem_entry.get('currentVersion') or 'unknown',
                     remediationVersion=rem_entry.get('remediationVersion'), availableVersions=rem_entry.get('availableVersions'),
                     project_code=project_code, module_name=module_name)

        # Link phantom dependencies to related ODC packages
        # Strategy: Match by groupId prefix for known starter patterns
        if phantom_deps and odc_lookup:
            for phantom in phantom_deps:
                phantom_gid = phantom['gid']
                phantom_aid = phantom['aid']
                phantom_id = phantom['phantom_id']

                # Determine the groupId prefix to match
                # For spring-boot-starter-*, match org.springframework.*
                # For other starters, match the base groupId
                match_prefixes = []

                if 'springframework' in phantom_gid or 'spring-boot' in phantom_aid:
                    match_prefixes = ['org.springframework', 'org.apache.tomcat', 'io.micrometer']
                elif 'jackson' in phantom_gid:
                    match_prefixes = ['com.fasterxml.jackson']
                elif 'log4j' in phantom_gid or 'logging' in phantom_gid:
                    match_prefixes = ['org.apache.logging', 'org.slf4j']
                else:
                    # Default: match same groupId prefix (first 2 parts)
                    parts = phantom_gid.split('.')
                    if len(parts) >= 2:
                        match_prefixes = ['.'.join(parts[:2])]

                # Find and link related packages from ODC
                for odc_key in odc_lookup.keys():
                    odc_gid = odc_key.split(':')[0]

                    for prefix in match_prefixes:
                        if odc_gid.startswith(prefix):
                            # Get SHA256 for this ODC package
                            for odc_entry in odc_lookup[odc_key]:
                                sha256 = odc_entry.get('sha256')
                                if sha256:
                                    # Create DEPENDS_ON relationship
                                    session.run("""
                                        MATCH (phantom:Dependency {phantomId: $phantom_id})
                                        MATCH (target:Dependency {sha256: $sha256})
                                        MERGE (phantom)-[:DEPENDS_ON]->(target)
                                    """, phantom_id=phantom_id, sha256=sha256)
                                    linked_count += 1
                            break  # Found a match for this prefix

        if phantom_count > 0:
            print_success(f"  Imported {phantom_count} phantom dependencies from POM")
        if linked_count > 0:
            print_success(f"  Created {linked_count} DEPENDS_ON links from phantom to ODC packages")

    def _import_dependency(self, session, module_id: str, dep: Dict, graphml_data: Dict, remediation_map: Dict[str, Dict], direct_dep_ids: Set[str]):
        """Import a single dependency"""
        # Extract dependency properties
        sha256 = dep.get('sha256')
        if not sha256:
            return  # Skip if no identifier

        props = {
            'sha256': sha256,
            'fileName': dep.get('fileName'),
            'filePath': dep.get('filePath'),
            'md5': dep.get('md5'),
            'sha1': dep.get('sha1'),
            'description': dep.get('description'),
            'license': dep.get('license')
        }

        # Extract package info (for GraphML mapping and remediation matching)
        packages = dep.get('packages', [])
        if packages:
            pkg = packages[0]
            pkg_id = pkg.get('id', '')

            # Parse package URL format: pkg:maven/GROUP_ID/ARTIFACT_ID@VERSION
            if pkg_id.startswith('pkg:maven/'):
                rest = pkg_id.replace('pkg:maven/', '', 1)

                # Extract version (after @)
                if '@' in rest:
                    artifact_part, version = rest.rsplit('@', 1)
                    props['detectedVersion'] = version
                else:
                    artifact_part = rest
                    props['detectedVersion'] = None

                # Extract groupId and artifactId (split by /)
                parts = artifact_part.split('/')
                if len(parts) >= 2:
                    # Last part is artifactId, rest is groupId with dots
                    props['artifactId'] = parts[-1]
                    props['groupId'] = '.'.join(parts[:-1])
                else:
                    props['groupId'] = None
                    props['artifactId'] = None
            else:
                # Fallback to old parsing if format is different
                props['groupId'] = pkg_id.split(':')[0] if ':' in pkg_id else None
                props['artifactId'] = pkg_id.split(':')[1] if ':' in pkg_id else None
                props['detectedVersion'] = pkg_id.split(':')[2] if pkg_id.count(':') >= 2 else None

        # Determine if this is a direct dependency by checking GraphML
        is_direct = False
        gid = props.get('groupId')
        aid = props.get('artifactId')
        if gid and aid and direct_dep_ids and graphml_data:
            # Check if any of the direct dependency nodes match this groupId:artifactId
            for dep_node_id in direct_dep_ids:
                node_label = graphml_data.get(dep_node_id, {}).get('label', '')
                # GraphML label format: "groupId:artifactId:type:version:scope"
                # Check if both groupId and artifactId appear in the label
                if f"{gid}:{aid}" in node_label:
                    is_direct = True
                    break

        # Lookup remediation info by groupId:artifactId
        remediation = None
        gid = props.get('groupId')
        aid = props.get('artifactId')
        if gid and aid and remediation_map:
            remediation = remediation_map.get(f"{gid}:{aid}")
            if remediation:
                rem_version = remediation.get('remediationVersion')
                if rem_version:
                    print_success(f"    ✓ Remediation: {gid}:{aid} -> {rem_version}")
                else:
                    print_info(f"    ℹ No remediation version for: {gid}:{aid}")

        # Extract project code and module name from module_id
        # Format: "PROJECT_CODE:module_name"
        project_code, module_name = module_id.split(':', 1)

        # Create/merge dependency node with array properties for fast LLM queries
        session.run("""
            MERGE (d:Dependency {sha256: $sha256})
            SET d += $props

            // Add module to usedByModules array if not already present
            SET d.usedByModules = CASE
                WHEN d.usedByModules IS NULL THEN [$module_name]
                WHEN NOT $module_name IN d.usedByModules THEN d.usedByModules + $module_name
                ELSE d.usedByModules
            END

            // Add project to usedByProjects array if not already present
            SET d.usedByProjects = CASE
                WHEN d.usedByProjects IS NULL THEN [$project_code]
                WHEN NOT $project_code IN d.usedByProjects THEN d.usedByProjects + $project_code
                ELSE d.usedByProjects
            END

            // Set hasRemediation property for easy querying by LLM
            SET d.hasRemediation = ($remediation IS NOT NULL AND $remediation.remediationVersion IS NOT NULL)

            WITH d, $remediation AS remediation, $module_id AS module_id, $module_name AS module_name, $project_code AS project_code

            // Direct Dependency -> ArtifactVersion model (Plan1.md Yöntem 2 + multi-project context)
            FOREACH (_ IN CASE WHEN remediation IS NULL OR d.groupId IS NULL OR d.artifactId IS NULL THEN [] ELSE [1] END |
              // Create current version node with version parsing
              MERGE (cur:ArtifactVersion { key: d.groupId + ':' + d.artifactId + ':' + remediation.currentVersion })
              ON CREATE SET
                cur.gid = d.groupId,
                cur.aid = d.artifactId,
                cur.version = remediation.currentVersion,
                cur.majorVersion = toInteger(split(remediation.currentVersion, '.')[0]),
                cur.minorVersion = CASE WHEN size(split(remediation.currentVersion, '.')) > 1
                                    THEN toInteger(split(remediation.currentVersion, '.')[1])
                                    ELSE 0 END,
                cur.patchVersion = CASE WHEN size(split(remediation.currentVersion, '.')) > 2
                                    THEN toInteger(split(remediation.currentVersion, '.')[2])
                                    ELSE 0 END,
                cur.created = datetime(),
                cur.updated = datetime()
              ON MATCH SET cur.updated = datetime()

              // Link Dependency -> Current Version with project/module context
              MERGE (d)-[rcur:CURRENT_VERSION {project: project_code, module: module_name}]->(cur)
              ON CREATE SET rcur.detectedAt = datetime()

              // Recommended version node and link (if exists)
              FOREACH (_ IN CASE WHEN remediation.remediationVersion IS NULL THEN [] ELSE [1] END |
                MERGE (rec:ArtifactVersion { key: d.groupId + ':' + d.artifactId + ':' + remediation.remediationVersion })
                ON CREATE SET
                  rec.gid = d.groupId,
                  rec.aid = d.artifactId,
                  rec.version = remediation.remediationVersion,
                  rec.majorVersion = toInteger(split(remediation.remediationVersion, '.')[0]),
                  rec.minorVersion = CASE WHEN size(split(remediation.remediationVersion, '.')) > 1
                                      THEN toInteger(split(remediation.remediationVersion, '.')[1])
                                      ELSE 0 END,
                  rec.patchVersion = CASE WHEN size(split(remediation.remediationVersion, '.')) > 2
                                      THEN toInteger(split(remediation.remediationVersion, '.')[2])
                                      ELSE 0 END,
                  rec.hasCVE = false,
                  rec.cveCount = 0,
                  rec.created = datetime(),
                  rec.updated = datetime()
                ON MATCH SET rec.updated = datetime()

                // Link Dependency -> Recommended Version with context
                MERGE (d)-[rrec:RECOMMENDED_VERSION {project: project_code, module: module_name}]->(rec)
                ON CREATE SET rrec.detectedAt = datetime()
              )

              // Available versions nodes and links
              FOREACH (v IN COALESCE(remediation.availableVersions, []) |
                MERGE (av:ArtifactVersion { key: d.groupId + ':' + d.artifactId + ':' + v })
                ON CREATE SET
                  av.gid = d.groupId,
                  av.aid = d.artifactId,
                  av.version = v,
                  av.majorVersion = toInteger(split(v, '.')[0]),
                  av.minorVersion = CASE WHEN size(split(v, '.')) > 1
                                     THEN toInteger(split(v, '.')[1])
                                     ELSE 0 END,
                  av.patchVersion = CASE WHEN size(split(v, '.')) > 2
                                     THEN toInteger(split(v, '.')[2])
                                     ELSE 0 END,
                  av.created = datetime(),
                  av.updated = datetime()
                ON MATCH SET av.updated = datetime()

                // Link Dependency -> Available Version with context
                MERGE (d)-[rav:AVAILABLE_VERSION {project: project_code, module: module_name}]->(av)
                ON CREATE SET rav.detectedAt = datetime()
              )
            )

            WITH d, module_id, module_name, project_code
            MATCH (m:Module {id: $module_id})
            MERGE (m)-[r:USES_DEPENDENCY]->(d)

            // Add metadata to relationship for detailed analysis
            SET r.addedDate = datetime(),
                r.module = $module_name,
                r.project = $project_code,
                r.isDirectDependency = $is_direct
        """, sha256=sha256, props=props, module_id=module_id,
             module_name=module_name, project_code=project_code, remediation=remediation, is_direct=is_direct)

        # Import vulnerabilities
        vulnerabilities = dep.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            self._import_vulnerability(session, sha256, vuln)

    def _import_vulnerability(self, session, dep_sha256: str, vuln: Dict):
        """Import a vulnerability and enrich current version nodes with CVE data"""
        vuln_name = vuln.get('name')
        if not vuln_name:
            return

        # Extract CVSS score
        cvss_score = None
        if 'cvssv3' in vuln and vuln['cvssv3']:
            cvss_score = vuln['cvssv3'].get('baseScore')
        elif 'cvssv2' in vuln and vuln['cvssv2']:
            cvss_score = vuln['cvssv2'].get('score')

        vuln_props = {
            'name': vuln_name,
            'description': vuln.get('description'),
            'severity': vuln.get('severity'),
            'cvssScore': cvss_score,
            'source': vuln.get('source')
        }

        severity = vuln.get('severity', 'UNKNOWN')

        session.run("""
            MERGE (v:Vulnerability {name: $name})
            SET v += $props
            WITH v
            MATCH (d:Dependency {sha256: $dep_sha256})
            MERGE (d)-[:HAS_VULNERABILITY]->(v)

            // Enrich current version nodes with CVE data
            WITH d, v
            OPTIONAL MATCH (d)-[:CURRENT_VERSION]->(cv:ArtifactVersion)
            WHERE cv IS NOT NULL
            SET cv.hasCVE = true,
                cv.cveCount = COALESCE(cv.cveCount, 0) + 1,
                cv.highSeverityCVECount = CASE
                    WHEN $severity IN ['HIGH', 'CRITICAL']
                    THEN COALESCE(cv.highSeverityCVECount, 0) + 1
                    ELSE COALESCE(cv.highSeverityCVECount, 0)
                END
        """, name=vuln_name, props=vuln_props, dep_sha256=dep_sha256, severity=severity)

    def _ensure_dot_dependencies_exist(self, session, module_id: str, dot_data: Dict, direct_dep_ids: Set[str], root_node_id: str = None):
        """
        Ensure all dependencies from DOT file exist in Neo4j.

        This is important because ODC may not report all transitive dependencies
        (e.g., non-vulnerable ones) or phantom packages (like spring-boot-starter-web).
        We need these nodes to exist for DEPENDS_ON relationships to work.

        DOT format captures phantom packages that GraphML misses.

        Args:
            session: Neo4j session
            module_id: Module ID for context
            dot_data: Dictionary of node label -> node_data from parse_dot
            direct_dep_ids: Set of labels that are direct dependencies (from root node edges)
            root_node_id: Root node label to skip (module itself)
        """
        created_count = 0
        existing_count = 0
        phantom_count = 0
        project_code, module_name = module_id.split(':', 1)

        for node_label, node_data in dot_data.items():
            # Skip root node (it's the module itself, not a dependency)
            if node_label == root_node_id:
                continue

            label = node_data.get('label')
            if not label:
                continue

            coords = self._parse_maven_label(label)
            if not coords:
                continue

            group_id = coords.get('groupId')
            artifact_id = coords.get('artifactId')
            version = coords.get('version')
            pkg_type = coords.get('type', 'jar')

            if not group_id or not artifact_id:
                continue

            # Determine if this is a direct dependency
            is_direct = node_label in direct_dep_ids

            # Determine if this is a phantom package (pom type = no jar file)
            is_phantom = pkg_type == 'pom'

            # Check if dependency already exists with EXACT VERSION
            # Different versions of same artifact must be different nodes!
            existing = session.run("""
                MATCH (d:Dependency)
                WHERE d.groupId = $gid
                  AND d.artifactId = $aid
                  AND d.detectedVersion = $version
                RETURN d.sha256 as sha256
                LIMIT 1
            """, gid=group_id, aid=artifact_id, version=version).single()

            if existing:
                existing_count += 1
                # Create/update USES_DEPENDENCY relationship with isDirectDependency
                # IMPORTANT: Match by groupId, artifactId AND version to avoid cross-contamination
                session.run("""
                    MATCH (d:Dependency)
                    WHERE d.groupId = $gid
                      AND d.artifactId = $aid
                      AND d.detectedVersion = $version
                    WITH d
                    MATCH (m:Module {id: $module_id})
                    MERGE (m)-[r:USES_DEPENDENCY]->(d)
                    SET r.isDirectDependency = $is_direct,
                        r.module = $module_name,
                        r.project = $project_code
                """, gid=group_id, aid=artifact_id, version=version, is_direct=is_direct,
                     module_id=module_id, module_name=module_name, project_code=project_code)
            else:
                # Create a DOT-only dependency node
                # These include phantom packages and transitive deps not in ODC
                dot_id = f"dot:{group_id}:{artifact_id}:{version or 'unknown'}"

                # IMPORTANT: MERGE on (groupId, artifactId, version) to avoid version conflicts
                # Different versions of same artifact MUST be different nodes
                # Example: spring-core:5.2.0 and spring-core:6.1.10 are DIFFERENT dependencies
                session.run("""
                    MERGE (d:Dependency {groupId: $gid, artifactId: $aid, detectedVersion: $version})
                    SET d.packageType = COALESCE(d.packageType, $pkg_type),
                        d.isDotOnly = COALESCE(d.isDotOnly, true),
                        d.isPhantomDependency = COALESCE(d.isPhantomDependency, $is_phantom),
                        d.hasRemediation = COALESCE(d.hasRemediation, false),
                        d.dotId = COALESCE(d.dotId, $dot_id),
                        d.description = COALESCE(d.description,
                            CASE
                                WHEN $is_phantom THEN 'Phantom/BOM package from DOT (no jar file, direct dependency in pom.xml)'
                                ELSE 'Transitive dependency from DOT (not in OWASP DC report)'
                            END),
                        d.usedByModules = CASE
                            WHEN d.usedByModules IS NULL THEN [$module_name]
                            WHEN NOT $module_name IN d.usedByModules THEN d.usedByModules + $module_name
                            ELSE d.usedByModules
                        END,
                        d.usedByProjects = CASE
                            WHEN d.usedByProjects IS NULL THEN [$project_code]
                            WHEN NOT $project_code IN d.usedByProjects THEN d.usedByProjects + $project_code
                            ELSE d.usedByProjects
                        END
                    WITH d
                    MATCH (m:Module {id: $module_id})
                    MERGE (m)-[r:USES_DEPENDENCY]->(d)
                    SET r.isDirectDependency = $is_direct,
                        r.module = $module_name,
                        r.project = $project_code
                """, dot_id=dot_id, gid=group_id, aid=artifact_id,
                     version=version, pkg_type=pkg_type, is_phantom=is_phantom,
                     is_direct=is_direct, module_id=module_id, module_name=module_name,
                     project_code=project_code)

                created_count += 1
                if is_phantom:
                    phantom_count += 1

        if created_count > 0:
            print_success(f"  Created {created_count} DOT-only dependency nodes ({phantom_count} phantom packages)")
        print_info(f"  Found {existing_count} existing dependencies in Neo4j")

    def _import_dot_edges(self, session, edges_list: List[Dict], dot_data: Dict, odc_lookup: Dict, root_node_id: str = None):
        """
        Import all DOT edges as DEPENDS_ON relationships.

        Uses groupId:artifactId matching for reliability.

        Args:
            session: Neo4j session
            edges_list: List of edges from parse_dot
            dot_data: Node data from parse_dot
            odc_lookup: ODC lookup map (kept for compatibility)
            root_node_id: Root node label to skip (module itself)
        """
        imported_count = 0
        skipped_root_edges = 0
        not_found_count = 0

        print_info(f"  Processing {len(edges_list)} DOT edges...")

        for edge in edges_list:
            source_label = edge.get('source_label')
            target_label = edge.get('target_label')

            # Skip edges from root node (module itself - already handled by USES_DEPENDENCY)
            if root_node_id and source_label == root_node_id:
                skipped_root_edges += 1
                continue

            # Parse labels to get groupId:artifactId
            source_coords = self._parse_maven_label(source_label)
            target_coords = self._parse_maven_label(target_label)

            if not source_coords or not target_coords:
                not_found_count += 1
                continue

            # Create DEPENDS_ON relationship using groupId + artifactId matching
            result = session.run("""
                MATCH (source:Dependency)
                WHERE source.groupId = $source_gid AND source.artifactId = $source_aid
                MATCH (target:Dependency)
                WHERE target.groupId = $target_gid AND target.artifactId = $target_aid
                MERGE (source)-[:DEPENDS_ON]->(target)
                RETURN count(*) as created
            """,
                source_gid=source_coords['groupId'],
                source_aid=source_coords['artifactId'],
                target_gid=target_coords['groupId'],
                target_aid=target_coords['artifactId']
            )

            created = result.single()["created"]
            if created > 0:
                imported_count += 1
            else:
                not_found_count += 1
                if not_found_count <= 3:
                    print_warning(f"    No match for: {source_coords['groupId']}:{source_coords['artifactId']} -> {target_coords['groupId']}:{target_coords['artifactId']}")

        print_success(f"Created {imported_count} DEPENDS_ON relationships")
        if skipped_root_edges > 0:
            print_info(f"  Skipped {skipped_root_edges} edges from module root (handled via USES_DEPENDENCY)")
        if not_found_count > 0:
            print_warning(f"  Could not match {not_found_count} edges (dependencies not in Neo4j)")

    def _parse_maven_label(self, label: str) -> Optional[Dict[str, str]]:
        """
        Parse Maven coordinate label from DOT/GraphML.

        Format: "groupId:artifactId:type:version:scope" or "groupId:artifactId:jar:version"
        Example: "com.fasterxml.jackson.core:jackson-databind:jar:2.9.8:compile"

        Returns:
            Dict with groupId, artifactId, type, version or None if parse fails
        """
        if not label:
            return None

        parts = label.split(':')

        if len(parts) >= 4:
            # Standard format: groupId:artifactId:type:version[:scope]
            return {
                'groupId': parts[0],
                'artifactId': parts[1],
                'type': parts[2],
                'version': parts[3],
                'scope': parts[4] if len(parts) > 4 else 'compile'
            }
        elif len(parts) == 3:
            # Short format: groupId:artifactId:version
            return {
                'groupId': parts[0],
                'artifactId': parts[1],
                'version': parts[2]
            }
        elif len(parts) == 2:
            # Minimal format: groupId:artifactId
            return {
                'groupId': parts[0],
                'artifactId': parts[1]
            }

        return None

    def _create_version_upgrade_paths(self, session):
        """Create UPGRADES_TO relationships between consecutive versions of same artifact"""
        session.run("""
            // Find all unique artifacts (gid:aid combinations)
            MATCH (v:ArtifactVersion)
            WITH DISTINCT v.gid AS gid, v.aid AS aid
            WHERE gid IS NOT NULL AND aid IS NOT NULL

            // For each artifact, get all versions sorted by version number
            MATCH (av:ArtifactVersion)
            WHERE av.gid = gid AND av.aid = aid
            WITH gid, aid, av
            ORDER BY av.majorVersion ASC, av.minorVersion ASC, av.patchVersion ASC
            WITH gid, aid, collect(av) AS sortedVersions

            // Create UPGRADES_TO between consecutive versions
            UNWIND range(0, size(sortedVersions) - 2) AS idx
            WITH sortedVersions[idx] AS fromVersion, sortedVersions[idx + 1] AS toVersion
            MERGE (fromVersion)-[:UPGRADES_TO]->(toVersion)
        """)


def main():
    parser = argparse.ArgumentParser(
        description='Import OWASP Dependency Check reports to Neo4j with project hierarchy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import all ODC reports from target directory
  %(prog)s --target-dir /app --project MY_PROJECT

  # Specify Neo4j connection
  %(prog)s --target-dir /app --project MY_PROJECT \\
    --neo4j-uri bolt://localhost:7687 \\
    --neo4j-user neo4j \\
    --neo4j-password mypassword

Graph Structure (Plan1.md Yöntem 2 + Multi-Project):
  (Project) -[:HAS_MODULE]-> (Module) -[:USES_DEPENDENCY]-> (Dependency)
  (Dependency) -[:HAS_VULNERABILITY]-> (Vulnerability)
  (Dependency) -[:CURRENT_VERSION {project, module}]-> (ArtifactVersion)
  (Dependency) -[:RECOMMENDED_VERSION {project, module}]-> (ArtifactVersion)
  (Dependency) -[:AVAILABLE_VERSION {project, module}]-> (ArtifactVersion)
  (ArtifactVersion) -[:UPGRADES_TO]-> (ArtifactVersion)
  (Dependency) -[:DEPENDS_ON]-> (Dependency)

Node Properties:
  Dependency: sha256, groupId, artifactId, detectedVersion (ODC detected), fileName
  ArtifactVersion: version, majorVersion, minorVersion, patchVersion, hasCVE, cveCount
        """
    )

    parser.add_argument('--target-dir',
                       required=True,
                       help='Directory containing ODC reports (recursive search)')
    parser.add_argument('--project',
                       required=True,
                       help='Project code/identifier')

    # Neo4j connection
    neo4j_group = parser.add_argument_group('Neo4j Connection')
    neo4j_group.add_argument('--neo4j-uri',
                            default=os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
                            help='Neo4j URI (default: bolt://localhost:7687)')
    neo4j_group.add_argument('--neo4j-user',
                            default=os.getenv('NEO4J_USER', 'neo4j'),
                            help='Neo4j username (default: neo4j)')
    neo4j_group.add_argument('--neo4j-password',
                            default=os.getenv('NEO4J_PASSWORD', 'password'),
                            help='Neo4j password')

    args = parser.parse_args()

    # Validate target directory
    if not os.path.isdir(args.target_dir):
        print_error(f"Target directory not found: {args.target_dir}")
        sys.exit(1)

    print_header("OWASP Dependency Check → Neo4j Importer")

    # Find all ODC reports
    print_info(f"Searching for ODC reports in: {args.target_dir}")
    modules = find_odc_reports(args.target_dir)

    if not modules:
        print_warning("No ODC reports found!")
        sys.exit(1)

    print_success(f"Found {len(modules)} module(s) with ODC reports")
    for module in modules:
        print(f"  - {module.module_name}")
        print(f"    JSON: {module.odc_json_path}")
        if module.dot_path:
            print(f"    DOT: {module.dot_path}")

    # Connect to Neo4j
    print_header("Connecting to Neo4j")
    print_info(f"URI: {args.neo4j_uri}")
    print_info(f"User: {args.neo4j_user}")

    try:
        importer = Neo4jImporter(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        print_success("Connected to Neo4j")
    except Exception as e:
        print_error(f"Failed to connect to Neo4j: {e}")
        sys.exit(1)

    try:
        # Create constraints
        importer.create_constraints()

        # Import data
        print_header(f"Importing Project: {args.project}")
        importer.import_project(args.project, modules)

        print_header("Import Complete")
        print_success(f"✓ Project: {args.project}")
        print_success(f"✓ Modules: {len(modules)}")
        print_success("✓ Check Neo4j Browser to view the graph")

    except Exception as e:
        print_error(f"Import failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        importer.close()


if __name__ == '__main__':
    main()
