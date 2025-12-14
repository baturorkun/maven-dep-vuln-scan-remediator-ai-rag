#!/usr/bin/env python3
"""
Fix missing transitive dependencies by downloading POM files from Maven Central.

This script:
1. Finds all dependencies in Neo4j
2. Downloads their POM files from Maven Central
3. Parses the dependencies from those POM files
4. Creates DEPENDS_ON relationships in Neo4j

This solves the problem where direct dependencies in pom.xml hide transitive relationships.
"""

import os
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase
import requests
from urllib.parse import quote

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

def download_pom_from_maven_central(group_id: str, artifact_id: str, version: str) -> str:
    """Download POM file from Maven Central"""
    try:
        # Convert groupId dots to slashes
        group_path = group_id.replace('.', '/')

        # Maven Central URL format
        url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

        print(f"  Downloading POM from: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        return response.text
    except Exception as e:
        print(f"  Failed to download POM: {e}")
        return None

def parse_pom_dependencies(pom_xml: str) -> list:
    """Parse dependencies from POM XML string"""
    dependencies = []
    try:
        root = ET.fromstring(pom_xml)
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

        # Try with namespace
        deps = root.findall('.//m:dependencies/m:dependency', ns)
        if not deps:
            # Try without namespace
            deps = root.findall('.//dependencies/dependency')

        for dep in deps:
            # Find elements with proper null checking
            group_id = dep.find('m:groupId', ns)
            if group_id is None:
                group_id = dep.find('groupId')

            artifact_id = dep.find('m:artifactId', ns)
            if artifact_id is None:
                artifact_id = dep.find('artifactId')

            version = dep.find('m:version', ns)
            if version is None:
                version = dep.find('version')

            scope = dep.find('m:scope', ns)
            if scope is None:
                scope = dep.find('scope')

            optional = dep.find('m:optional', ns)
            if optional is None:
                optional = dep.find('optional')

            # Skip if no groupId or artifactId
            if group_id is None or artifact_id is None:
                continue

            # Skip optional dependencies
            if optional is not None and optional.text == 'true':
                continue

            # Skip test/provided dependencies
            scope_text = scope.text if scope is not None else 'compile'
            if scope_text in ['test', 'provided']:
                continue

            dependencies.append({
                'groupId': group_id.text,
                'artifactId': artifact_id.text,
                'version': version.text if version is not None else None
            })
    except Exception as e:
        print(f"Failed to parse POM XML: {e}")

    return dependencies

def find_dependency_in_neo4j(session, group_id: str, artifact_id: str):
    """Find dependency node in Neo4j by groupId:artifactId"""
    result = session.run("""
        MATCH (d:Dependency)
        WHERE d.groupId = $groupId AND d.artifactId = $artifactId
        RETURN d.sha256 AS sha256
        LIMIT 1
    """, groupId=group_id, artifactId=artifact_id)
    record = result.single()
    return record['sha256'] if record else None

def main():
    print("=" * 70)
    print("Fixing Missing Transitive Dependencies from Maven Central")
    print("=" * 70)
    print()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    try:
        with driver.session() as session:
            # Get all dependencies with groupId, artifactId, version
            result = session.run("""
                MATCH (d:Dependency)
                WHERE d.groupId IS NOT NULL
                  AND d.artifactId IS NOT NULL
                  AND d.detectedVersion IS NOT NULL
                  AND (d.isPhantomDependency IS NULL OR d.isPhantomDependency = false)
                RETURN d.sha256 AS sha256,
                       d.groupId AS groupId,
                       d.artifactId AS artifactId,
                       d.detectedVersion AS version
                ORDER BY d.groupId, d.artifactId
            """)

            dependencies = result.data()
            print(f"Found {len(dependencies)} dependencies in Neo4j")
            print()

            total_added = 0
            total_processed = 0
            total_skipped = 0

            for dep in dependencies:
                total_processed += 1
                parent_artifact = f"{dep['groupId']}:{dep['artifactId']}:{dep['version']}"
                print(f"[{total_processed}/{len(dependencies)}] Processing: {parent_artifact}")

                # Download POM from Maven Central
                pom_xml = download_pom_from_maven_central(
                    dep['groupId'],
                    dep['artifactId'],
                    dep['version']
                )

                if not pom_xml:
                    print(f"  ⚠️  Could not download POM")
                    total_skipped += 1
                    continue

                # Parse dependencies from POM
                pom_deps = parse_pom_dependencies(pom_xml)
                if not pom_deps:
                    print(f"  ℹ️  No dependencies in POM")
                    continue

                print(f"  Found {len(pom_deps)} dependencies in POM:")

                # Create DEPENDS_ON relationships
                for child_dep in pom_deps:
                    child_sha256 = find_dependency_in_neo4j(
                        session,
                        child_dep['groupId'],
                        child_dep['artifactId']
                    )

                    if child_sha256:
                        # Create DEPENDS_ON relationship
                        session.run("""
                            MATCH (parent:Dependency {sha256: $parentSha256})
                            MATCH (child:Dependency {sha256: $childSha256})
                            MERGE (parent)-[:DEPENDS_ON]->(child)
                        """, parentSha256=dep['sha256'], childSha256=child_sha256)

                        version_str = child_dep['version'] or '(version from parent)'
                        print(f"    ✅ {child_dep['groupId']}:{child_dep['artifactId']}:{version_str}")
                        total_added += 1
                    else:
                        version_str = child_dep['version'] or '(version from parent)'
                        print(f"    ⚠️  {child_dep['groupId']}:{child_dep['artifactId']}:{version_str} (not in Neo4j)")

                print()

            print("=" * 70)
            print(f"✅ Processed: {total_processed}")
            print(f"✅ Created {total_added} new DEPENDS_ON relationships")
            print(f"⚠️  Skipped: {total_skipped}")
            print("=" * 70)

    finally:
        driver.close()

if __name__ == "__main__":
    main()