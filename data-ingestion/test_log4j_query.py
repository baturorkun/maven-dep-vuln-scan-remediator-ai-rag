#!/usr/bin/env python3
"""Test script to query log4j dependencies from Neo4j"""

import sys
import os
sys.path.append('/Users/batur/Documents/Projects/github/maven-dep-vuln-scan-remediator-ai-rag/llm-agent')

from tools import read_neo4j_query
import json

def test_log4j_queries():
    """Test various Cypher queries for log4j dependencies"""

    # Query 1: Check if log4j exists in the database
    print("=" * 70)
    print("Query 1: Checking for log4j dependencies in database")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH (d:Dependency)
        WHERE d.groupId CONTAINS 'log4j' OR d.artifactId CONTAINS 'log4j'
        RETURN d.groupId, d.artifactId, d.detectedVersion, d.isDirectDependency
        LIMIT 10
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    if not data.get('success') or data.get('count', 0) == 0:
        print("⚠️ No log4j found! Let's check all dependencies with 'apache' or 'logging'")
        print()

        # Query 2: Check for apache logging dependencies
        print("=" * 70)
        print("Query 2: Checking for apache/logging dependencies")
        print("=" * 70)
        result = read_neo4j_query("""
            MATCH (d:Dependency)
            WHERE d.groupId CONTAINS 'apache' OR d.groupId CONTAINS 'logging' OR d.artifactId CONTAINS 'logging'
            RETURN d.groupId, d.artifactId, d.detectedVersion
            LIMIT 20
        """)
        data = json.loads(result)
        print(json.dumps(data, indent=2))
        print()

        # Query 3: Get all unique groupIds to understand what's in the database
        print("=" * 70)
        print("Query 3: List all unique groupIds (first 30)")
        print("=" * 70)
        result = read_neo4j_query("""
            MATCH (d:Dependency)
            WHERE d.groupId IS NOT NULL
            RETURN DISTINCT d.groupId
            ORDER BY d.groupId
            LIMIT 30
        """)
        data = json.loads(result)
        print(json.dumps(data, indent=2))
        print()
        return

    # If log4j exists, proceed with dependency tree queries
    print("✅ Log4j found! Now querying dependency tree...")
    print()

    # Query 4: Get direct dependencies of log4j (1st level)
    print("=" * 70)
    print("Query 4: Direct dependencies of log4j (1st level)")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH (log4j:Dependency)-[:DEPENDS_ON]->(child:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        RETURN log4j.groupId + ':' + log4j.artifactId AS log4j_artifact,
               child.groupId + ':' + child.artifactId AS dependency,
               child.detectedVersion AS version
        LIMIT 20
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 5: Get ALL transitive dependencies of log4j (all levels)
    print("=" * 70)
    print("Query 5: ALL transitive dependencies of log4j (recursive)")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH path = (log4j:Dependency)-[:DEPENDS_ON*1..5]->(child:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        RETURN log4j.groupId + ':' + log4j.artifactId AS log4j_artifact,
               child.groupId + ':' + child.artifactId AS transitive_dependency,
               child.detectedVersion AS version,
               length(path) AS depth
        ORDER BY depth, transitive_dependency
        LIMIT 50
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 6: Get dependency tree with path information
    print("=" * 70)
    print("Query 6: Dependency tree with full path")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH path = (log4j:Dependency)-[:DEPENDS_ON*1..3]->(child:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        WITH log4j, child, length(path) AS depth,
             [node IN nodes(path) | node.groupId + ':' + node.artifactId] AS full_path
        RETURN log4j.groupId + ':' + log4j.artifactId AS log4j_artifact,
               full_path,
               depth
        ORDER BY depth
        LIMIT 30
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

if __name__ == "__main__":
    test_log4j_queries()