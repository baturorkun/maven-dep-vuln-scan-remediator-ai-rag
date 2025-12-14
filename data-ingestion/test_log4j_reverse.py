#!/usr/bin/env python3
"""Test script to query dependencies that DEPEND ON log4j (reverse direction)"""

import sys
import os
sys.path.append('/Users/batur/Documents/Projects/github/maven-dep-vuln-scan-remediator-ai-rag/llm-agent')

from tools import read_neo4j_query
import json

def test_reverse_log4j_queries():
    """Test queries for dependencies that USE log4j"""

    # Query 1: Find dependencies that directly depend on log4j
    print("=" * 70)
    print("Query 1: Dependencies that DIRECTLY depend on log4j")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH (parent:Dependency)-[:DEPENDS_ON]->(log4j:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        RETURN parent.groupId + ':' + parent.artifactId AS parent_dependency,
               parent.detectedVersion AS parent_version,
               log4j.groupId + ':' + log4j.artifactId AS log4j_artifact,
               log4j.detectedVersion AS log4j_version
        LIMIT 20
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 2: Find ALL dependencies that transitively depend on log4j (any depth)
    print("=" * 70)
    print("Query 2: ALL dependencies that TRANSITIVELY depend on log4j")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH path = (parent:Dependency)-[:DEPENDS_ON*1..5]->(log4j:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        RETURN parent.groupId + ':' + parent.artifactId AS parent_dependency,
               log4j.groupId + ':' + log4j.artifactId AS log4j_artifact,
               length(path) AS depth
        ORDER BY depth, parent_dependency
        LIMIT 30
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 3: Get the full dependency chain leading TO log4j
    print("=" * 70)
    print("Query 3: Full dependency chain TO log4j")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH path = (parent:Dependency)-[:DEPENDS_ON*1..3]->(log4j:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        WITH parent, log4j, length(path) AS depth,
             [node IN nodes(path) | node.groupId + ':' + node.artifactId + ':' + node.detectedVersion] AS full_path
        RETURN full_path, depth
        ORDER BY depth
        LIMIT 20
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 4: Check DEPENDS_ON relationships count
    print("=" * 70)
    print("Query 4: Count of all DEPENDS_ON relationships in database")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH ()-[r:DEPENDS_ON]->()
        RETURN count(r) AS total_depends_on_relationships
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 5: Check if log4j has any outgoing or incoming DEPENDS_ON relationships
    print("=" * 70)
    print("Query 5: Log4j relationship summary")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH (log4j:Dependency)
        WHERE log4j.groupId CONTAINS 'log4j' OR log4j.artifactId CONTAINS 'log4j'
        OPTIONAL MATCH (log4j)-[:DEPENDS_ON]->(child)
        OPTIONAL MATCH (parent)-[:DEPENDS_ON]->(log4j)
        WITH log4j,
             count(DISTINCT child) AS outgoing_count,
             count(DISTINCT parent) AS incoming_count
        RETURN log4j.groupId + ':' + log4j.artifactId AS artifact,
               log4j.detectedVersion AS version,
               outgoing_count AS dependencies_of_log4j,
               incoming_count AS dependencies_using_log4j
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    # Query 6: General DEPENDS_ON relationship statistics
    print("=" * 70)
    print("Query 6: Sample DEPENDS_ON relationships in database")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH (parent:Dependency)-[:DEPENDS_ON]->(child:Dependency)
        RETURN parent.groupId + ':' + parent.artifactId AS parent,
               child.groupId + ':' + child.artifactId AS child
        LIMIT 10
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

if __name__ == "__main__":
    test_reverse_log4j_queries()
