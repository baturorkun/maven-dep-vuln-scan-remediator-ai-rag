#!/usr/bin/env python3
"""Test jackson transitive dependencies"""

import sys
import os
sys.path.append('/Users/batur/Documents/Projects/github/maven-dep-vuln-scan-remediator-ai-rag/llm-agent')

from tools import read_neo4j_query
import json

def test_jackson_transitive():
    """Test if jackson-databind's transitive dependencies are in Neo4j"""

    print("=" * 70)
    print("Query: Jackson-databind transitive dependencies")
    print("=" * 70)
    result = read_neo4j_query("""
        MATCH (jackson:Dependency)-[:DEPENDS_ON]->(child:Dependency)
        WHERE jackson.artifactId = 'jackson-databind'
        RETURN jackson.groupId + ':' + jackson.artifactId AS jackson_artifact,
               jackson.detectedVersion AS jackson_version,
               child.groupId + ':' + child.artifactId AS dependency,
               child.detectedVersion AS dep_version
    """)
    data = json.loads(result)
    print(json.dumps(data, indent=2))
    print()

    if data.get('count', 0) > 0:
        print("✅ SUCCESS: DEPENDS_ON relationships ARE working!")
        print("   Jackson-databind HAS transitive dependencies in Neo4j")
    else:
        print("❌ PROBLEM: No DEPENDS_ON relationships found for jackson-databind")
    print()

    # Now check log4j-core's REAL transitive deps (if we remove direct log4j-api from pom)
    print("=" * 70)
    print("Query: What if we check log4j-core separately?")
    print("=" * 70)
    print("In pom.xml, both log4j-core and log4j-api are DIRECT dependencies.")
    print("So Maven doesn't show log4j-core -> log4j-api as transitive.")
    print()
    print("Let's verify by checking GraphML manually...")

if __name__ == "__main__":
    test_jackson_transitive()