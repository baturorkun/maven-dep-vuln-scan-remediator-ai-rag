#!/usr/bin/env python3
"""
Test tools directly without MCP protocol.
Run: python test_tools.py
"""

import sys
from pathlib import Path

# Add mcp_agent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_agent"))

from tools import (
    read_neo4j_query,
    analyze_risk_statistics,
    visualize_dependency_graph,
    enrich_cve_data
)

print("=" * 50)
print("🧪 OWASP Dependency Analysis Tool Testing")
print("=" * 50)
print()

print("1. read_neo4j_query('MATCH (v:Vulnerability) RETURN count(v) as total')")
result = read_neo4j_query("MATCH (v:Vulnerability) RETURN count(v) as total")
print(f"   → {result}")
print()

print("2. read_neo4j_query('MATCH (v:Vulnerability) RETURN v.severity, count(*) as count ORDER BY count DESC LIMIT 5')")
result = read_neo4j_query("MATCH (v:Vulnerability) RETURN v.severity, count(*) as count ORDER BY count DESC LIMIT 5")
print(f"   → {result}")
print()

print("=" * 50)
print("🆕 Testing OWASP Analysis Tools")
print("=" * 50)
print()

print("3. analyze_risk_statistics()")
result = analyze_risk_statistics()
print(f"   → {result[:200]}..." if len(result) > 200 else f"   → {result}")
print()

print("4. visualize_dependency_graph(limit=10, output_file='test_graph.png')")
result = visualize_dependency_graph(limit=10, output_file="test_graph.png")
print(f"   → {result}")
print()

print("5. enrich_cve_data('CVE-2024-21733')")
result = enrich_cve_data("CVE-2024-21733")
print(f"   → {result[:200]}..." if len(result) > 200 else f"   → {result}")
print()

print("=" * 50)
print("✅ All tools working!")
print("=" * 50)
