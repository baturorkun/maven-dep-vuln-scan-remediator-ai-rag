from fastmcp import FastMCP
from tools import (
    read_neo4j_query,
    analyze_risk_statistics,
    visualize_dependency_graph,
    enrich_cve_data,
    list_projects,
    get_dependency_tree,
    diagnose_graph_relationships,
    get_remediation_suggestions
)

# Create MCP Server
mcp = FastMCP("OWASP Dependency Analysis Tools")

# Register tools
mcp.tool()(list_projects)
mcp.tool()(read_neo4j_query)
mcp.tool()(analyze_risk_statistics)
mcp.tool()(visualize_dependency_graph)
mcp.tool()(enrich_cve_data)
mcp.tool()(get_dependency_tree)
mcp.tool()(diagnose_graph_relationships)
mcp.tool()(get_remediation_suggestions)  # NEW: Remediation suggestions tool

if __name__ == "__main__":
    print("Starting MCP Server...")
    mcp.run()
