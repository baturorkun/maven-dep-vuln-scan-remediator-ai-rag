from fastmcp import FastMCP
from tools import (
    read_neo4j_query,
    analyze_risk_statistics,
    visualize_dependency_graph,
    enrich_cve_data,
    list_projects
)

# Create MCP Server
mcp = FastMCP("OWASP Dependency Analysis Tools")

# Register tools
mcp.tool()(list_projects)
mcp.tool()(read_neo4j_query)
mcp.tool()(analyze_risk_statistics)
mcp.tool()(visualize_dependency_graph)
mcp.tool()(enrich_cve_data)

if __name__ == "__main__":
    print("Starting MCP Server...")
    mcp.run()
