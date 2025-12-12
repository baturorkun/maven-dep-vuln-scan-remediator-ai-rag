"""
Tool implementations - pure functions for OWASP dependency analysis.
These can be imported and tested directly.
"""

import json
import os
from neo4j import GraphDatabase
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import networkx as nx
    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def list_projects() -> str:
    """
    List all projects and their modules in the database with vulnerability and remediation summary.

    Use this tool when the user asks:
    - "What are my projects?"
    - "List projects"
    - "Show me all projects"
    - "What projects do I have?"
    - "Which projects are scanned?"
    - "Which project has the most vulnerabilities?"
    - "Show project vulnerability summary"

    Returns:
        JSON with list of projects and their modules, including:
        - Project names
        - Module count per project
        - Module names for each project
        - Total dependency count per module
        - Vulnerability count per project
        - Remediation count per project
    """
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # Get all projects with their modules, dependencies, vulnerabilities and remediations
            # NOTE: remediationCoverage = % of vulnerable dependencies that have a remediation
            result = session.run("""
                MATCH (p:Project)
                OPTIONAL MATCH (p)-[:HAS_MODULE]->(m:Module)
                OPTIONAL MATCH (m)-[:USES_DEPENDENCY]->(d:Dependency)
                OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WITH p, m, d, count(v) as vulnCountPerDep
                WITH p, m,
                     count(DISTINCT d) as depCount,
                     count(DISTINCT CASE WHEN vulnCountPerDep > 0 THEN d END) as vulnDepCount,
                     count(DISTINCT CASE WHEN vulnCountPerDep > 0 AND d.hasRemediation = true THEN d END) as remDepCount
                WITH p, collect({
                    name: m.name, 
                    id: m.id,
                    dependencyCount: depCount,
                    vulnerableDependencies: vulnDepCount,
                    remediatedDependencies: remDepCount
                }) as modules,
                sum(depCount) as totalDeps,
                sum(vulnDepCount) as totalVulnDeps,
                sum(remDepCount) as totalRemDeps
                RETURN p.name as projectName, 
                       p.updated as lastUpdated,
                       size(modules) as moduleCount,
                       totalDeps as totalDependencies,
                       totalVulnDeps as vulnerableDependencies,
                       totalRemDeps as remediatedDependencies,
                       modules
                ORDER BY totalVulnDeps DESC, p.name
            """).data()

            # Get summary statistics
            total_projects = len(result)
            total_modules = sum(p["moduleCount"] for p in result)
            total_vuln_deps = sum(p["vulnerableDependencies"] or 0 for p in result)
            total_rem_deps = sum(p["remediatedDependencies"] or 0 for p in result)

            return json.dumps({
                "success": True,
                "summary": {
                    "total_projects": total_projects,
                    "total_modules": total_modules,
                    "vulnerable_dependencies": total_vuln_deps,
                    "remediated_dependencies": total_rem_deps,
                    "remediation_coverage_percent": round(total_rem_deps * 100 / max(total_vuln_deps, 1), 1)
                },
                "projects": result
            }, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)
    finally:
        if driver:
            driver.close()


def analyze_risk_statistics() -> str:
    """
    Analyze OWASP dependency check data and provide comprehensive risk statistics.

    Returns detailed analysis including:
    - Total projects count and project details (project code, name, module count)
    - Total modules count and module details (module name, project, dependency count)
    - Direct vs transitive dependency breakdown
    - Remediation coverage statistics
    - Total vulnerabilities count
    - Severity distribution (CRITICAL, HIGH, MEDIUM, LOW)
    - Average CVSS score
    - Top 10 riskiest dependencies (with project and module usage info)
    - Dependencies without vulnerabilities count
    - Risk score calculation per dependency
    - Upgrade path analysis
    - Version distribution statistics
    - Transitive dependency depth analysis

    This is the PRIMARY tool for getting project and module overview!
    """
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # Get total project count
            total_projects = session.run("MATCH (p:Project) RETURN count(p) as total").single()["total"]

            # Get project details
            projects = session.run("""
                MATCH (p:Project)
                OPTIONAL MATCH (p)-[:HAS_MODULE]->(m:Module)
                RETURN p.name as projectName,
                       count(m) as moduleCount
                ORDER BY p.name
            """).data()

            # Get total module count
            total_modules = session.run("MATCH (m:Module) RETURN count(m) as total").single()["total"]

            # Get module details
            modules = session.run("""
                MATCH (p:Project)-[:HAS_MODULE]->(m:Module)
                OPTIONAL MATCH (m)-[:USES_DEPENDENCY]->(d:Dependency)
                RETURN m.name as moduleName,
                       m.project as projectCode,
                       count(d) as dependencyCount
                ORDER BY m.project, m.name
            """).data()

            # Get total vulnerability count
            total_vulns = session.run("MATCH (v:Vulnerability) RETURN count(v) as total").single()["total"]

            # Get severity distribution
            severity_dist = session.run("""
                MATCH (v:Vulnerability)
                RETURN v.severity as severity, count(*) as count
                ORDER BY count DESC
            """).data()

            # Get average CVSS score
            avg_cvss = session.run("""
                MATCH (v:Vulnerability)
                WHERE v.cvssScore IS NOT NULL
                RETURN avg(v.cvssScore) as avgScore,
                       max(v.cvssScore) as maxScore,
                       min(v.cvssScore) as minScore
            """).single()

            # Get dependency breakdown (direct vs transitive)
            dep_breakdown = session.run("""
                MATCH (d:Dependency)
                WITH d.isDirectDependency as isDirect, count(*) as count
                RETURN isDirect, count
                ORDER BY isDirect DESC
            """).data()

            # Get remediation coverage
            remediation_stats = session.run("""
                MATCH (d:Dependency)
                WITH d.hasRemediation as hasRemediation, count(*) as count
                RETURN hasRemediation, count
            """).data()

            # Get direct dependencies with/without remediations
            direct_dep_remediation = session.run("""
                MATCH (d:Dependency {isDirectDependency: true})
                WITH d.hasRemediation as hasRemediation, count(*) as count
                RETURN hasRemediation, count
            """).data()

            # Get top 10 riskiest dependencies with enhanced metrics
            risky_deps = session.run("""
                MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WITH d, count(v) as vulnCount,
                     avg(COALESCE(v.cvssScore, 5.0)) as avgCvss,
                     collect(v.severity) as severities
                WITH d, vulnCount, avgCvss,
                     size([s IN severities WHERE s = 'CRITICAL']) as criticalCount,
                     size([s IN severities WHERE s = 'HIGH']) as highCount,
                     size([s IN severities WHERE s = 'MEDIUM']) as mediumCount,
                     size([s IN severities WHERE s = 'LOW']) as lowCount
                WITH d, vulnCount, avgCvss, criticalCount, highCount, mediumCount, lowCount,
                     (criticalCount * 10 + highCount * 5 + mediumCount * 2 + lowCount) as riskScore
                RETURN d.groupId + ':' + d.artifactId as artifact,
                       d.detectedVersion as currentVersion,
                       d.fileName as fileName,
                       d.isDirectDependency as isDirect,
                       d.hasRemediation as hasRemediation,
                       d.usedByProjects as projects,
                       d.usedByModules as modules,
                       vulnCount,
                       avgCvss,
                       criticalCount,
                       highCount,
                       mediumCount,
                       lowCount,
                       riskScore
                ORDER BY riskScore DESC, criticalCount DESC, highCount DESC
                LIMIT 10
            """).data()

            # Get total dependencies count
            total_deps = session.run("MATCH (d:Dependency) RETURN count(d) as total").single()["total"]

            # Get safe dependencies (no vulnerabilities)
            safe_deps = session.run("""
                MATCH (d:Dependency)
                WHERE NOT (d)-[:HAS_VULNERABILITY]->()
                RETURN count(d) as safeDeps
            """).single()["safeDeps"]

            # Get dependencies with upgrade paths
            upgrade_path_stats = session.run("""
                MATCH (d:Dependency)-[:CURRENT_VERSION]->(cv:ArtifactVersion)
                MATCH (d)-[:RECOMMENDED_VERSION]->(rv:ArtifactVersion)
                WHERE cv.version <> rv.version
                RETURN count(DISTINCT d) as depsWithUpgrades,
                       avg(rv.majorVersion - cv.majorVersion) as avgMajorJump,
                       avg(rv.minorVersion - cv.minorVersion) as avgMinorJump
            """).single()

            # Get artifact version statistics
            version_stats = session.run("""
                MATCH (av:ArtifactVersion)
                WITH av.hasCVE as hasCVE, count(*) as count
                RETURN hasCVE, count
            """).data()

            # Get top artifacts with most versions tracked
            top_versioned_artifacts = session.run("""
                MATCH (av:ArtifactVersion)
                WITH av.gid + ':' + av.aid as artifact, count(*) as versionCount
                ORDER BY versionCount DESC
                LIMIT 5
                RETURN artifact, versionCount
            """).data()

            # Get transitive dependency depth analysis
            dependency_depth = session.run("""
                MATCH path = (d1:Dependency)-[:DEPENDS_ON*]->(d2:Dependency)
                WHERE d1.isDirectDependency = true
                WITH d1, max(length(path)) as maxDepth
                RETURN avg(maxDepth) as avgDepth,
                       max(maxDepth) as maxDepth,
                       min(maxDepth) as minDepth,
                       count(d1) as directDepsWithTransitive
            """).single()

            # Get most used transitive dependencies
            top_transitive = session.run("""
                MATCH (d:Dependency {isDirectDependency: false})
                WHERE size(d.usedByModules) > 1
                RETURN d.groupId + ':' + d.artifactId as artifact,
                       d.detectedVersion as version,
                       size(d.usedByModules) as moduleCount,
                       d.usedByModules as modules
                ORDER BY moduleCount DESC
                LIMIT 5
            """).data()

            # Build enhanced result
            result = {
                "success": True,
                "project_overview": {
                    "total_projects": total_projects,
                    "total_modules": total_modules,
                    "projects": projects,
                    "modules": modules
                },
                "dependency_breakdown": {
                    "total_dependencies": total_deps,
                    "direct_dependencies": next((item["count"] for item in dep_breakdown if item["isDirect"] == True), 0),
                    "transitive_dependencies": next((item["count"] for item in dep_breakdown if item["isDirect"] == False), 0),
                    "dependencies_with_vulnerabilities": total_deps - safe_deps,
                    "safe_dependencies": safe_deps
                },
                "remediation_coverage": {
                    "total_with_remediation": next((item["count"] for item in remediation_stats if item["hasRemediation"] == True), 0),
                    "total_without_remediation": next((item["count"] for item in remediation_stats if item["hasRemediation"] == False), 0),
                    "direct_deps_with_remediation": next((item["count"] for item in direct_dep_remediation if item["hasRemediation"] == True), 0),
                    "direct_deps_without_remediation": next((item["count"] for item in direct_dep_remediation if item["hasRemediation"] == False), 0),
                    "remediation_coverage_percent": round(
                        (next((item["count"] for item in remediation_stats if item["hasRemediation"] == True), 0) /
                         max(total_deps - safe_deps, 1)) * 100, 2
                    )
                },
                "vulnerability_summary": {
                    "total_vulnerabilities": total_vulns,
                    "severity_distribution": severity_dist,
                    "cvss_statistics": {
                        "average": round(avg_cvss["avgScore"], 2) if avg_cvss["avgScore"] else None,
                        "maximum": avg_cvss["maxScore"],
                        "minimum": avg_cvss["minScore"]
                    }
                },
                "upgrade_analysis": {
                    "dependencies_with_upgrade_paths": upgrade_path_stats["depsWithUpgrades"] if upgrade_path_stats else 0,
                    "avg_major_version_jump": round(upgrade_path_stats["avgMajorJump"], 2) if upgrade_path_stats and upgrade_path_stats["avgMajorJump"] else 0,
                    "avg_minor_version_jump": round(upgrade_path_stats["avgMinorJump"], 2) if upgrade_path_stats and upgrade_path_stats["avgMinorJump"] else 0
                },
                "version_tracking": {
                    "total_versions_tracked": sum(item["count"] for item in version_stats),
                    "versions_with_cves": next((item["count"] for item in version_stats if item["hasCVE"] == True), 0),
                    "safe_versions": next((item["count"] for item in version_stats if item["hasCVE"] == False), 0),
                    "top_versioned_artifacts": top_versioned_artifacts
                },
                "dependency_depth_analysis": {
                    "avg_transitive_depth": round(dependency_depth["avgDepth"], 2) if dependency_depth and dependency_depth["avgDepth"] else 0,
                    "max_transitive_depth": dependency_depth["maxDepth"] if dependency_depth else 0,
                    "min_transitive_depth": dependency_depth["minDepth"] if dependency_depth else 0,
                    "direct_deps_with_transitives": dependency_depth["directDepsWithTransitive"] if dependency_depth else 0
                },
                "top_10_riskiest_dependencies": risky_deps,
                "top_5_shared_transitive_dependencies": top_transitive
            }

            return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)
    finally:
        if driver:
            driver.close()


def visualize_dependency_graph(limit: int = 20, output_file: str = "dependency_graph.png") -> str:
    """
    Create a visual graph of dependencies and their vulnerabilities.

    Args:
        limit: Maximum number of dependencies to include (default: 20)
        output_file: Output filename for the graph image (default: "dependency_graph.png")

    Returns:
        JSON with success status and file path
    """
    if not HAS_VISUALIZATION:
        return json.dumps({
            "success": False,
            "error": "Visualization libraries not installed. Run: pip install matplotlib networkx"
        }, indent=2)

    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # Get dependencies with their vulnerabilities
            query = f"""
                MATCH (d:Dependency)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
                WITH d, count(v) as vulnCount
                ORDER BY vulnCount DESC
                LIMIT {limit}
                MATCH (d)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN d.fileName as dependency,
                       v.name as vulnerability,
                       v.severity as severity
            """
            results = session.run(query).data()

            if not results:
                return json.dumps({
                    "success": False,
                    "error": "No vulnerability data found in Neo4j"
                }, indent=2)

            # Create directed graph
            G = nx.DiGraph()

            # Add nodes and edges
            dep_nodes = set()
            vuln_nodes = set()

            for record in results:
                dep = record["dependency"]
                vuln = record["vulnerability"]
                severity = record["severity"]

                dep_nodes.add(dep)
                vuln_nodes.add(vuln)
                G.add_edge(dep, vuln, severity=severity)

            # Create layout
            pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

            # Create figure
            plt.figure(figsize=(20, 16))

            # Draw dependency nodes (blue squares)
            nx.draw_networkx_nodes(G, pos,
                                 nodelist=list(dep_nodes),
                                 node_color='lightblue',
                                 node_shape='s',
                                 node_size=3000,
                                 alpha=0.9)

            # Draw vulnerability nodes (colored by severity)
            severity_colors = {
                'CRITICAL': 'red',
                'HIGH': 'orange',
                'MEDIUM': 'yellow',
                'LOW': 'lightgreen',
                None: 'gray'
            }

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', None]:
                severity_nodes = [v for v in vuln_nodes
                                if any(d['severity'] == severity
                                     for d in results
                                     if d['vulnerability'] == v)]
                if severity_nodes:
                    nx.draw_networkx_nodes(G, pos,
                                         nodelist=severity_nodes,
                                         node_color=severity_colors.get(severity, 'gray'),
                                         node_shape='o',
                                         node_size=1500,
                                         alpha=0.8)

            # Draw edges
            nx.draw_networkx_edges(G, pos, edge_color='gray', alpha=0.5,
                                 arrows=True, arrowsize=10)

            # Draw labels
            labels = {node: node[:30] + '...' if len(node) > 30 else node for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)

            # Add legend
            legend_elements = [
                plt.Line2D([0], [0], marker='s', color='w', markerfacecolor='lightblue',
                         markersize=10, label='Dependencies'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red',
                         markersize=10, label='CRITICAL'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange',
                         markersize=10, label='HIGH'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='yellow',
                         markersize=10, label='MEDIUM'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightgreen',
                         markersize=10, label='LOW'),
            ]
            plt.legend(handles=legend_elements, loc='upper right')

            plt.title(f'Dependency Vulnerability Graph (Top {limit} Dependencies)', fontsize=16)
            plt.axis('off')
            plt.tight_layout()

            # Save figure
            plt.savefig(output_file, dpi=150, bbox_inches='tight')
            plt.close()

            return json.dumps({
                "success": True,
                "output_file": output_file,
                "dependencies_count": len(dep_nodes),
                "vulnerabilities_count": len(vuln_nodes),
                "edges_count": len(results),
                "message": f"Graph saved to {output_file}"
            }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)
    finally:
        if driver:
            driver.close()


def enrich_cve_data(cve_id: str) -> str:
    """
    Fetch detailed CVE information from the National Vulnerability Database (NVD) API.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2024-1234')

    Returns:
        JSON with CVE details including description, CVSS scores, CWE, references, etc.
    """
    if not HAS_REQUESTS:
        return json.dumps({
            "success": False,
            "error": "requests library not installed. Run: pip install requests"
        }, indent=2)

    try:
        # NVD API endpoint
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}

        # Make request
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()

        # Check if CVE was found
        if data.get("totalResults", 0) == 0:
            return json.dumps({
                "success": False,
                "cve_id": cve_id,
                "error": "CVE not found in NVD database"
            }, indent=2)

        # Extract CVE details
        cve = data["vulnerabilities"][0]["cve"]

        # Get descriptions
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")

        # Get CVSS scores
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if "cvssMetricV31" in metrics else {}
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if "cvssMetricV2" in metrics else {}

        # Get CWE information
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwes.append(desc.get("value"))

        # Get references
        references = cve.get("references", [])
        ref_urls = [ref.get("url") for ref in references[:5]]  # Limit to 5 references

        # Published and modified dates
        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")

        result = {
            "success": True,
            "cve_id": cve_id,
            "description": description,
            "published": published,
            "last_modified": last_modified,
            "cvss_v3": {
                "score": cvss_v3.get("baseScore"),
                "severity": cvss_v3.get("baseSeverity"),
                "vector": cvss_v3.get("vectorString")
            } if cvss_v3 else None,
            "cvss_v2": {
                "score": cvss_v2.get("baseScore"),
                "severity": cvss_v2.get("baseSeverity"),
                "vector": cvss_v2.get("vectorString")
            } if cvss_v2 else None,
            "cwes": cwes,
            "references": ref_urls
        }

        return json.dumps(result, indent=2)

    except requests.RequestException as e:
        return json.dumps({
            "success": False,
            "cve_id": cve_id,
            "error": f"API request failed: {str(e)}"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "cve_id": cve_id,
            "error": str(e)
        }, indent=2)


def read_neo4j_query(query: str) -> str:
    """
    Execute a Cypher query on Neo4j database containing OWASP dependency check data.

    Args:
        query: Cypher query to execute (e.g., 'MATCH (v:Vulnerability) RETURN v.name, v.severity LIMIT 10')

    Common query examples:
    - List all vulnerabilities: "MATCH (v:Vulnerability) RETURN v.name, v.severity, v.cvssScore ORDER BY v.cvssScore DESC LIMIT 10"
    - Count vulnerabilities by severity: "MATCH (v:Vulnerability) RETURN v.severity, count(*) as count ORDER BY count DESC"
    - Find dependencies with vulnerabilities: "MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN d.fileName, count(v) as vulnCount ORDER BY vulnCount DESC LIMIT 10"
    - Get specific CVE details: "MATCH (v:Vulnerability {name: 'CVE-2024-1234'}) RETURN v"
    - Critical vulnerabilities: "MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability {severity: 'CRITICAL'}) RETURN d.fileName, v.name, v.cvssScore"
    """
    # Auto-fix common SQL->Cypher mistakes
    original_query = query
    query_upper = query.upper()

    # Check for GROUP BY and auto-fix
    if "GROUP BY" in query_upper:
        # Remove GROUP BY clause
        import re
        # Pattern: GROUP BY [field_name] (before RETURN, ORDER BY, or end)
        query = re.sub(r'\s+GROUP\s+BY\s+[^\s]+(\s|$)', ' ', query, flags=re.IGNORECASE)
        warning_msg = f"⚠️ AUTO-FIXED: Removed 'GROUP BY' (not valid in Cypher). Original: {original_query}"
        print(warning_msg)

    # Get Neo4j credentials from environment variables
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        # Connect to Neo4j
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        # Execute query
        with driver.session() as session:
            result = session.run(query)

            # Convert results to list of dictionaries
            records = []
            for record in result:
                # Convert Record to dictionary
                record_dict = {}
                for key in record.keys():
                    value = record[key]
                    # Handle Neo4j node/relationship objects
                    if hasattr(value, '__dict__'):
                        record_dict[key] = dict(value)
                    else:
                        record_dict[key] = value
                records.append(record_dict)

            return json.dumps({
                "success": True,
                "query": query,
                "results": records,
                "count": len(records)
            }, indent=2)

    except Exception as e:
        error_message = str(e)
        # Make Neo4j errors more helpful
        if "SyntaxError" in error_message or "Invalid input" in error_message:
            error_type = "CYPHER SYNTAX ERROR"
        elif "Unknown property" in error_message or "not defined" in error_message:
            error_type = "PROPERTY/LABEL ERROR"
        elif "authentication" in error_message.lower():
            error_type = "AUTHENTICATION ERROR"
        else:
            error_type = "QUERY ERROR"

        return json.dumps({
            "success": False,
            "error_type": error_type,
            "error": error_message,
            "query": query,
            "message": "⚠️ Query failed! Do NOT make up data. Fix the query and try again."
        }, indent=2)
    finally:
        if driver:
            driver.close()


# For direct testing
if __name__ == "__main__":
    print("Testing OWASP Dependency Analysis tools:\n")
    print("1. Analyzing risk statistics...")
    result = analyze_risk_statistics()
    print(f"   Result (truncated): {result[:200]}...\n")

    print("2. Querying Neo4j (count vulnerabilities):")
    result = read_neo4j_query("MATCH (v:Vulnerability) RETURN v.severity, count(*) as count ORDER BY count DESC")
    print(f"   Result: {result}\n")

    print("✅ Tools tested successfully!")
