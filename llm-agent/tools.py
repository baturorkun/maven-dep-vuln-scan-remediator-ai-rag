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
    matplotlib = None
    plt = None
    nx = None
    HAS_VISUALIZATION = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False


def read_neo4j_query(cypher_query: str) -> str:
    """
    Execute a raw Cypher query against Neo4j and return results.

    Use this tool when:
    - You need to run a custom Cypher query
    - Other tools don't provide the specific data you need
    - The user asks for specific graph queries

    Args:
        cypher_query: A valid Cypher query string

    Returns:
        JSON with query results or error message
    """
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            result = session.run(cypher_query)
            records = result.data()

            return json.dumps({
                "success": True,
                "query": cypher_query,
                "result_count": len(records),
                "results": records
            }, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "success": False,
            "query": cypher_query,
            "error": str(e)
        }, indent=2)
    finally:
        if driver:
            driver.close()


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
            # Step 1: per-module aggregation to avoid grouping mistakes in a single complex Cypher
            per_module_rows = session.run("""
                MATCH (p:Project)-[:HAS_MODULE]->(m:Module)
                OPTIONAL MATCH (m)-[:USES_DEPENDENCY]->(d:Dependency)
                OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WITH p, m, count(DISTINCT d) as depCount,
                     count(DISTINCT CASE WHEN v IS NOT NULL THEN d END) as vulnDepCount,
                     count(DISTINCT CASE WHEN v IS NOT NULL AND d.hasRemediation = true THEN d END) as remDepCount
                RETURN p.name as projectName, p.updated as lastUpdated, m.name as moduleName, m.id as moduleId, depCount, vulnDepCount, remDepCount
                ORDER BY p.name, m.name
            """).data()

            # Aggregate per-project in Python for reliability
            projects_map = {}
            for row in per_module_rows:
                pname = row['projectName']
                if pname not in projects_map:
                    projects_map[pname] = {
                        'projectName': pname,
                        'lastUpdated': row.get('lastUpdated'),
                        'modules': [],
                        'totalDependencies': 0,
                        'vulnerableDependencies': 0,
                        'remediatedDependencies': 0
                    }

                projects_map[pname]['modules'].append({
                    'name': row.get('moduleName'),
                    'id': row.get('moduleId'),
                    'dependencyCount': row.get('depCount', 0),
                    'vulnerableDependencies': row.get('vulnDepCount', 0),
                    'remediatedDependencies': row.get('remDepCount', 0)
                })

                projects_map[pname]['totalDependencies'] += row.get('depCount') or 0
                projects_map[pname]['vulnerableDependencies'] += row.get('vulnDepCount') or 0
                projects_map[pname]['remediatedDependencies'] += row.get('remDepCount') or 0

            # Build resulting list and sort by vulnerable deps desc
            result = []
            for pname, pdata in projects_map.items():
                result.append({
                    'projectName': pdata['projectName'],
                    'lastUpdated': pdata['lastUpdated'],
                    'moduleCount': len(pdata['modules']),
                    'totalDependencies': pdata['totalDependencies'],
                    'vulnerableDependencies': pdata['vulnerableDependencies'],
                    'remediatedDependencies': pdata['remediatedDependencies'],
                    'modules': pdata['modules']
                })

            # Sort
            result = sorted(result, key=lambda x: x.get('vulnerableDependencies', 0), reverse=True)

            # Compute summary statistics
            total_projects = len(result)
            total_modules = sum(p['moduleCount'] for p in result)
            total_vuln_deps = sum(p['vulnerableDependencies'] or 0 for p in result)
            total_rem_deps = sum(p['remediatedDependencies'] or 0 for p in result)

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


def diagnose_graph_relationships() -> str:
    """
    Diagnose the graph database to check relationship counts and data integrity.

    Use this tool when:
    - The user asks "why can't I see the dependency tree?"
    - Dependency tree queries return empty results
    - You need to understand the database structure
    - Before attempting complex tree queries

    Returns:
        JSON with diagnostic information about all node types and relationships
    """
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            diagnostics = {
                "success": True,
                "node_counts": {},
                "relationship_counts": {},
                "dependency_analysis": {},
                "recommendations": []
            }

            # Node counts
            for label in ["Project", "Module", "Dependency", "Vulnerability", "ArtifactVersion"]:
                count = session.run(f"MATCH (n:{label}) RETURN count(n) as cnt").single()["cnt"]
                diagnostics["node_counts"][label] = count

            # Relationship counts
            rel_types = ["HAS_MODULE", "USES_DEPENDENCY", "HAS_VULNERABILITY", "DEPENDS_ON",
                         "CURRENT_VERSION", "RECOMMENDED_VERSION", "AVAILABLE_VERSION", "UPGRADES_TO"]
            for rel in rel_types:
                count = session.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) as cnt").single()["cnt"]
                diagnostics["relationship_counts"][rel] = count

            # Dependency analysis
            direct_deps = session.run("""
                MATCH (d:Dependency) WHERE d.isDirectDependency = true RETURN count(d) as cnt
            """).single()["cnt"]

            transitive_deps = session.run("""
                MATCH (d:Dependency) WHERE d.isDirectDependency = false RETURN count(d) as cnt
            """).single()["cnt"]

            deps_with_vuln = session.run("""
                MATCH (d:Dependency)-[:HAS_VULNERABILITY]->() RETURN count(DISTINCT d) as cnt
            """).single()["cnt"]

            diagnostics["dependency_analysis"] = {
                "direct_dependencies": direct_deps,
                "transitive_dependencies": transitive_deps,
                "dependencies_with_vulnerabilities": deps_with_vuln
            }

            # Generate recommendations
            if diagnostics["relationship_counts"]["DEPENDS_ON"] == 0:
                diagnostics["recommendations"].append(
                    "CRITICAL: No DEPENDS_ON relationships found! Transitive dependency tree cannot be built. "
                    "Re-run import with GraphML files (dependency-graph.graphml) to populate transitive relationships."
                )

            if diagnostics["node_counts"]["Dependency"] == 0:
                diagnostics["recommendations"].append(
                    "No Dependency nodes found. The database may be empty. Run the import process first."
                )

            if transitive_deps > 0 and diagnostics["relationship_counts"]["DEPENDS_ON"] == 0:
                diagnostics["recommendations"].append(
                    "Transitive dependencies exist but no DEPENDS_ON edges. "
                    "The dependency tree structure is incomplete. GraphML import may have failed."
                )

            # Sample data for debugging
            if diagnostics["node_counts"]["Dependency"] > 0:
                sample_deps = session.run("""
                    MATCH (d:Dependency)
                    RETURN d.groupId + ':' + d.artifactId as artifact,
                           d.isDirectDependency as isDirect,
                           d.detectedVersion as version
                    LIMIT 5
                """).data()
                diagnostics["sample_dependencies"] = sample_deps

            if diagnostics["relationship_counts"]["DEPENDS_ON"] > 0:
                sample_edges = session.run("""
                    MATCH (a:Dependency)-[:DEPENDS_ON]->(b:Dependency)
                    RETURN a.groupId + ':' + a.artifactId as from_artifact,
                           b.groupId + ':' + b.artifactId as to_artifact
                    LIMIT 5
                """).data()
                diagnostics["sample_depends_on_edges"] = sample_edges

            return json.dumps(diagnostics, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)
    finally:
        if driver:
            driver.close()


def get_dependency_tree(artifact_name: str = None, max_depth: int = 5, direction: str = "forward") -> str:
    """
    Get the dependency tree for a project, module, or specific artifact.

    This is the PRIMARY tool for understanding dependency hierarchies and transitive relationships.

    Use this tool when the user asks:
    - "Show me the dependency tree for myproject" (project-level)
    - "Show me the dependency tree of jackson-databind" (artifact-level)
    - "What are the transitive dependencies of log4j?"
    - "Which libraries depend on log4j?" (use direction="reverse")
    - "Show all dependency chains"
    - "What is the dependency hierarchy?"

    Args:
        artifact_name: Project name, module name, or artifact pattern to filter.
                       Examples: "myproject", "module1", "jackson-databind", "log4j", "spring"
                       If None, returns tree for all projects.
        max_depth: Maximum depth of transitive chain to follow (1-10, default: 5)
        direction: "forward" = what does X depend on, "reverse" = what depends on X

    Returns:
        JSON with dependency tree structure
    """
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    max_depth = max(1, min(10, max_depth))

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # First, determine what the user is asking for: Project, Module, or Artifact?
            search_type = None

            if artifact_name:
                # Check if it's a Project name
                project_check = session.run("""
                    MATCH (p:Project) WHERE p.name CONTAINS $name RETURN p.name as name LIMIT 1
                """, name=artifact_name).single()

                if project_check:
                    search_type = "project"
                else:
                    # Check if it's a Module name
                    module_check = session.run("""
                        MATCH (m:Module) WHERE m.name CONTAINS $name OR m.id CONTAINS $name 
                        RETURN m.id as id LIMIT 1
                    """, name=artifact_name).single()

                    if module_check:
                        search_type = "module"
                    else:
                        search_type = "artifact"

            # Check DEPENDS_ON relationships
            depends_on_count = session.run("""
                MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS cnt
            """).single()["cnt"]

            result_data = {
                "success": True,
                "search_term": artifact_name or "all",
                "search_type": search_type or "all_projects",
                "direction": direction,
                "max_depth": max_depth,
                "total_depends_on_relationships": depends_on_count,
                "trees": []
            }

            # PROJECT-LEVEL TREE: Show all modules and their dependencies
            if search_type == "project" or (artifact_name is None) or (search_type is None and artifact_name):
                if search_type == "project":
                    query = """
                        MATCH (p:Project)-[:HAS_MODULE]->(m:Module)
                        WHERE p.name CONTAINS $name
                        WITH p, m
                        MATCH (m)-[:USES_DEPENDENCY]->(d:Dependency)
                        WITH p.name as project, m.name as module, d
                        ORDER BY d.isDirectDependency DESC, d.artifactId
                        WITH project, module, collect({
                            artifact: d.groupId + ':' + d.artifactId,
                            version: d.detectedVersion,
                            isDirect: d.isDirectDependency,
                            hasVulnerabilities: EXISTS((d)-[:HAS_VULNERABILITY]->())
                        }) as dependencies
                        RETURN project, module, 
                               size([dep IN dependencies WHERE dep.isDirect = true]) as directCount,
                               size([dep IN dependencies WHERE dep.isDirect = false]) as transitiveCount,
                               size([dep IN dependencies WHERE dep.hasVulnerabilities]) as vulnerableCount,
                               dependencies[0..30] as dependencies
                        ORDER BY module
                    """
                    records = session.run(query, name=artifact_name).data()

                    if records:
                        result_data["trees"] = records
                        result_data["summary"] = {
                            "project": artifact_name,
                            "total_modules": len(records),
                            "total_direct_deps": sum(r.get("directCount", 0) for r in records),
                            "total_transitive_deps": sum(r.get("transitiveCount", 0) for r in records),
                            "total_vulnerable": sum(r.get("vulnerableCount", 0) for r in records)
                        }
                    else:
                        # Project exists but no data - try broader query
                        result_data["warning"] = f"Project '{artifact_name}' found but no dependency data. Showing all projects."
                        search_type = "all_projects"

            # MODULE-LEVEL TREE
            if search_type == "module":
                query = """
                    MATCH (m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
                    WHERE m.name CONTAINS $name OR m.id CONTAINS $name
                    WITH m, d
                    ORDER BY d.isDirectDependency DESC, d.artifactId
                    OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    WITH m.name as module, m.id as moduleId, d, collect(v.name)[0..3] as cves
                    WITH module, moduleId, collect({
                        artifact: d.groupId + ':' + d.artifactId,
                        version: d.detectedVersion,
                        isDirect: d.isDirectDependency,
                        cves: cves
                    }) as dependencies
                    RETURN module, moduleId,
                           size([dep IN dependencies WHERE dep.isDirect = true]) as directCount,
                           size(dependencies) as totalCount,
                           dependencies
                """
                records = session.run(query, name=artifact_name).data()
                result_data["trees"] = records

            # ARTIFACT-LEVEL TREE (with DEPENDS_ON)
            if search_type == "artifact" and depends_on_count > 0:
                if direction == "reverse":
                    # What depends on this artifact?
                    query = f"""
                        MATCH (target:Dependency)
                        WHERE target.artifactId CONTAINS $name OR target.groupId CONTAINS $name
                        WITH target
                        OPTIONAL MATCH path = (parent:Dependency)-[:DEPENDS_ON*1..{max_depth}]->(target)
                        WITH target, parent, length(path) AS depth,
                             [n IN nodes(path) | n.groupId + ':' + n.artifactId] AS chain
                        WHERE parent IS NOT NULL
                        WITH target, collect(DISTINCT {{
                            parent: parent.groupId + ':' + parent.artifactId,
                            version: parent.detectedVersion,
                            isDirect: parent.isDirectDependency,
                            depth: depth
                        }})[0..20] AS dependents
                        RETURN target.groupId + ':' + target.artifactId AS artifact,
                               target.detectedVersion AS version,
                               size(dependents) AS dependentCount,
                               dependents
                        ORDER BY dependentCount DESC
                    """
                else:
                    # What does this artifact depend on?
                    query = f"""
                        MATCH (root:Dependency)
                        WHERE root.artifactId CONTAINS $name OR root.groupId CONTAINS $name
                        WITH root
                        OPTIONAL MATCH path = (root)-[:DEPENDS_ON*1..{max_depth}]->(child:Dependency)
                        OPTIONAL MATCH (child)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                        WITH root, child, length(path) AS depth,
                             [n IN nodes(path) | n.groupId + ':' + n.artifactId + ':' + COALESCE(n.detectedVersion, '?')] AS chain,
                             collect(DISTINCT v.name) AS cves
                        WHERE child IS NOT NULL
                        WITH root, collect(DISTINCT {{
                            dependency: child.groupId + ':' + child.artifactId,
                            version: child.detectedVersion,
                            depth: depth,
                            chain: chain,
                            cveCount: size(cves)
                        }})[0..30] AS transitives
                        RETURN root.groupId + ':' + root.artifactId AS artifact,
                               root.detectedVersion AS version,
                               root.isDirectDependency AS isDirect,
                               size(transitives) AS transitiveCount,
                               transitives
                        ORDER BY transitiveCount DESC
                    """
                records = session.run(query, name=artifact_name).data()
                result_data["trees"] = records

            # FALLBACK: Show all projects if no specific match or no DEPENDS_ON
            if not result_data["trees"] or search_type == "all_projects":
                query = """
                    MATCH (p:Project)-[:HAS_MODULE]->(m:Module)
                    WITH p, m
                    OPTIONAL MATCH (m)-[:USES_DEPENDENCY]->(d:Dependency)
                    WITH p.name as project, m.name as module,
                         count(DISTINCT d) as depCount,
                         count(DISTINCT CASE WHEN d.isDirectDependency = true THEN d END) as directCount,
                         count(DISTINCT CASE WHEN EXISTS((d)-[:HAS_VULNERABILITY]->()) THEN d END) as vulnCount
                    RETURN project, collect({
                        module: module,
                        totalDependencies: depCount,
                        directDependencies: directCount,
                        vulnerableDependencies: vulnCount
                    }) as modules
                    ORDER BY project
                """
                records = session.run(query).data()

                if records:
                    result_data["trees"] = records
                    result_data["info"] = "Showing project/module overview. For artifact-level tree, specify an artifact name like 'jackson-databind' or 'log4j'."

            # Add helpful message if no results
            if not result_data["trees"]:
                result_data["success"] = False
                result_data["error"] = f"No data found for '{artifact_name}'"
                result_data["suggestions"] = [
                    "Use list_projects() to see available projects",
                    "Try searching for a specific artifact like 'log4j' or 'jackson'",
                    "Run diagnose_graph_relationships() to check database status"
                ]

            return json.dumps(result_data, indent=2, default=str)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)
    finally:
        if driver:
            driver.close()
# End of tools.py - no more code after this
