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
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
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
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
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
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
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


def visualize_dependency_graph(limit: int = 20, output_file: str = "dependency_graph.png", artifact_name: str = None) -> str:
    """
    Create a visual graph of dependencies and their vulnerabilities.

    If artifact_name is provided, creates a transitive dependency tree for that specific artifact.
    Otherwise, shows top vulnerable dependencies.

    Args:
        limit: Maximum number of dependencies to include (default: 20)
        output_file: Output filename for the graph image (default: "dependency_graph.png")
        artifact_name: Optional artifact name to show transitive tree (e.g., "jackson-databind")

    Returns:
        JSON with success status and file path

    Examples:
        - visualize_dependency_graph() - Top 20 vulnerable dependencies
        - visualize_dependency_graph(artifact_name="jackson-databind") - jackson-databind's transitive tree
    """
    if not HAS_VISUALIZATION:
        return json.dumps({
            "success": False,
            "error": "Visualization libraries not installed. Run: pip install matplotlib networkx"
        }, indent=2)

    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # Check if artifact_name is provided - create transitive tree
            if artifact_name:
                # Get transitive dependency tree with DEPENDS_ON relationships AND CVE info
                query = f"""
                    MATCH (root:Dependency)
                    WHERE root.artifactId CONTAINS $artifact_name OR root.groupId CONTAINS $artifact_name
                    WITH root LIMIT 1
                    OPTIONAL MATCH path = (root)-[:DEPENDS_ON*1..5]->(child:Dependency)
                    WITH root, path, child
                    OPTIONAL MATCH (child)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    WITH root, 
                         CASE WHEN child IS NULL THEN [root] ELSE nodes(path) END as path_nodes,
                         child,
                         collect(DISTINCT {{name: v.name, severity: v.severity}}) as vulns
                    UNWIND path_nodes as node
                    WITH DISTINCT node, 
                         CASE WHEN node = child THEN vulns ELSE [] END as node_vulns
                    // Get CVE info for each node
                    OPTIONAL MATCH (node)-[:HAS_VULNERABILITY]->(cve:Vulnerability)
                    WITH node,
                         node.groupId + ':' + node.artifactId as artifact,
                         node.detectedVersion as version,
                         collect(DISTINCT cve.name) as cve_list,
                         collect(DISTINCT cve.severity) as severity_list
                    RETURN artifact,
                           version,
                           size(cve_list) as vuln_count,
                           cve_list[0..3] as sample_cves,
                           CASE 
                               WHEN 'CRITICAL' IN severity_list THEN 'CRITICAL'
                               WHEN 'HIGH' IN severity_list THEN 'HIGH'
                               WHEN 'MEDIUM' IN severity_list THEN 'MEDIUM'
                               WHEN 'LOW' IN severity_list THEN 'LOW'
                               ELSE null
                           END as top_severity
                    LIMIT {limit * 2}
                """
                results = session.run(query, artifact_name=artifact_name).data()

                if not results:
                    return json.dumps({
                        "success": False,
                        "error": f"Artifact '{artifact_name}' not found or has no transitive dependencies"
                    }, indent=2)

                # Get edges for transitive tree
                edges_query = f"""
                    MATCH (root:Dependency)
                    WHERE root.artifactId CONTAINS $artifact_name OR root.groupId CONTAINS $artifact_name
                    WITH root LIMIT 1
                    MATCH path = (root)-[:DEPENDS_ON*1..5]->(child:Dependency)
                    WITH relationships(path) as rels
                    UNWIND rels as rel
                    WITH startNode(rel) as source, endNode(rel) as target
                    RETURN DISTINCT 
                           source.groupId + ':' + source.artifactId as source_artifact,
                           target.groupId + ':' + target.artifactId as target_artifact
                    LIMIT {limit * 5}
                """
                edges_results = session.run(edges_query, artifact_name=artifact_name).data()

                # Create directed graph for transitive tree
                G = nx.DiGraph()

                # Add nodes with vulnerability info and CVE data
                node_colors = {}
                node_sizes = {}
                node_cve_info = {}  # Store CVE info for labels

                for record in results:
                    node_name = record['artifact']
                    vuln_count = record['vuln_count']
                    sample_cves = record.get('sample_cves', [])

                    G.add_node(node_name)

                    # Store CVE info for this node
                    node_cve_info[node_name] = {
                        'count': vuln_count,
                        'cves': sample_cves
                    }

                    # Professional color palette for light background
                    if vuln_count > 0:
                        severity = record['top_severity']
                        if severity == 'CRITICAL':
                            node_colors[node_name] = '#DC3545'  # Bootstrap danger red
                        elif severity == 'HIGH':
                            node_colors[node_name] = '#FD7E14'  # Bootstrap orange
                        elif severity == 'MEDIUM':
                            node_colors[node_name] = '#FFC107'  # Bootstrap warning yellow
                        else:
                            node_colors[node_name] = '#28A745'  # Bootstrap success green
                    else:
                        node_colors[node_name] = '#17A2B8'  # Bootstrap info blue

                    # Larger nodes for better visibility
                    node_sizes[node_name] = 4500

                # Add edges
                for edge in edges_results:
                    G.add_edge(edge['source_artifact'], edge['target_artifact'])

                # Use force-directed layout with more spacing
                try:
                    pos = nx.kamada_kawai_layout(G, scale=2.5)
                except:
                    # Fallback to spring layout with more spacing
                    pos = nx.spring_layout(G, k=4, iterations=200, seed=42)

                # Create larger figure with WHITE background
                fig, ax = plt.subplots(figsize=(24, 18), facecolor='white')
                ax.set_facecolor('white')

                # Draw edges - darker gray for better visibility on white
                nx.draw_networkx_edges(
                    G, pos,
                    edge_color='#6C757D',  # Medium gray
                    alpha=0.6,
                    arrows=True,
                    arrowsize=25,
                    arrowstyle='->',
                    width=3,
                    connectionstyle='arc3,rad=0.1',
                    ax=ax
                )

                # Draw nodes - vibrant colors WITHOUT thick borders
                colors = [node_colors.get(node, '#17A2B8') for node in G.nodes()]
                sizes = [node_sizes.get(node, 4500) for node in G.nodes()]

                nx.draw_networkx_nodes(
                    G, pos,
                    node_color=colors,
                    node_size=sizes,
                    alpha=0.9,
                    edgecolors='none',  # No borders for better text readability
                    linewidths=0,
                    ax=ax
                )

                # Draw labels - BLACK text with CVE count
                labels = {}
                for node in G.nodes():
                    # Show only artifactId (last part after :)
                    parts = node.split(':')
                    artifact_name = parts[1] if len(parts) >= 2 else node

                    # Add CVE count to label
                    cve_info = node_cve_info.get(node, {})
                    cve_count = cve_info.get('count', 0)

                    if cve_count > 0:
                        labels[node] = f"{artifact_name}\n({cve_count} CVEs)"
                    else:
                        labels[node] = artifact_name

                nx.draw_networkx_labels(
                    G, pos, labels,
                    font_size=16,  # Large, readable font
                    font_weight='bold',
                    font_color='black',  # Black text on white background
                    font_family='sans-serif',
                    ax=ax
                )

                # Add improved legend with dark text
                legend_elements = [
                    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#DC3545',
                              markersize=15, label='CRITICAL', markeredgewidth=0),
                    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#FD7E14',
                              markersize=15, label='HIGH', markeredgewidth=0),
                    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#FFC107',
                              markersize=15, label='MEDIUM', markeredgewidth=0),
                    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#28A745',
                              markersize=15, label='LOW', markeredgewidth=0),
                    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#17A2B8',
                              markersize=15, label='No Vulnerabilities', markeredgewidth=0),
                    plt.Line2D([0], [0], color='#6C757D', linewidth=3, label='DEPENDS_ON →'),
                ]
                legend = ax.legend(handles=legend_elements, loc='upper left',
                                 frameon=True, facecolor='white', edgecolor='#DEE2E6',
                                 fontsize=14, labelcolor='black', title='Legend',
                                 title_fontsize=16)
                legend.get_title().set_color('black')

                # Title - black text on white background
                ax.set_title(f'Dependency Graph: {artifact_name}',
                           fontsize=24, fontweight='bold', color='black', pad=30)

                ax.axis('off')
                plt.tight_layout()

                plt.savefig(output_file, dpi=200, bbox_inches='tight', facecolor='white')
                plt.close()

                return json.dumps({
                    "success": True,
                    "output_file": output_file,
                    "artifact": artifact_name,
                    "dependencies_count": len(G.nodes()),
                    "relationships_count": len(G.edges()),
                    "message": f"Transitive tree for {artifact_name} saved to {output_file}"
                }, indent=2)

            # Original vulnerability-based graph (when no artifact_name)
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
    Fetch detailed CVE information from OWASP Dependency Check's offline H2 database.

    This function works in air-gapped environments by reading from the local NVD mirror
    that OWASP Dependency Check maintains.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2024-1234')

    Returns:
        JSON with CVE details including description, CVSS scores, CWE, references, etc.
    """
    import jaydebeapi
    import os

    try:
        # Path to H2 database (OWASP Dependency Check's NVD mirror)
        # Try multiple possible locations
        possible_db_paths = [
            "/odc-data/odc",  # Inside container
            "/app/odc-data/odc",  # If mounted
            "../version-scanner-odc/odc-data/odc",  # Relative path
            os.path.expanduser("~/odc-data/odc"),  # User home
        ]

        db_path = None
        for path in possible_db_paths:
            if os.path.exists(f"{path}.mv.db"):
                db_path = path
                break

        if not db_path:
            return json.dumps({
                "success": False,
                "cve_id": cve_id,
                "error": "H2 database not found. Ensure OWASP Dependency Check has been run to populate the NVD database.",
                "hint": "Expected database at: /odc-data/odc.mv.db or ../version-scanner-odc/odc-data/odc.mv.db"
            }, indent=2)

        # Connect to H2 database
        # H2 JDBC driver should be available in the container
        # Try multiple possible jar locations
        import glob

        h2_jar_paths = [
            "/opt/dependency-check/lib/h2-*.jar",  # OWASP DC lib directory
            "/usr/share/java/h2.jar",  # Standard location
            "/root/.m2/repository/com/h2database/h2/*/h2-*.jar",  # Maven cache
        ]

        h2_jar = None
        for pattern in h2_jar_paths:
            matches = glob.glob(pattern)
            if matches:
                h2_jar = matches[0]
                break

        if not h2_jar:
            return json.dumps({
                "success": False,
                "error": "H2 JDBC driver not found. Please ensure OWASP Dependency Check is installed."
            }, indent=2)

        conn = jaydebeapi.connect(
            "org.h2.Driver",
            f"jdbc:h2:{db_path}",
            ["sa", "password"],  # OWASP DC H2 database credentials
            h2_jar
        )

        cursor = conn.cursor()

        # Query vulnerability table for CVE details
        # Note: This H2 database version does not store published/modified dates
        cursor.execute("""
            SELECT 
                CVE,
                DESCRIPTION
            FROM VULNERABILITY 
            WHERE CVE = ?
        """, [cve_id])

        row = cursor.fetchone()

        if not row:
            cursor.close()
            conn.close()
            return json.dumps({
                "success": False,
                "cve_id": cve_id,
                "error": "CVE not found in local H2 database"
            }, indent=2)

        # Extract basic data
        cve, description = row

        # Try to get CVSS scores - column names vary by OWASP DC version
        # We'll try multiple approaches to be compatible
        v3_base_score = None
        v3_severity = None
        v2_base_score = None

        try:
            # Try modern column names (OWASP DC 8.0+)
            cursor.execute("""
                SELECT V3BaseScore, V3BaseSeverity, V2BaseScore
                FROM VULNERABILITY 
                WHERE CVE = ?
            """, [cve_id])
            score_row = cursor.fetchone()
            if score_row:
                v3_base_score, v3_severity, v2_base_score = score_row
        except:
            # If that fails, try older column names
            try:
                cursor.execute("""
                    SELECT CVSSV3_BASE_SCORE, CVSSV3_SEVERITY, CVSSV2_BASE_SCORE
                    FROM VULNERABILITY 
                    WHERE CVE = ?
                """, [cve_id])
                score_row = cursor.fetchone()
                if score_row:
                    v3_base_score, v3_severity, v2_base_score = score_row
            except:
                # Scores not available in this database version
                pass

        # Get CWE information
        cwes = []
        try:
            cursor.execute("""
                SELECT CWE 
                FROM CWE_ENTRY 
                WHERE CVE_ID = (SELECT ID FROM VULNERABILITY WHERE CVE = ?)
            """, [cve_id])
            cwes = [row[0] for row in cursor.fetchall() if row[0]]
        except:
            # CWE_ENTRY table might not exist or have different structure
            pass

        # Get references
        references = []
        try:
            cursor.execute("""
                SELECT NAME, URL, SOURCE 
                FROM REFERENCE 
                WHERE CVE_ID = (SELECT ID FROM VULNERABILITY WHERE CVE = ?)
                LIMIT 10
            """, [cve_id])

            for ref_row in cursor.fetchall():
                if ref_row[1]:  # URL exists
                    references.append({
                        "name": ref_row[0],
                        "url": ref_row[1],
                        "source": ref_row[2]
                    })
        except:
            # REFERENCE table might not exist or have different structure
            pass


        cursor.close()
        conn.close()

        # Query Neo4j to get affected packages for this CVE
        affected_packages = []
        try:
            NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
            NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
            NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

            neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    WHERE v.name = $cve_id
                    OPTIONAL MATCH (m:Module)-[:USES_DEPENDENCY]->(d)
                    OPTIONAL MATCH (p:Project)-[:HAS_MODULE]->(m)
                    RETURN DISTINCT 
                        d.groupId as groupId,
                        d.artifactId as artifactId,
                        d.detectedVersion as version,
                        d.isDirectDependency as isDirect,
                        collect(DISTINCT m.name)[0] as module,
                        collect(DISTINCT p.name)[0] as project
                    ORDER BY d.groupId, d.artifactId
                    LIMIT 20
                """, cve_id=cve_id)

                for record in result:
                    pkg = {
                        "groupId": record["groupId"],
                        "artifactId": record["artifactId"],
                        "version": record["version"],
                        "isDirect": record["isDirect"],
                        "module": record["module"],
                        "project": record["project"]
                    }
                    affected_packages.append(pkg)

            neo4j_driver.close()
        except Exception as neo4j_error:
            # Neo4j query failed, continue without affected packages
            pass

        # Build result - no date columns exist in this H2 database version
        result = {
            "success": True,
            "source": "offline_h2_database",
            "cve_id": cve_id,
            "description": description,
            "cvss_v3": {
                "score": float(v3_base_score) if v3_base_score else None,
                "severity": v3_severity
            } if v3_base_score else None,
            "cvss_v2": {
                "score": float(v2_base_score) if v2_base_score else None
            } if v2_base_score else None,
            "cwes": cwes if cwes else [],
            "references": references[:5] if references else [],  # Limit to 5 references
            "affected_packages": affected_packages,
            "affected_count": len(affected_packages),
            "note": "Date information not available in offline H2 database"
        }

        return json.dumps(result, indent=2, default=str)

    except ImportError:
        return json.dumps({
            "success": False,
            "error": "jaydebeapi library not installed. Run: pip install jaydebeapi"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "cve_id": cve_id,
            "error": f"Database query failed: {str(e)}",
            "type": type(e).__name__
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
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
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
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
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


def get_remediation_suggestions(project_name: str = None) -> str:
    """
    Get remediation version suggestions for dependencies with vulnerabilities.

    Returns upgrade recommendations from Neo4j database:
    - Current version
    - Recommended version (fixes vulnerabilities)
    - Available upgrade versions
    - Vulnerability count

    Args:
        project_name: Optional project name to filter results (default: all projects)

    Returns:
        JSON with remediation suggestions for each vulnerable dependency

    Example response:
    {
      "success": true,
      "project": "java-project",
      "remediation_count": 5,
      "suggestions": [
        {
          "artifact": "org.apache.logging.log4j:log4j-api",
          "current_version": "2.14.1",
          "recommended_version": "2.17.1",
          "vulnerability_count": 12,
          "upgrade_path": ["2.15.0", "2.16.0", "2.17.0", "2.17.1"]
        }
      ]
    }
    """
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.containers.internal:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    driver = None
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # Build query with optional project filter
            if project_name:
                query = """
                    // Get dependencies with remediation recommendations for specific project
                    MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
                    WHERE p.name CONTAINS $project_name AND d.hasRemediation = true
                    
                    // Get current version
                    OPTIONAL MATCH (d)-[:CURRENT_VERSION]->(cv:ArtifactVersion)
                    
                    // Get recommended version
                    OPTIONAL MATCH (d)-[:RECOMMENDED_VERSION]->(rv:ArtifactVersion)
                    
                    // Get upgrade path
                    OPTIONAL MATCH path = (cv)-[:UPGRADES_TO*1..5]->(rv)
                    WITH d, cv, rv, path,
                         [node IN nodes(path) | node.version] as upgrade_versions
                    
                    // Count vulnerabilities
                    OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    WITH d, cv, rv, upgrade_versions,
                         count(DISTINCT v) as vuln_count,
                         collect(DISTINCT v.severity) as severities
                    
                    // Return results
                    RETURN DISTINCT
                        d.groupId + ':' + d.artifactId as artifact,
                        cv.version as current_version,
                        rv.version as recommended_version,
                        vuln_count,
                        CASE 
                            WHEN 'CRITICAL' IN severities THEN 'CRITICAL'
                            WHEN 'HIGH' IN severities THEN 'HIGH'
                            WHEN 'MEDIUM' IN severities THEN 'MEDIUM'
                            WHEN 'LOW' IN severities THEN 'LOW'
                            ELSE 'UNKNOWN'
                        END as highest_severity,
                        upgrade_versions[1..-1] as upgrade_path
                    ORDER BY vuln_count DESC, highest_severity
                """
                params = {"project_name": project_name}
            else:
                query = """
                    // Get dependencies with remediation recommendations for all projects
                    MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
                    WHERE d.hasRemediation = true
                    
                    // Get current version
                    OPTIONAL MATCH (d)-[:CURRENT_VERSION]->(cv:ArtifactVersion)
                    
                    // Get recommended version
                    OPTIONAL MATCH (d)-[:RECOMMENDED_VERSION]->(rv:ArtifactVersion)
                    
                    // Get upgrade path
                    OPTIONAL MATCH path = (cv)-[:UPGRADES_TO*1..5]->(rv)
                    WITH d, cv, rv, path,
                         [node IN nodes(path) | node.version] as upgrade_versions
                    
                    // Count vulnerabilities
                    OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    WITH d, cv, rv, upgrade_versions,
                         count(DISTINCT v) as vuln_count,
                         collect(DISTINCT v.severity) as severities
                    
                    // Return results
                    RETURN DISTINCT
                        d.groupId + ':' + d.artifactId as artifact,
                        cv.version as current_version,
                        rv.version as recommended_version,
                        vuln_count,
                        CASE 
                            WHEN 'CRITICAL' IN severities THEN 'CRITICAL'
                            WHEN 'HIGH' IN severities THEN 'HIGH'
                            WHEN 'MEDIUM' IN severities THEN 'MEDIUM'
                            WHEN 'LOW' IN severities THEN 'LOW'
                            ELSE 'UNKNOWN'
                        END as highest_severity,
                        upgrade_versions[1..-1] as upgrade_path
                    ORDER BY vuln_count DESC, highest_severity
                """
                params = {}

            results = session.run(query, **params).data()

            if not results:
                return json.dumps({
                    "success": True,
                    "project": project_name or "all projects",
                    "remediation_count": 0,
                    "message": "No remediation suggestions found. This could mean:\n" +
                              "  - No dependencies have recommended versions\n" +
                              "  - All dependencies are already up to date\n" +
                              "  - Project name doesn't match",
                    "suggestions": []
                }, indent=2)

            # Format results
            suggestions = []
            for record in results:
                suggestion = {
                    "artifact": record["artifact"],
                    "current_version": record["current_version"],
                    "recommended_version": record["recommended_version"],
                    "vulnerability_count": record["vuln_count"],
                    "highest_severity": record["highest_severity"],
                    "upgrade_path": record["upgrade_path"] or []
                }
                suggestions.append(suggestion)

            return json.dumps({
                "success": True,
                "project": project_name or "all projects",
                "remediation_count": len(suggestions),
                "message": f"Found {len(suggestions)} remediation suggestion(s)",
                "suggestions": suggestions
            }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "message": "Failed to retrieve remediation suggestions from Neo4j"
        }, indent=2)
    finally:
        if driver:
            driver.close()


# End of tools.py - no more code after this
