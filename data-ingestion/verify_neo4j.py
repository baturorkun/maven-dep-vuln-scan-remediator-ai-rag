import os
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

def verify():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            # Node counts
            result = session.run("MATCH (n) RETURN labels(n) as Label, count(n) as Count")
            print("Verification Results:")
            for record in result:
                print(f"{record['Label']}: {record['Count']}")

            # Relationship counts
            rel_result = session.run("MATCH ()-[r]->() RETURN type(r) as Type, count(r) as Count")
            print("\nRelationships:")
            for record in rel_result:
                print(f"{record['Type']}: {record['Count']}")

            # Dependency property statistics
            dep_stats = session.run("""
                MATCH (m:Module)-[r:USES_DEPENDENCY]->(d:Dependency)
                RETURN
                    count(CASE WHEN r.isDirectDependency = true THEN 1 END) as direct,
                    count(CASE WHEN r.isDirectDependency = false THEN 1 END) as transitive,
                    count(CASE WHEN d.isPhantomDependency = true THEN 1 END) as phantom,
                    count(CASE WHEN d.isPhantomDependency = false THEN 1 END) as normal,
                    count(r) as total
            """).single()

            print("\nDependency Statistics:")
            print(f"  Direct: {dep_stats['direct']}")
            print(f"  Transitive: {dep_stats['transitive']}")
            print(f"  Phantom (BOM/Starter): {dep_stats['phantom']}")
            print(f"  Normal (JAR): {dep_stats['normal']}")
            print(f"  Total: {dep_stats['total']}")

            # Vulnerability statistics
            vuln_stats = session.run("""
                MATCH (d:Dependency)
                OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WITH d, count(v) as vuln_count
                RETURN
                    count(CASE WHEN vuln_count > 0 THEN 1 END) as vulnerable,
                    count(CASE WHEN vuln_count = 0 THEN 1 END) as safe,
                    sum(vuln_count) as total_vulnerabilities
            """).single()

            print("\nVulnerability Statistics:")
            print(f"  Vulnerable Dependencies: {vuln_stats['vulnerable']}")
            print(f"  Safe Dependencies: {vuln_stats['safe']}")
            print(f"  Total Vulnerabilities: {vuln_stats['total_vulnerabilities']}")

    finally:
        driver.close()

if __name__ == "__main__":
    verify()
