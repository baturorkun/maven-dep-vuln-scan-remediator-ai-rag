#!/usr/bin/env python3
"""
Neo4j Database Model Test Script
Tests if data is correctly imported and relationships are working.
"""

import json
import sys

def run_tests():
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))

    results = {
        "connection": False,
        "node_counts": {},
        "relationship_counts": {},
        "sample_data": {},
        "transitive_test": {},
        "issues": []
    }

    try:
        driver.verify_connectivity()
        results["connection"] = True
        print("✅ Neo4j bağlantısı başarılı!")
    except Exception as e:
        print(f"❌ Neo4j bağlantı hatası: {e}")
        return results

    with driver.session() as session:
        # 1. Node Counts
        print("\n" + "=" * 60)
        print("1. NODE SAYILARI")
        print("=" * 60)
        for label in ["Project", "Module", "Dependency", "Vulnerability", "ArtifactVersion"]:
            count = session.run(f"MATCH (n:{label}) RETURN count(n) as cnt").single()["cnt"]
            results["node_counts"][label] = count
            status = "✅" if count > 0 else "⚠️"
            print(f"   {status} {label}: {count}")

        # 2. Relationship Counts
        print("\n" + "=" * 60)
        print("2. RELATIONSHIP SAYILARI")
        print("=" * 60)
        for rel in ["HAS_MODULE", "USES_DEPENDENCY", "HAS_VULNERABILITY", "DEPENDS_ON",
                    "CURRENT_VERSION", "RECOMMENDED_VERSION"]:
            count = session.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) as cnt").single()["cnt"]
            results["relationship_counts"][rel] = count
            status = "✅" if count > 0 else "⚠️"
            print(f"   {status} {rel}: {count}")

        # 3. Project -> Module -> Dependency Chain Test
        print("\n" + "=" * 60)
        print("3. PROJECT -> MODULE -> DEPENDENCY ZİNCİRİ")
        print("=" * 60)
        chain_test = session.run("""
            MATCH (p:Project)-[:HAS_MODULE]->(m:Module)-[:USES_DEPENDENCY]->(d:Dependency)
            RETURN p.name as project, m.name as module, count(d) as dep_count
            ORDER BY m.name
        """).data()

        if chain_test:
            print("   ✅ Zincir çalışıyor:")
            for row in chain_test:
                print(f"      {row['project']} -> {row['module']} -> {row['dep_count']} dependency")
            results["sample_data"]["project_chain"] = chain_test
        else:
            print("   ❌ Project->Module->Dependency zinciri bulunamadı!")
            results["issues"].append("Project chain not found")

        # 4. DEPENDS_ON Transitive Test
        print("\n" + "=" * 60)
        print("4. DEPENDS_ON TRANSİTİVE TEST")
        print("=" * 60)
        depends_on_count = results["relationship_counts"].get("DEPENDS_ON", 0)

        if depends_on_count > 0:
            print(f"   ✅ {depends_on_count} DEPENDS_ON ilişkisi mevcut")

            # Sample edges
            edges = session.run("""
                MATCH (a:Dependency)-[:DEPENDS_ON]->(b:Dependency)
                RETURN a.groupId + ':' + a.artifactId as from_dep,
                       b.groupId + ':' + b.artifactId as to_dep
                LIMIT 5
            """).data()

            print("   Örnek DEPENDS_ON ilişkileri:")
            for e in edges:
                print(f"      {e['from_dep']} -> {e['to_dep']}")
            results["sample_data"]["depends_on_edges"] = edges

            # Transitive depth test
            depth_test = session.run("""
                MATCH path = (d:Dependency)-[:DEPENDS_ON*1..5]->(child:Dependency)
                WHERE d.isDirectDependency = true
                RETURN d.artifactId as root, 
                       max(length(path)) as max_depth,
                       count(DISTINCT child) as transitive_count
                ORDER BY transitive_count DESC
                LIMIT 5
            """).data()

            if depth_test:
                print("\n   En çok transitive dependency'ye sahip olanlar:")
                for row in depth_test:
                    print(f"      {row['root']}: {row['transitive_count']} transitive (max depth: {row['max_depth']})")
                results["transitive_test"]["top_transitives"] = depth_test
        else:
            print("   ❌ DEPENDS_ON ilişkisi bulunamadı!")
            results["issues"].append("No DEPENDS_ON relationships")

        # 5. Vulnerability Test
        print("\n" + "=" * 60)
        print("5. VULNERABILITY TEST")
        print("=" * 60)
        vuln_test = session.run("""
            MATCH (d:Dependency)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN d.groupId + ':' + d.artifactId as artifact,
                   count(v) as vuln_count,
                   collect(v.severity)[0..3] as severities
            ORDER BY vuln_count DESC
            LIMIT 5
        """).data()

        if vuln_test:
            print("   ✅ En çok vulnerability'ye sahip dependency'ler:")
            for row in vuln_test:
                print(f"      {row['artifact']}: {row['vuln_count']} vuln ({row['severities']})")
            results["sample_data"]["top_vulnerable"] = vuln_test
        else:
            print("   ⚠️ Vulnerability verisi bulunamadı")

        # 6. Remediation Test
        print("\n" + "=" * 60)
        print("6. REMEDIATION TEST")
        print("=" * 60)
        remediation_test = session.run("""
            MATCH (d:Dependency)-[:CURRENT_VERSION]->(cv:ArtifactVersion)
            MATCH (d)-[:RECOMMENDED_VERSION]->(rv:ArtifactVersion)
            WHERE cv.version <> rv.version
            RETURN d.groupId + ':' + d.artifactId as artifact,
                   cv.version as current,
                   rv.version as recommended
            LIMIT 5
        """).data()

        if remediation_test:
            print("   ✅ Remediation önerileri:")
            for row in remediation_test:
                print(f"      {row['artifact']}: {row['current']} -> {row['recommended']}")
            results["sample_data"]["remediations"] = remediation_test
        else:
            print("   ⚠️ Remediation verisi bulunamadı (normal olabilir)")

        # 7. Specific Artifact Tree Test (jackson-databind)
        print("\n" + "=" * 60)
        print("7. JACKSON-DATABIND TRANSİTİVE TREE")
        print("=" * 60)
        jackson_tree = session.run("""
            MATCH (root:Dependency)
            WHERE root.artifactId = 'jackson-databind'
            OPTIONAL MATCH path = (root)-[:DEPENDS_ON*1..3]->(child:Dependency)
            WITH root, child, length(path) as depth
            WHERE child IS NOT NULL
            RETURN root.groupId + ':' + root.artifactId + ':' + root.detectedVersion as root_artifact,
                   child.groupId + ':' + child.artifactId + ':' + child.detectedVersion as transitive,
                   depth
            ORDER BY depth
        """).data()

        if jackson_tree:
            print(f"   ✅ jackson-databind'in {len(jackson_tree)} transitive dependency'si:")
            for dep in jackson_tree:
                indent = "   " + "  " * dep['depth']
                print(f"{indent}└─ {dep['transitive']} (depth: {dep['depth']})")
            results["transitive_test"]["jackson_tree"] = jackson_tree
        else:
            # Check if jackson-databind exists
            jd = session.run("MATCH (d:Dependency) WHERE d.artifactId = 'jackson-databind' RETURN d.artifactId, d.detectedVersion").data()
            if jd:
                print(f"   ⚠️ jackson-databind mevcut ama transitive yok: {jd}")
            else:
                print("   ⚠️ jackson-databind bulunamadı")

    driver.close()

    # Summary
    print("\n" + "=" * 60)
    print("ÖZET")
    print("=" * 60)

    total_nodes = sum(results["node_counts"].values())
    total_rels = sum(results["relationship_counts"].values())

    print(f"   Toplam Node: {total_nodes}")
    print(f"   Toplam Relationship: {total_rels}")
    print(f"   DEPENDS_ON: {results['relationship_counts'].get('DEPENDS_ON', 0)}")

    if results["issues"]:
        print(f"\n   ⚠️ Sorunlar: {results['issues']}")
    else:
        print("\n   ✅ Tüm testler başarılı!")

    return results

if __name__ == "__main__":
    print("Neo4j Database Model Test")
    print("=" * 60)
    results = run_tests()

    # Save results to JSON
    with open("/tmp/neo4j_test_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n📄 Sonuçlar /tmp/neo4j_test_results.json dosyasına kaydedildi")

