#!/usr/bin/env python3
"""Check DEPENDS_ON relationships in Neo4j"""

import sys
from neo4j import GraphDatabase

def main():
    print("Connecting to Neo4j...", flush=True)
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
        # Test connection
        driver.verify_connectivity()
        print("Connected!", flush=True)
    except Exception as e:
        print(f"Connection failed: {e}", flush=True)
        sys.exit(1)

    try:
        with driver.session() as session:
            print("=" * 70)
            print("1. DEPENDS_ON İlişki Sayısı")
            print("=" * 70)
            result = session.run("MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) as cnt").single()
            print(f"   Toplam DEPENDS_ON ilişkisi: {result['cnt']}")

            print("\n" + "=" * 70)
            print("2. Örnek DEPENDS_ON İlişkileri (ilk 10)")
            print("=" * 70)
            edges = session.run("""
                MATCH (a:Dependency)-[:DEPENDS_ON]->(b:Dependency)
                RETURN a.groupId + ':' + a.artifactId as from_artifact,
                       a.detectedVersion as from_version,
                       b.groupId + ':' + b.artifactId as to_artifact,
                       b.detectedVersion as to_version
                LIMIT 10
            """).data()

            if edges:
                for i, e in enumerate(edges, 1):
                    print(f"   {i}. {e['from_artifact']}:{e['from_version']}")
                    print(f"      └─> {e['to_artifact']}:{e['to_version']}")
            else:
                print("   ❌ Hiç DEPENDS_ON ilişkisi bulunamadı!")

            print("\n" + "=" * 70)
            print("3. jackson-databind için Transitive Tree (forward)")
            print("=" * 70)
            jackson_tree = session.run("""
                MATCH (root:Dependency)
                WHERE root.artifactId = 'jackson-databind'
                OPTIONAL MATCH path = (root)-[:DEPENDS_ON*1..5]->(child:Dependency)
                WITH root, child, length(path) as depth
                WHERE child IS NOT NULL
                RETURN root.groupId + ':' + root.artifactId + ':' + root.detectedVersion as root_dep,
                       child.groupId + ':' + child.artifactId + ':' + child.detectedVersion as transitive_dep,
                       depth
                ORDER BY depth
            """).data()

            if jackson_tree:
                print(f"   jackson-databind'in {len(jackson_tree)} transitive dependency'si var:")
                for dep in jackson_tree[:10]:
                    indent = "   " + "  " * dep['depth']
                    print(f"{indent}└─ {dep['transitive_dep']} (depth: {dep['depth']})")
            else:
                print("   ❌ jackson-databind için transitive dependency bulunamadı!")
                # Check if jackson-databind exists
                jd = session.run("""
                    MATCH (d:Dependency) WHERE d.artifactId = 'jackson-databind'
                    RETURN d.groupId, d.artifactId, d.detectedVersion
                """).data()
                if jd:
                    print(f"   ℹ️  jackson-databind mevcut: {jd}")
                else:
                    print("   ℹ️  jackson-databind node'u bulunamadı")

            print("\n" + "=" * 70)
            print("4. log4j için Reverse Tree (ne log4j'ye bağlı?)")
            print("=" * 70)
            log4j_reverse = session.run("""
                MATCH (target:Dependency)
                WHERE target.artifactId CONTAINS 'log4j'
                OPTIONAL MATCH (parent:Dependency)-[:DEPENDS_ON]->(target)
                RETURN target.groupId + ':' + target.artifactId + ':' + target.detectedVersion as log4j_dep,
                       collect(parent.groupId + ':' + parent.artifactId)[0..5] as depends_on_log4j
            """).data()

            if log4j_reverse:
                for item in log4j_reverse:
                    print(f"   {item['log4j_dep']}")
                    if item['depends_on_log4j']:
                        for parent in item['depends_on_log4j']:
                            if parent:
                                print(f"      ← {parent}")
                    else:
                        print("      (hiçbir şey buna bağlı değil - muhtemelen direct dependency)")
            else:
                print("   ❌ log4j bulunamadı!")

            print("\n" + "=" * 70)
            print("5. Tüm Dependency Sayıları")
            print("=" * 70)
            counts = session.run("""
                MATCH (d:Dependency)
                RETURN count(d) as total,
                       count(CASE WHEN d.isDirectDependency = true THEN 1 END) as direct,
                       count(CASE WHEN d.isDirectDependency = false THEN 1 END) as transitive,
                       count(CASE WHEN d.isDotOnly = true THEN 1 END) as dot_only,
                       count(CASE WHEN d.isPhantomDependency = true THEN 1 END) as phantom
            """).single()

            print(f"   Toplam Dependency: {counts['total']}")
            print(f"   Direct: {counts['direct']}")
            print(f"   Transitive: {counts['transitive']}")
            print(f"   DOT-only: {counts['dot_only']}")
            print(f"   Phantom (BOM/starter): {counts['phantom']}")

    finally:
        driver.close()

    print("\n✅ Kontrol tamamlandı!")

if __name__ == "__main__":
    main()

