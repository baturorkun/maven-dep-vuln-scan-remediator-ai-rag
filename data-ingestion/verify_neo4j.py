import os
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

def verify():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            result = session.run("MATCH (n) RETURN labels(n) as Label, count(n) as Count")
            print("Verification Results:")
            for record in result:
                print(f"{record['Label']}: {record['Count']}")
            
            rel_result = session.run("MATCH ()-[r]->() RETURN type(r) as Type, count(r) as Count")
            print("\nRelationships:")
            for record in rel_result:
                print(f"{record['Type']}: {record['Count']}")
    finally:
        driver.close()

if __name__ == "__main__":
    verify()
