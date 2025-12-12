#!/usr/bin/env bash

podman exec neo4j-owasp cypher-shell  -u neo4j -p  password "MATCH (n) DETACH DELETE n"

python verify_neo4j.py