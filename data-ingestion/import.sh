#!/usr/bin/envveri bash

# Run data ingestion in container
podman run --rm \
  --network host \
  -v "$(pwd)/../version-scanner-odc:/app" \
  data-ingestion \
  --target-dir /app/java-project \
  --project java-project \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password password

# Verify the import in container
podman run --rm \
  --network host \
  --entrypoint python \
  data-ingestion \
  /ingestion/verify_neo4j.py
