#!/usr/bin/env bash
set -x

# Run data ingestion in container
podman run --rm \
  --network host \
  -v "$(pwd)/../version-scanner-odc:/app" \
  -v "$(pwd)/import_odc_to_neo4j.py":/ingestion/import_odc_to_neo4j.py \
  data-ingestion \
  --target-dir /app/java-project \
  --project java-project \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password password

# Verify the import in container (with updated verify script)
podman run --rm \
  --network host \
  -v "$(pwd)/verify_neo4j.py":/ingestion/verify_neo4j.py \
  --entrypoint python \
  data-ingestion \
  /ingestion/verify_neo4j.py
