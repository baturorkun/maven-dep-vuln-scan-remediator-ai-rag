#!/usr/bin/env bash

# Verify the import in container (with updated verify script)
podman run --rm \
  --network host \
  -v "$(pwd)/verify_neo4j.py":/ingestion/verify_neo4j.py \
  --entrypoint python \
  data-ingestion \
  /ingestion/verify_neo4j.py