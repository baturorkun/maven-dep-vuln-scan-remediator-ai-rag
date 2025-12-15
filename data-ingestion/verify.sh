#!/usr/bin/env bash

# Verify the import in container
podman run --rm \
  --network host \
  --entrypoint python \
  data-ingestion \
  /ingestion/verify_neo4j.py
