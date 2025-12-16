#!/usr/bin/env bash

# Create .m2/repository if not exists
mkdir -p "$(pwd)/.m2/repository"

podman run --rm \
  -v "$(pwd)":/app \
  -v "$(pwd)/version-scanner-odc.py":/scanner/version-scanner-odc.py \
  -v "$(pwd)/remediation.py":/scanner/remediation.py \
  -v "$(pwd)/.m2":/root/.m2 \
  -e ALLOW_MAJOR_UPGRADE=true \
  version-scanner:odc-arm64 \
  --target-dir /app/java-project \
  --remediation \
  --transitive
