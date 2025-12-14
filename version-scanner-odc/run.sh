#!/usr/bin/env bash

podman run --rm -v "$(pwd)":/app -v "$(pwd)/.m2:/root/.m2" -e ALLOW_MAJOR_UPGRADE=true version-scanner:odc-arm64 --target-dir /app/java-project --remediation --transitive
