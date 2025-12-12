#!/usr/bin/env bash

#podman run --env NEO4J_URI=your_uri --env NEO4J_USER=your_user --env NEO4J_PASSWORD=your_password data-ingestion

podman run -v "$(pwd)/../version-scanner-odc":/app data-ingestion --target-dir /app/java-project --project "myproject"
