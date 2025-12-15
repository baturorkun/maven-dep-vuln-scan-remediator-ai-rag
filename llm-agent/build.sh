#!/bin/bash

# Build the agent image
echo "Building agent image..."
podman build -t localhost/llm-agent:odc-arm64 -f Dockerfile.agent .
