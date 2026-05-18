#!/bin/bash

# Build the agent image
echo "Building agent image..."
podman build -t localhost/baturorkun/llm-agent:latest -f Dockerfile.agent .

# Determine absolute path to odc-data
# Assuming run_dashboard.sh is in llm-agent/ and odc-data is in ../version-scanner-odc/odc-data
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ODC_DATA_DIR="$(cd "$SCRIPT_DIR/../version-scanner-odc/odc-data" && pwd)"

echo "Mounting ODC Data from: $ODC_DATA_DIR"

# Run the container
echo "Starting dashboard at http://localhost:8501"
podman run --rm -it \
  -p 8501:8501 \
  -v "$ODC_DATA_DIR":/data:ro \
  -e NEO4J_URI=${NEO4J_URI:-bolt://host.containers.internal:7687} \
  -e NEO4J_USER=${NEO4J_USER:-neo4j} \
  -e NEO4J_PASSWORD=${NEO4J_PASSWORD:-password} \
  localhost/baturorkun/llm-agent:latest
