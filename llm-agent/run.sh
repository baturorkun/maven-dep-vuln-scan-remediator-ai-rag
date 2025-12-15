#!/usr/bin/env bash
set -xeuo pipefail

# Load .env if present
if [ -f .env ]; then
  # shellcheck disable=SC1091
  source .env
fi

# Default values
NEO4J_URI="${NEO4J_URI:-bolt://host.containers.internal:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-password}"
PORT="${PORT:-8501}"
CONTAINER_NAME="${CONTAINER_NAME:-llm-agent}"
IMAGE_NAME="${IMAGE_NAME:-localhost/llm-agent:odc-arm64}"

# LLM Configuration (from .env)
LLM_BASE_URL="${LLM_BASE_URL:-http://host.containers.internal:11434/v1}"
LLM_MODEL="${LLM_MODEL:-qwen3:8b}"
LLM_API_KEY="${LLM_API_KEY:-}"

# CVE Lookup Configuration (default: offline only, set to "true" to enable NVD API fallback)
CVE_LOOKUP_ONLINE="${CVE_LOOKUP_ONLINE:-false}"

# Stop and remove existing container if running
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
  echo "Stopping and removing existing container: ${CONTAINER_NAME}..."
  podman stop "${CONTAINER_NAME}" 2>/dev/null || true
  podman rm "${CONTAINER_NAME}" 2>/dev/null || true
fi

echo "Starting LLM Agent container (foreground mode)..."
echo "  Image: ${IMAGE_NAME}"
echo "  Port: ${PORT}"
echo "  Neo4j: ${NEO4J_URI}"
echo "  LLM: ${LLM_BASE_URL} (${LLM_MODEL})"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run the container in foreground (no -d flag)
podman run --rm \
  --name "${CONTAINER_NAME}" \
  -p "${PORT}:8501" \
  -v "$(pwd):/app" \
  -v "$(pwd)/../version-scanner-odc/odc-data:/odc-data:ro" \
  -e NEO4J_URI="${NEO4J_URI}" \
  -e NEO4J_USER="${NEO4J_USER}" \
  -e NEO4J_PASSWORD="${NEO4J_PASSWORD}" \
  -e LLM_BASE_URL="${LLM_BASE_URL}" \
  -e LLM_MODEL="${LLM_MODEL}" \
  -e LLM_API_KEY="${LLM_API_KEY}" \
  -e CVE_LOOKUP_ONLINE="${CVE_LOOKUP_ONLINE}" \
  -e JAVA_HOME="/opt/java/openjdk" \
  -e LD_LIBRARY_PATH="/opt/java/openjdk/lib/server:/opt/java/openjdk/lib" \
  -e DEPENDENCY_CHECK_HOME="/opt/dependency-check" \
  "${IMAGE_NAME}"

