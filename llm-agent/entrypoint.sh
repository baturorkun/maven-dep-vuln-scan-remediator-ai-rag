#!/usr/bin/env bash
set -euo pipefail

# Load .env if present (safe parsing, ignores comments and blank lines)
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Default port can be overridden by PORT env var
PORT="${PORT:-8501}"

# Run Streamlit, bind to 0.0.0.0 so it works inside containers
exec streamlit run dashboard.py --server.address=0.0.0.0 --server.port="$PORT"

