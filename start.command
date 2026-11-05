#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOR_BINARY="${HOME}/Applications/ProjectNULL/tor-expert-16.0/tor/tor"
PYTHON="${HOME}/miniforge3/envs/project-null-gui/bin/python"

if [[ -n "${PROJECT_NULL_TOR_BINARY:-}" && "${PROJECT_NULL_TOR_BINARY}" != "${TOR_BINARY}" ]]; then
  echo "Unmanaged Tor binary overrides are disabled. Run ./setup_macos.sh and use the pinned per-user Tor bundle."
  exit 1
fi
if [[ ! -x "$PYTHON" ]]; then
  echo "Project NULL's Python environment is missing. Run ./setup_macos.sh first."
  exit 1
fi
if [[ ! -x "$TOR_BINARY" ]]; then
  echo "Tor was not found at the pinned per-user location. Run ./setup_macos.sh first."
  exit 1
fi

cd "$PROJECT_DIR"
exec "$PYTHON" "$PROJECT_DIR/project_null.py" "$@"
