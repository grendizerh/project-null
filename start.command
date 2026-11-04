#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOR_BINARY="${PROJECT_NULL_TOR_BINARY:-${HOME}/Applications/ProjectNULL/tor-expert-16.0/tor/tor}"
PYTHON="${PROJECT_NULL_PYTHON:-${HOME}/miniforge3/envs/project-null-gui/bin/python}"

if [[ ! -x "$PYTHON" ]]; then
  echo "Project NULL's Python environment is missing. Run ./setup_macos.sh first."
  read -r -p "Press Enter to close..."
  exit 1
fi
if [[ ! -x "$TOR_BINARY" ]]; then
  echo "Tor was not found. Run ./setup_macos.sh first or set PROJECT_NULL_TOR_BINARY."
  read -r -p "Press Enter to close..."
  exit 1
fi

export PROJECT_NULL_TOR_BINARY="$TOR_BINARY"
cd "$PROJECT_DIR"
exec "$PYTHON" "$PROJECT_DIR/project_null.py" "$@"
