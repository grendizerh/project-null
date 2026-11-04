#!/usr/bin/env bash
set -Eeuo pipefail

# Project NULL macOS setup. Installs only under the current user's home folder.
# No sudo, Xcode, or Homebrew build toolchain is required.

MINIFORGE_VERSION="26.9.4-1"
TOR_EXPERT_VERSION="16.0"
TOR_SHA256="b8da251eccbe9e82f3681ee3af3c97fb4291c4a4e153e5b824bde48a1117cd6a"
ENV_NAME="project-null-gui"
MINIFORGE_PREFIX="${HOME}/miniforge3"
TOR_INSTALL_DIR="${HOME}/Applications/ProjectNULL/tor-expert-${TOR_EXPERT_VERSION}"
TOR_BINARY="${TOR_INSTALL_DIR}/tor/tor"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/project-null-setup.XXXXXX")"

cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

fail() { echo "ERROR: $*" >&2; exit 1; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "This setup helper currently supports macOS only."
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  fail "The bundled setup is currently tested on Apple Silicon (arm64). Intel macOS users must install a compatible Tor binary manually."
fi

free_kb="$(df -Pk "$HOME" | awk 'NR==2 {print $4}')"
free_mb="$((free_kb / 1024))"
echo "Project NULL setup — free storage: ${free_mb} MB"
if (( free_mb < 3072 )); then
  fail "At least 3 GB of free storage is recommended before creating the Python GUI environment."
fi

# ---------------------------------------------------------------------------
# Python + Tkinter environment (reuse the user's existing Miniforge install).
# ---------------------------------------------------------------------------
CONDA="${MINIFORGE_PREFIX}/bin/conda"
if [[ ! -x "$CONDA" ]]; then
  if command -v conda >/dev/null 2>&1; then
    CONDA="$(command -v conda)"
  else
    echo "Installing Miniforge ${MINIFORGE_VERSION} into ${MINIFORGE_PREFIX}..."
    mf_file="Miniforge3-${MINIFORGE_VERSION}-MacOSX-arm64.sh"
    mf_base="https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_VERSION}"
    curl -fL --retry 5 --retry-all-errors "${mf_base}/${mf_file}" -o "${TEMP_DIR}/${mf_file}"
    curl -fL --retry 5 --retry-all-errors "${mf_base}/${mf_file}.sha256" -o "${TEMP_DIR}/${mf_file}.sha256"
    expected="$(awk 'NR==1 {print $1}' "${TEMP_DIR}/${mf_file}.sha256")"
    actual="$(shasum -a 256 "${TEMP_DIR}/${mf_file}" | awk '{print $1}')"
    [[ -n "$expected" && "$expected" == "$actual" ]] || fail "Miniforge SHA-256 verification failed. Installer was not run."
    bash "${TEMP_DIR}/${mf_file}" -b -p "$MINIFORGE_PREFIX"
  fi
fi

# Create the environment once. If it exists, leave its packages intact and update
# only the application dependencies below.
if ! "$CONDA" env list | awk '{print $1}' | grep -Fxq "$ENV_NAME"; then
  echo "Creating Python 3.12 + Tkinter environment..."
  "$CONDA" create -y -n "$ENV_NAME" python=3.12 tk pip
else
  # Repair a pre-existing environment if Tkinter was omitted from its first install.
  "$CONDA" install -y -n "$ENV_NAME" python=3.12 tk pip
fi
PYTHON="$MINIFORGE_PREFIX/envs/${ENV_NAME}/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  # Support a Conda installation outside ~/miniforge3.
  PYTHON="$($CONDA run -n "$ENV_NAME" python -c 'import sys; print(sys.executable)')"
fi

"$PYTHON" -m pip install --upgrade cryptography stem certifi
"$PYTHON" -c 'import tkinter, cryptography, stem, certifi; print("Python, Tkinter and dependencies: OK")' \
  || fail "The Python environment is incomplete. Re-run this setup after checking Conda output."

# ---------------------------------------------------------------------------
# Official Tor Expert Bundle for Apple Silicon. Verify before extraction.
# ---------------------------------------------------------------------------
if [[ ! -x "$TOR_BINARY" ]]; then
  echo "Downloading official Tor Expert Bundle ${TOR_EXPERT_VERSION}..."
  mkdir -p "$TOR_INSTALL_DIR"
  tor_archive="tor-expert-bundle-macos-aarch64-${TOR_EXPERT_VERSION}.tar.gz"
  tor_url="https://dist.torproject.org/torbrowser/${TOR_EXPERT_VERSION}/${tor_archive}"
  curl -fL --retry 5 --retry-all-errors "$tor_url" -o "${TEMP_DIR}/${tor_archive}"
  actual_tor_sha="$(shasum -a 256 "${TEMP_DIR}/${tor_archive}" | awk '{print $1}')"
  [[ "$actual_tor_sha" == "$TOR_SHA256" ]] || fail "Tor Expert Bundle SHA-256 verification failed. Archive was not extracted."
  tar -xzf "${TEMP_DIR}/${tor_archive}" -C "$TOR_INSTALL_DIR"
fi

[[ -f "$TOR_BINARY" ]] || fail "Tor executable not found at ${TOR_BINARY}. Check the Expert Bundle layout."
chmod u+x "$TOR_BINARY"

# The Expert Bundle binary in this tested release carries an invalid embedded
# ad-hoc signature on some macOS installations. Re-sign locally only after its
# archive checksum has been verified. This is an ad-hoc signature, not Apple
# notarization or a publisher identity.
if ! codesign --verify --strict "$TOR_BINARY" >/dev/null 2>&1; then
  echo "Applying a local ad-hoc code signature to the checksum-verified Tor binary..."
  codesign --remove-signature "$TOR_BINARY" >/dev/null 2>&1 || true
  codesign --force --sign - "$TOR_BINARY"
fi
codesign --verify --strict "$TOR_BINARY" >/dev/null 2>&1 \
  || fail "macOS could not validate the local Tor binary signature."

version_line="$("$TOR_BINARY" --version 2>&1 | head -n 1)"
echo "Tor: ${version_line}"
"$PYTHON" - "$version_line" <<'PYVER' || fail "Tor 0.4.9.15 or newer is required."
import re
import sys
match = re.search(r"Tor version (\d+)\.(\d+)\.(\d+)\.(\d+)", sys.argv[1])
if not match or tuple(map(int, match.groups())) < (0, 4, 9, 15):
    raise SystemExit(1)
PYVER

# Mark helper scripts executable for users who downloaded the repository as a ZIP.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "${SCRIPT_DIR}/start.command" 2>/dev/null || true

cat <<EOF

Setup complete.

Python: ${PYTHON}
Tor:    ${TOR_BINARY}

Next: double-click start.command, or run:
  ./start.command
EOF
