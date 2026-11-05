#!/usr/bin/env bash
set -Eeuo pipefail

# Project NULL v0.4.9 — per-user macOS Apple Silicon setup.
# No sudo, Homebrew compilation, or full Xcode installation is required.

APP_VERSION="0.4.9"
MINIFORGE_VERSION="26.9.4-1"
TOR_EXPERT_VERSION="16.0"
TOR_MIN_VERSION="0.4.9.15"
TOR_SHA256="b8da251eccbe9e82f3681ee3af3c97fb4291c4a4e153e5b824bde48a1117cd6a"
ENV_NAME="project-null-gui"
MINIFORGE_PREFIX="${HOME}/miniforge3"
TOR_INSTALL_DIR="${HOME}/Applications/ProjectNULL/tor-expert-${TOR_EXPERT_VERSION}"
TOR_BINARY="${TOR_INSTALL_DIR}/tor/tor"
TOR_MANIFEST="${TOR_INSTALL_DIR}/.project-null-tor-manifest.json"
TOR_INSTALL_PARENT="${HOME}/Applications/ProjectNULL"
STAGING_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/project-null-setup.XXXXXX")"
cleanup() {
  rm -rf "$TEMP_DIR"
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then rm -rf "$STAGING_DIR"; fi
}
trap cleanup EXIT
fail() { echo "ERROR: $*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || fail "This setup helper supports macOS only."
[[ "$(uname -m)" == "arm64" ]] || fail "This setup helper currently supports Apple Silicon (arm64) only."

CONDA="${MINIFORGE_PREFIX}/bin/conda"
if [[ -x "$CONDA" ]] && "$CONDA" env list | awk '{print $1}' | grep -Fxq "$ENV_NAME"; then
  minimum_free_mb=1024
else
  minimum_free_mb=5120
fi
free_kb="$(df -Pk "$HOME" | awk 'NR==2 {print $4}')"
free_mb="$((free_kb / 1024))"
echo "Project NULL ${APP_VERSION} setup — available storage: ${free_mb} MB"
if (( free_mb < minimum_free_mb )); then
  if (( minimum_free_mb >= 5120 )); then
    fail "At least 5 GB free is recommended for first-time Miniforge + Python/Tk installation."
  else
    fail "At least 1 GB free is recommended to update the existing environment safely."
  fi
fi

# ---------------------------------------------------------------------------
# Miniforge and Python/Tk environment.
# ---------------------------------------------------------------------------
if [[ ! -x "$CONDA" ]]; then
  [[ ! -e "$MINIFORGE_PREFIX" ]] || fail "Incomplete Miniforge directory exists at ${MINIFORGE_PREFIX}. Inspect/remove only that incomplete directory, then retry."
  echo "Installing Miniforge ${MINIFORGE_VERSION} under ${MINIFORGE_PREFIX}..."
  mf_file="Miniforge3-${MINIFORGE_VERSION}-MacOSX-arm64.sh"
  mf_base="https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_VERSION}"
  curl -fL --retry 5 --retry-all-errors "${mf_base}/${mf_file}" -o "${TEMP_DIR}/${mf_file}"
  curl -fL --retry 5 --retry-all-errors "${mf_base}/${mf_file}.sha256" -o "${TEMP_DIR}/${mf_file}.sha256"
  expected="$(awk 'NR==1 {print $1}' "${TEMP_DIR}/${mf_file}.sha256")"
  actual="$(shasum -a 256 "${TEMP_DIR}/${mf_file}" | awk '{print $1}')"
  [[ -n "$expected" && "$expected" == "$actual" ]] || fail "Miniforge SHA-256 verification failed; installer was not run."
  bash "${TEMP_DIR}/${mf_file}" -b -p "$MINIFORGE_PREFIX"
fi

if ! "$CONDA" env list | awk '{print $1}' | grep -Fxq "$ENV_NAME"; then
  echo "Creating Python 3.12 + Tkinter environment..."
  "$CONDA" create -y -n "$ENV_NAME" python=3.12 tk pip setuptools
else
  echo "Checking the existing ${ENV_NAME} environment..."
  "$CONDA" install -y -n "$ENV_NAME" python=3.12 tk pip setuptools
fi
PYTHON="${MINIFORGE_PREFIX}/envs/${ENV_NAME}/bin/python"
[[ -x "$PYTHON" ]] || fail "Expected Python interpreter missing at ${PYTHON}."
"$PYTHON" -m pip install --upgrade --no-deps --require-hashes --no-build-isolation -r "${SCRIPT_DIR}/requirements.txt"
"$PYTHON" - <<'PY' || fail "Python/Tkinter/Stem/Certifi validation failed."
import tkinter
import stem
import certifi
print("Tkinter:", tkinter.TkVersion)
print("Stem:", stem.__version__)
print("Certifi CA bundle:", certifi.where())
print("Python environment: OK")
PY

# ---------------------------------------------------------------------------
# Tor Project Expert Bundle, checksum verification, binary integrity manifest.
# ---------------------------------------------------------------------------
tor_needs_install=1
[[ ! -L "${HOME}/Applications" ]] || fail "${HOME}/Applications is a symlink; refusing to install Tor through it."
[[ ! -L "$TOR_INSTALL_PARENT" ]] || fail "Tor installation parent is a symlink: ${TOR_INSTALL_PARENT}"
mkdir -p "$TOR_INSTALL_PARENT"
chmod 700 "$TOR_INSTALL_PARENT"
if [[ -x "$TOR_BINARY" && ! -L "$TOR_BINARY" && -f "$TOR_MANIFEST" && ! -L "$TOR_MANIFEST" ]]; then
  installed_version="$("$TOR_BINARY" --version 2>/dev/null | head -n 1 || true)"
  installed_binary_sha="$(shasum -a 256 "$TOR_BINARY" | awk '{print $1}')"
  manifest_archive_sha="$(sed -n 's/.*"archive_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$TOR_MANIFEST" | head -n 1)"
  manifest_binary_sha="$(sed -n 's/.*"binary_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$TOR_MANIFEST" | head -n 1)"
  if [[ "$manifest_archive_sha" == "$TOR_SHA256" && "$manifest_binary_sha" == "$installed_binary_sha" ]] \
    && grep -Fq '"bundle_version": "'"${TOR_EXPERT_VERSION}"'"' "$TOR_MANIFEST" \
    && grep -Fq '"binary_relative_path": "tor/tor"' "$TOR_MANIFEST" \
    && /usr/bin/codesign --verify --strict "$TOR_BINARY" >/dev/null 2>&1 \
    && "$PYTHON" - "$installed_version" "$TOR_MIN_VERSION" <<'PYVER'
import re, sys
match = re.search(r"Tor version (\d+)\.(\d+)\.(\d+)\.(\d+)", sys.argv[1])
current = tuple(map(int, match.groups())) if match else None
minimum = tuple(map(int, sys.argv[2].split(".")))
raise SystemExit(0 if current is not None and current >= minimum else 1)
PYVER
  then
    tor_needs_install=0
  fi
fi

if (( tor_needs_install )); then
  echo "Installing Tor Expert Bundle ${TOR_EXPERT_VERSION}..."
  tor_archive="tor-expert-bundle-macos-aarch64-${TOR_EXPERT_VERSION}.tar.gz"
  tor_url="https://dist.torproject.org/torbrowser/${TOR_EXPERT_VERSION}/${tor_archive}"
  curl -fL --retry 5 --retry-all-errors "$tor_url" -o "${TEMP_DIR}/${tor_archive}"
  actual_tor_sha="$(shasum -a 256 "${TEMP_DIR}/${tor_archive}" | awk '{print $1}')"
  [[ "$actual_tor_sha" == "$TOR_SHA256" ]] || fail "Tor Expert Bundle SHA-256 verification failed; archive was not extracted."
  STAGING_DIR="${TOR_INSTALL_PARENT}/.tor-expert-stage.$$.$RANDOM"
  mkdir -m 700 "$STAGING_DIR"
  tar -xzf "${TEMP_DIR}/${tor_archive}" -C "$STAGING_DIR"
  STAGED_TOR_BINARY="${STAGING_DIR}/tor/tor"
  [[ -f "$STAGED_TOR_BINARY" && ! -L "$STAGED_TOR_BINARY" ]] || fail "Tor archive did not contain the expected regular executable at tor/tor."
  chmod u+x "$STAGED_TOR_BINARY"
  if ! /usr/bin/codesign --verify --strict "$STAGED_TOR_BINARY" >/dev/null 2>&1; then
    # This changes only the code signature after the entire upstream archive
    # has passed the pinned SHA-256 check. It does not establish publisher ID.
    /usr/bin/codesign --remove-signature "$STAGED_TOR_BINARY" >/dev/null 2>&1 || true
    /usr/bin/codesign --force --sign - "$STAGED_TOR_BINARY"
  fi
  /usr/bin/codesign --verify --strict "$STAGED_TOR_BINARY" >/dev/null 2>&1 || fail "Tor code-signature integrity check failed after extraction."
  staged_binary_sha="$(shasum -a 256 "$STAGED_TOR_BINARY" | awk '{print $1}')"
  [[ "$staged_binary_sha" =~ ^[0-9a-f]{64}$ ]] || fail "Could not calculate the staged Tor binary digest."
  umask 077
  cat > "${STAGING_DIR}/.project-null-tor-manifest.json" <<EOF
{
  "bundle_version": "${TOR_EXPERT_VERSION}",
  "archive_sha256": "${TOR_SHA256}",
  "binary_relative_path": "tor/tor",
  "binary_sha256": "${staged_binary_sha}"
}
EOF
  chmod 600 "${STAGING_DIR}/.project-null-tor-manifest.json"
  [[ ! -L "$TOR_INSTALL_DIR" ]] || fail "Existing Tor installation path is a symlink; refusing to replace it."
  rm -rf "$TOR_INSTALL_DIR"
  mv "$STAGING_DIR" "$TOR_INSTALL_DIR"
  STAGING_DIR=""
fi

[[ -f "$TOR_BINARY" && ! -L "$TOR_BINARY" ]] || fail "Tor executable not found as a regular, non-symlink file at ${TOR_BINARY}. Check the Expert Bundle layout."
/usr/bin/codesign --verify --strict "$TOR_BINARY" >/dev/null 2>&1 || fail "Tor code-signature integrity check failed."
[[ -f "$TOR_MANIFEST" && ! -L "$TOR_MANIFEST" ]] || fail "Tor bundle integrity manifest is missing."
installed_binary_sha="$(shasum -a 256 "$TOR_BINARY" | awk '{print $1}')"
manifest_binary_sha="$(sed -n 's/.*"binary_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$TOR_MANIFEST" | head -n 1)"
manifest_archive_sha="$(sed -n 's/.*"archive_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$TOR_MANIFEST" | head -n 1)"
[[ "$installed_binary_sha" == "$manifest_binary_sha" && "$manifest_archive_sha" == "$TOR_SHA256" ]] || fail "Installed Tor binary does not match its pinned installation manifest."
grep -Fq '"bundle_version": "'"${TOR_EXPERT_VERSION}"'"' "$TOR_MANIFEST" || fail "Tor bundle manifest version is incorrect."
grep -Fq '"binary_relative_path": "tor/tor"' "$TOR_MANIFEST" || fail "Tor bundle manifest path is incorrect."
version_line="$("$TOR_BINARY" --version 2>&1 | head -n 1)"
echo "Tor: ${version_line}"
"$PYTHON" - "$version_line" "$TOR_MIN_VERSION" <<'PYVER' || fail "Tor ${TOR_MIN_VERSION} or newer is required."
import re, sys
match = re.search(r"Tor version (\d+)\.(\d+)\.(\d+)\.(\d+)", sys.argv[1])
minimum = tuple(map(int, sys.argv[2].split(".")))
if not match or tuple(map(int, match.groups())) < minimum:
    raise SystemExit(1)
PYVER

chmod +x "${SCRIPT_DIR}/start.command"
echo "Running Project NULL offline self-tests..."
"$PYTHON" "${SCRIPT_DIR}/project_null.py" --self-test

cat <<EOF

Setup complete — Project NULL ${APP_VERSION}.
Python: ${PYTHON}
Tor:    ${TOR_BINARY}

Next: ./start.command

No sudo or system-wide network settings were used.
EOF
