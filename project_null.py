#!/usr/bin/env python3
"""Project NULL — loopback-only Chrome SOCKS5 adapter backed by Tor.

Python 3.11+. This is NOT a system-wide VPN or an anonymity guarantee. Chrome
connects to an unauthenticated SOCKS5 listener bound only to 127.0.0.1; that
adapter enforces hostname/TCP-443 policy and opens session- or host-isolated
streams through Tor's private Unix-domain SOCKS socket. No direct-destination
fallback exists. Any local process able to reach the loopback listener can use it; this
is a deliberate compatibility trade-off, not a local-user security boundary.

The session identifier is an opaque local label, not a network identity. Tor
SOCKS isolation credentials follow the configured session/hostname scope;
they do not authenticate a user to Tor relays or hide the client's IP from
the Tor entry guard. Chrome is compatibility mode, not Tor Browser.
"""

from __future__ import annotations

import argparse
from collections import deque
import errno
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import queue
import re
import resource
import secrets
import select
import shutil
import socket
import socketserver
import ssl
import stat
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

# Tkinter is optional for command-line self-tests. Some Homebrew Python builds
# install the Tk bindings separately, so importing the GUI toolkit at module
# load time would otherwise prevent --self-test and --self-test-live from
# running at all.
try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    TK_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:  # GUI mode reports the actionable installation step.
    tk = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    TK_IMPORT_ERROR = exc

APP_NAME = "PROJECT NULL"
APP_VERSION = "0.4.9"
MIN_TOR_VERSION = (0, 4, 9, 15)
TOR_EXPERT_BUNDLE_VERSION = "16.0"
TOR_EXPERT_ARCHIVE_SHA256 = "b8da251eccbe9e82f3681ee3af3c97fb4291c4a4e153e5b824bde48a1117cd6a"
def _raise_process_fd_soft_limit(target: int = 512) -> int:
    """Raise only this process's soft descriptor limit when its hard cap permits.

    This is a per-process resource setting, not a system-wide change. It gives
    the bounded browser proxy enough descriptors for parallel page resources
    while leaving the hard limit untouched.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 0:  # already RLIM_INFINITY
            return soft
        if hard < 0:
            desired = target
        else:
            desired = min(target, hard)
        if desired > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return int(soft)
    except (AttributeError, OSError, ValueError, PermissionError):
        try:
            return int(resource.getrlimit(resource.RLIMIT_NOFILE)[0])
        except Exception:
            return 256


PROXY_PENDING_QUEUE_SIZE = 128
PROXY_LISTEN_BACKLOG = 256


def _proxy_client_limit_for_fd_budget(soft_limit: int | float | None) -> int:
    """Bound workers while reserving descriptors for active and queued sockets.

    Each active tunnel uses two descriptors; each pending request holds one
    accepted browser socket. Reserve 64 descriptors for Tor Control, files,
    and headroom, and include the bounded pending queue in the calculation.
    """
    if soft_limit is None:
        return 64
    try:
        numeric_limit = int(soft_limit)
    except (TypeError, ValueError, OverflowError):
        return 64
    if numeric_limit < 0:  # RLIM_INFINITY on POSIX
        return 128
    usable = max(0, numeric_limit - 64 - PROXY_PENDING_QUEUE_SIZE)
    return max(1, min(128, usable // 2))


PROCESS_NOFILE_SOFT_LIMIT = _raise_process_fd_soft_limit()
MAX_PROXY_CLIENTS = _proxy_client_limit_for_fd_budget(PROCESS_NOFILE_SOFT_LIMIT)
TOR_STREAM_TIMEOUT = 90.0
TUNNEL_IDLE_TIMEOUT = 300.0
TUNNEL_SEND_TIMEOUT = 30.0
ALLOWED_CONNECT_PORTS = frozenset({443})
BLOCKED_DNS_SUFFIXES = (
    ".localhost", ".local", ".localdomain", ".lan", ".home",
    ".home.arpa", ".internal", ".test", ".invalid", ".example", ".exit",
)
APP_DIR = Path.home() / "Library" / "Application Support" / "Project NULL"
CONFIG_PATH = APP_DIR / "config.json"
TOR_DATA_DIR = APP_DIR / "tor-data"
# Tor's ControlSocket parser reports the remaining path components as invalid
# options on some builds when the path contains spaces, even when quoted.
# Put only the transient Unix sockets in a private, short, space-free runtime
# directory. Persistent Tor state remains in Application Support.
RUNTIME_BASE = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")
RUNTIME_DIR = RUNTIME_BASE / f"project-null-{os.getuid() if hasattr(os, 'getuid') else os.getpid()}"
SOCKS_SOCKET_PATH = RUNTIME_DIR / "socks.sock"
CONTROL_SOCKET_PATH = RUNTIME_DIR / "control.sock"
MANAGED_TOR_BINARY = (
    Path.home() / "Applications" / "ProjectNULL"
    / f"tor-expert-{TOR_EXPERT_BUNDLE_VERSION}" / "tor" / "tor"
)
MANAGED_TOR_MANIFEST = MANAGED_TOR_BINARY.parent.parent / ".project-null-tor-manifest.json"


# ---------------------------------------------------------------------------
# Configuration and identity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AppConfig:
    proxy_port: int = 28080
    bootstrap_timeout: int = 180
    circuit_timeout: int = 90
    stream_isolation: str = "session"

    def validate(self) -> None:
        # bool is a subclass of int in Python; reject it and all coercible
        # strings/floats rather than silently accepting ambiguous config.
        if type(self.proxy_port) is not int or not 1024 <= self.proxy_port <= 65535:
            raise ValueError("The local SOCKS5 proxy port must be an integer between 1024 and 65535.")
        if type(self.bootstrap_timeout) is not int or not 30 <= self.bootstrap_timeout <= 600:
            raise ValueError("Bootstrap timeout must be an integer between 30 and 600 seconds.")
        if type(self.circuit_timeout) is not int or not 15 <= self.circuit_timeout <= 300:
            raise ValueError("Circuit timeout must be an integer between 15 and 300 seconds.")
        if type(self.stream_isolation) is not str or self.stream_isolation not in {"session", "hostname"}:
            raise ValueError("Stream isolation must be 'session' or 'hostname'.")


def ensure_private_directory(path: Path, trusted_home: Optional[Path] = None) -> None:
    """Create/verify a private directory without chmod-by-path races.

    For production paths beneath the user's home, traverse with directory file
    descriptors and O_NOFOLLOW. This avoids the previous lstat()-then-chmod()
    gap, where a directory removed between those calls raised FileNotFoundError
    from a Tk callback and escaped its error handler.
    """
    path = Path(os.path.abspath(path))
    home = Path(os.path.abspath(trusted_home if trusted_home is not None else Path.home()))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    uid = os.getuid() if hasattr(os, "getuid") else None

    try:
        relative = path.relative_to(home)
    except ValueError:
        # Used only by isolated tests with tempfile-owned directories outside
        # the real home directory. Validate the final component without
        # following a final symlink; production state always stays under home.
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(path), flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise RuntimeError(f"Application path is not a directory: {path}")
            if uid is not None and info.st_uid != uid:
                raise PermissionError(f"Application directory is not owned by the current user: {path}")
            if stat.S_IMODE(info.st_mode) & 0o022:
                raise PermissionError(f"Application directory is writable by group or other users: {path}")
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        return

    # A concurrent launch/cleanup can remove a newly-created leaf. Retry the
    # descriptor walk a few times; each retry revalidates every component.
    last_missing: Optional[FileNotFoundError] = None
    for attempt in range(3):
        current_fd: Optional[int] = None
        try:
            current_fd = os.open(str(home), flags)
            home_info = os.fstat(current_fd)
            if not stat.S_ISDIR(home_info.st_mode):
                raise RuntimeError(f"Home path is not a real directory: {home}")
            if uid is not None and home_info.st_uid != uid:
                raise PermissionError(f"Home directory is not owned by the current user: {home}")
            if stat.S_IMODE(home_info.st_mode) & 0o022:
                raise PermissionError(f"Home directory is writable by group or other users: {home}")

            parts = relative.parts
            for index, component in enumerate(parts):
                is_leaf = index == len(parts) - 1
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                try:
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise RuntimeError(
                            f"Refusing to traverse a symlink or non-directory application path: {home / Path(*parts[:index + 1])}"
                        ) from exc
                    raise
                try:
                    child_info = os.fstat(child_fd)
                    child_path = home / Path(*parts[:index + 1])
                    if not stat.S_ISDIR(child_info.st_mode):
                        raise RuntimeError(f"Application path is not a directory: {child_path}")
                    if uid is not None and child_info.st_uid != uid:
                        raise PermissionError(f"Application directory is not owned by the current user: {child_path}")
                    if stat.S_IMODE(child_info.st_mode) & 0o022:
                        raise PermissionError(f"Application path is writable by group or other users: {child_path}")
                    if is_leaf:
                        # Change permissions on the already-open inode, not by
                        # resolving its path again after validation.
                        os.fchmod(child_fd, 0o700)
                except Exception:
                    os.close(child_fd)
                    raise
                os.close(current_fd)
                current_fd = child_fd

            # Detect replacement/removal of the named leaf after descriptor
            # traversal. The descriptor remains authoritative for fchmod.
            if parts:
                fd_info = os.fstat(current_fd)
                path_info = path.lstat()
                if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISDIR(path_info.st_mode):
                    raise RuntimeError(f"Application directory changed during validation: {path}")
                if (path_info.st_dev, path_info.st_ino) != (fd_info.st_dev, fd_info.st_ino):
                    raise RuntimeError(f"Application directory was replaced during validation: {path}")
                if stat.S_IMODE(fd_info.st_mode) & 0o077:
                    raise PermissionError(f"Could not make application directory private: {path}")
            return
        except FileNotFoundError as exc:
            last_missing = exc
            if attempt == 2:
                raise
        finally:
            if current_fd is not None:
                try:
                    os.close(current_fd)
                except OSError:
                    pass
    if last_missing is not None:
        raise last_missing


def ensure_private_runtime_directory() -> None:
    """Create a short, private socket directory beneath the OS temp root.

    macOS uses /private/tmp (rather than /tmp, which is commonly a symlink).
    The parent must be root-owned, sticky, and world-writable as expected for
    a temporary directory. The per-user child is created/retained as 0700.
    """
    base = RUNTIME_BASE
    info = base.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Unsafe runtime temporary-directory root: {base}")
    if hasattr(os, "getuid") and info.st_uid != 0:
        raise PermissionError(f"Runtime temporary-directory root is not system-owned: {base}")
    mode = stat.S_IMODE(info.st_mode)
    if not (mode & stat.S_ISVTX) or not (mode & 0o002):
        raise PermissionError(f"Runtime temporary-directory root lacks sticky/world-write semantics: {base}")
    try:
        RUNTIME_DIR.mkdir(mode=0o700)
    except FileExistsError:
        pass
    child = RUNTIME_DIR.lstat()
    if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
        raise RuntimeError(f"Refusing unsafe Project NULL runtime path: {RUNTIME_DIR}")
    if hasattr(os, "getuid") and child.st_uid != os.getuid():
        raise PermissionError(f"Project NULL runtime directory is owned by another user: {RUNTIME_DIR}")
    os.chmod(RUNTIME_DIR, 0o700)
    verified = RUNTIME_DIR.lstat()
    if stat.S_IMODE(verified.st_mode) & 0o077:
        raise PermissionError(f"Could not make runtime directory private: {RUNTIME_DIR}")


def write_private_file(path: Path, content: str) -> None:
    """Atomically replace a private file without truncating an existing inode.

    Opening a pre-existing path with O_TRUNC can damage the target of a
    hardlink before the caller has had a chance to inspect it.  Write to a
    new O_EXCL file in the same private directory, fsync it, then atomically
    replace the destination.  os.replace replaces a symlink itself rather
    than following its target.
    """
    ensure_private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(temporary, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"Refusing to write a non-regular private file: {temporary}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise PermissionError(f"Private file is not owned by the current user: {temporary}")
        os.fchmod(fd, 0o600)
        payload = content.encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("Short write while creating private file.")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        # Persist the directory entry where the platform supports directory fsync.
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class ConfigStore:
    @staticmethod
    def load() -> AppConfig:
        if not APP_DIR.exists() and not APP_DIR.is_symlink():
            return AppConfig()
        ensure_private_directory(APP_DIR)
        if CONFIG_PATH.is_symlink():
            raise RuntimeError(f"Refusing to read a symlink configuration file: {CONFIG_PATH}")
        if not CONFIG_PATH.exists():
            return AppConfig()
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(CONFIG_PATH, flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimeError("Configuration path is not a regular file.")
                if hasattr(os, "getuid") and info.st_uid != os.getuid():
                    raise PermissionError("Configuration file is not owned by the current user.")
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                    raw = json.load(stream)
            finally:
                os.close(fd)
            if not isinstance(raw, dict):
                raise ValueError("Configuration must be a JSON object.")
            # v0.3 no longer exposes Tor SOCKS or Control on TCP ports.
            # Legacy v0.2 socks_port/control_port values are intentionally ignored.
            raw_port = raw.get("proxy_port", 28080)
            if type(raw_port) is not int:
                raise ValueError("proxy_port must be a JSON integer.")
            raw_isolation = raw.get("stream_isolation", "session")
            if type(raw_isolation) is not str:
                raise ValueError("stream_isolation must be a string.")
            clean = {"proxy_port": raw_port, "stream_isolation": raw_isolation}
            config = AppConfig(**clean)
            config.validate()
            return config
        except Exception as exc:
            # Do not silently use a partially valid configuration.
            raise RuntimeError(f"Invalid configuration file: {CONFIG_PATH}: {type(exc).__name__}: {exc}") from exc

    @staticmethod
    def save(config: AppConfig) -> None:
        config.validate()
        ensure_private_directory(APP_DIR)
        if CONFIG_PATH.is_symlink():
            raise RuntimeError(f"Refusing to replace a symlink configuration file: {CONFIG_PATH}")
        payload = {
            "proxy_port": config.proxy_port,
            "stream_isolation": config.stream_isolation,
        }
        temp_path = APP_DIR / f"config.{os.getpid()}.{secrets.token_hex(6)}.tmp"
        write_private_file(temp_path, json.dumps(payload, indent=2) + "\n")
        os.replace(temp_path, CONFIG_PATH)
        os.chmod(CONFIG_PATH, 0o600)


@dataclass
class SessionContext:
    """Opaque local session label plus independent Tor stream-isolation secret."""

    session_id: str
    isolation_token: str

    def __repr__(self) -> str:
        return f"SessionContext(session_id={self.session_id!r}, isolation_token=<redacted>)"


class IdentityManager:
    """Generate a random local session label and a separate 256-bit isolation value."""

    def __init__(self) -> None:
        self.current: Optional[SessionContext] = None
        self.rotate()

    def rotate(self) -> SessionContext:
        self.current = SessionContext(
            session_id=secrets.token_hex(12).upper(),
            isolation_token=secrets.token_hex(32),
        )
        return self.current


def derive_stream_isolation_token(session_secret: str, hostname: str) -> str:
    """Derive a stable, per-destination SOCKS isolation value for one session.

    v0.3 reused one SOCKS authentication value for every destination in a
    session.  Because Tor's IsolateSOCKSAuth groups equal credentials together,
    unrelated hostnames could then share a circuit.  v0.4 derives a different
    value per canonical CONNECT hostname while keeping connections to that
    same hostname in one isolation group.  Rotating the session secret changes
    every derived value.  This is hostname isolation, not browser first-party
    isolation: a generic CONNECT proxy cannot observe the top-level web origin.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", session_secret):
        raise ValueError("Session isolation secret must be a 256-bit lowercase hex value.")
    normalized = hostname.rstrip(".").lower()
    if not normalized or not normalized.isascii():
        raise ValueError("A canonical ASCII hostname is required for isolation.")
    key = bytes.fromhex(session_secret)
    message = b"Project NULL SOCKS hostname isolation v1\0" + normalized.encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def select_stream_isolation_token(session_secret: str, hostname: str, mode: str) -> str:
    """Choose Tor SOCKS isolation scope for the configured browser profile.

    Session mode is the compatibility/performance default: all browser
    destinations in one ephemeral Project NULL session share the same Tor
    SOCKS isolation credential and may reuse a circuit. Hostname mode derives
    a separate credential for each hostname and can trigger many extra Tor
    circuits, causing slower pages and repeated Cloudflare challenges.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", session_secret):
        raise ValueError("Session isolation secret must be a 256-bit lowercase hex value.")
    if mode == "session":
        return session_secret
    if mode == "hostname":
        return derive_stream_isolation_token(session_secret, hostname)
    raise ValueError("Unknown stream-isolation mode.")


def find_chrome_binary() -> Optional[Path]:
    candidates = (
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path.home() / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    # Spotlight may know about a nonstandard per-user Applications location.
    try:
        result = subprocess.run(
            ["mdfind", "kMDItemCFBundleIdentifier == 'com.google.Chrome'"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        for app_path in result.stdout.splitlines():
            candidate = Path(app_path) / "Contents" / "MacOS" / "Google Chrome"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _tor_quote(path: Path) -> str:
    """Quote a Tor configuration path using Tor's C-style quoted-string syntax."""
    return json.dumps(str(path.resolve()), ensure_ascii=False)


def prepare_private_unix_socket_path(path: Path) -> None:
    """Create a private parent and remove only stale sockets owned by this user."""
    # Darwin's sockaddr_un.sun_path is small; fail clearly rather than let Tor
    # fail later with an ambiguous bind error.
    if sys.platform == "darwin" and len(os.fsencode(path)) >= 100:
        raise RuntimeError(f"Tor Unix-socket path is too long for macOS: {path}")
    ensure_private_directory(path.parent)
    if path.is_symlink():
        raise RuntimeError(f"Refusing to use a symlink as a Tor socket path: {path}")
    if not path.exists():
        return
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(f"Refusing to replace a non-socket path: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"Refusing to remove a socket owned by another user: {path}")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.5)
        probe.connect(str(path))
    except OSError as exc:
        if exc.errno not in (errno.ECONNREFUSED, errno.ENOENT):
            raise RuntimeError(f"Cannot determine whether Unix socket is stale: {path}: {exc}") from exc
        path.unlink(missing_ok=True)
    else:
        raise RuntimeError(f"Unix socket is already active; refusing to attach: {path}")
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# SOCKS5 client. Hostnames are sent as names (ATYP=DOMAIN), not locally resolved.
# ---------------------------------------------------------------------------

TOR_SOCKS_EXT_USERNAME = b"<torS0X>0"  # Tor SOCKS isolation extension format 0.


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        piece = sock.recv(length - len(chunks))
        if not piece:
            raise ConnectionError("Unexpected EOF during SOCKS5 handshake.")
        chunks.extend(piece)
    return bytes(chunks)


def encode_socks_target(host: str, port: int) -> bytes:
    """Encode a SOCKS5 CONNECT target without resolving hostname locally."""
    if not host or not (1 <= port <= 65535):
        raise ValueError("Invalid SOCKS destination.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        domain = host.rstrip(".").encode("idna")
        if not domain or len(domain) > 255:
            raise ValueError("Hostname is invalid or too long for SOCKS5.")
        return b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + port.to_bytes(2, "big")
    if isinstance(ip, ipaddress.IPv4Address):
        return b"\x05\x01\x00\x01" + ip.packed + port.to_bytes(2, "big")
    return b"\x05\x01\x00\x04" + ip.packed + port.to_bytes(2, "big")


class ProxyPolicyError(ValueError):
    """A syntactically valid request denied by the local proxy policy."""


def validate_connect_target(host: str, port: int) -> tuple[str, int]:
    """Apply the outbound policy before a request reaches Tor.

    Only SOCKS5 TCP/443 CONNECT is allowed. IP-literal targets and local/reserved
    names are rejected so the proxy's supported browser path uses SOCKS5
    domain-name addressing and Tor-side name resolution.
    """
    if type(port) is not int or port not in ALLOWED_CONNECT_PORTS:
        raise ProxyPolicyError("Only CONNECT to TCP port 443 is permitted; TLS is not inspected by this proxy.")
    if not host or len(host) > 253 or any(ch.isspace() or ord(ch) < 33 for ch in host):
        raise ProxyPolicyError("Invalid destination hostname.")
    if any(ch in host for ch in "\\/%?#@"):
        raise ProxyPolicyError("Destination must be a hostname, not a URL or path.")

    # For this strict profile, do not accept IP literals. Passing hostnames as
    # SOCKS5 ATYP=DOMAIN makes the Tor client perform remote name resolution.
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise ProxyPolicyError("IP-literal destinations are disabled; use a hostname for Tor-side resolution.")

    normalized = host[:-1] if host.endswith(".") else host
    try:
        ascii_host = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProxyPolicyError("Destination hostname is not valid IDNA.") from exc
    if not ascii_host or len(ascii_host) > 253 or "." not in ascii_host:
        raise ProxyPolicyError("Single-label or invalid hostnames are not permitted.")

    labels = ascii_host.split(".")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_re.fullmatch(label) for label in labels):
        raise ProxyPolicyError("Destination hostname contains an invalid DNS label.")

    # inet_aton accepts legacy IPv4 spellings such as 127.1, 2130706433,
    # 0177.0.0.1 and 0x7f000001.  They are not accepted by ipaddress.ip_address
    # but some network stacks interpret them as IP literals.  Reject them so
    # all accepted destinations are unambiguous DNS names.
    try:
        socket.inet_aton(ascii_host)
    except OSError:
        pass
    else:
        raise ProxyPolicyError("Non-canonical IPv4 address spellings are not permitted.")

    if ascii_host == "localhost" or any(
        ascii_host == suffix.lstrip(".") or ascii_host.endswith(suffix)
        for suffix in BLOCKED_DNS_SUFFIXES
    ):
        raise ProxyPolicyError("Local, reserved, and relay-pinning hostnames are blocked.")

    # Only valid v3 onion hostnames are passed through (no .exit relay pinning).
    if ascii_host.endswith(".onion"):
        onion_label = ascii_host[:-6]
        if not re.fullmatch(r"[a-z2-7]{56}", onion_label):
            raise ProxyPolicyError("Only valid v3 .onion hostnames are permitted.")

    return ascii_host, port


def socks5_connect(
    host: str,
    port: int,
    socks_socket_path: str,
    isolation_token: str,
    timeout: float = 90.0,
) -> socket.socket:
    """Open a TCP stream through Tor; never attempts a direct destination socket.

    Timeout errors identify the exact SOCKS phase. A fresh IsolateSOCKSAuth
    credential can require Tor to construct a separate circuit, so the default
    timeout is longer than the old 25-second value.
    """
    # Enforce the destination policy again at the transport boundary.  The
    # HTTP handler also checks it, but this function must remain safe if a
    # future caller invokes it directly.
    host, port = validate_connect_target(host, port)
    if not isinstance(isolation_token, str) or not re.fullmatch(r"[0-9a-f]{64}", isolation_token):
        raise ValueError("SOCKS isolation token must be a 256-bit lowercase hexadecimal value.")
    stage = "connecting to the Tor SOCKS listener"
    upstream: Optional[socket.socket] = None
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.settimeout(timeout)
        upstream.connect(socks_socket_path)

        stage = "SOCKS5 method negotiation"
        # Offer only USERNAME/PASSWORD. Tor uses this pair for stream isolation.
        upstream.sendall(b"\x05\x01\x02")
        method = recv_exact(upstream, 2)
        if method != b"\x05\x02":
            raise ConnectionError(
                "Tor SOCKS did not accept the required isolation-auth method; refusing fallback."
            )

        stage = "SOCKS5 isolation authentication"
        username = TOR_SOCKS_EXT_USERNAME
        password = isolation_token.encode("ascii")
        if len(username) > 255 or not (1 <= len(password) <= 255):
            raise ValueError("Invalid SOCKS isolation credential length.")
        upstream.sendall(
            b"\x01" + bytes([len(username)]) + username
            + bytes([len(password)]) + password
        )
        auth_reply = recv_exact(upstream, 2)
        if auth_reply != b"\x01\x00":
            raise ConnectionError("Tor SOCKS stream-isolation authentication failed.")

        stage = "Tor SOCKS CONNECT request / circuit assignment"
        upstream.sendall(encode_socks_target(host, port))
        reply = recv_exact(upstream, 4)
        if reply[0] != 5 or reply[2] != 0:
            raise ConnectionError("Invalid SOCKS5 response from Tor (version/reserved byte).")
        if reply[1] != 0:
            reasons = {
                1: "general failure", 2: "connection not allowed", 3: "network unreachable",
                4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                7: "command unsupported", 8: "address type unsupported",
            }
            raise ConnectionError(
                "Tor exit could not connect: "
                + reasons.get(reply[1], f"SOCKS error {reply[1]}")
            )
        atyp = reply[3]
        if atyp == 1:
            recv_exact(upstream, 4 + 2)
        elif atyp == 4:
            recv_exact(upstream, 16 + 2)
        elif atyp == 3:
            n = recv_exact(upstream, 1)[0]
            if n == 0:
                raise ConnectionError("Invalid empty SOCKS5 domain bind address.")
            recv_exact(upstream, n + 2)
        else:
            raise ConnectionError("Invalid SOCKS5 bind-address type.")

        upstream.settimeout(None)
        return upstream
    except (socket.timeout, TimeoutError) as exc:
        if upstream is not None:
            upstream.close()
        raise TimeoutError(f"Timed out during {stage}.") from exc
    except Exception:
        if upstream is not None:
            upstream.close()
        raise


# ---------------------------------------------------------------------------
# Local SOCKS5 adapter. It is loopback-only, no-auth on the browser side,
# hostname-only, and restricted to TCP/443. Tor-side SOCKS uses an authenticated
# per-session (default) or optional per-host isolation credential over a private
# Unix-domain socket.
# ---------------------------------------------------------------------------

SOCKS5_CLIENT_TIMEOUT = 12.0
SOCKS5_REPLY_GENERAL_FAILURE = 1
SOCKS5_REPLY_NOT_ALLOWED = 2
SOCKS5_REPLY_COMMAND_UNSUPPORTED = 7
SOCKS5_REPLY_ADDRESS_UNSUPPORTED = 8


def _socks5_reply(sock: socket.socket, code: int) -> None:
    # BND.ADDR=0.0.0.0 and BND.PORT=0 are valid placeholders for CONNECT.
    try:
        sock.sendall(bytes((5, code, 0, 1, 0, 0, 0, 0, 0, 0)))
    except OSError:
        pass


def _relay_streams(
    left: socket.socket,
    right: socket.socket,
    idle_timeout: float = TUNNEL_IDLE_TIMEOUT,
) -> None:
    peers = {left: right, right: left}
    active = [left, right]
    last_activity = time.monotonic()
    for sock in (left, right):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            sock.settimeout(TUNNEL_SEND_TIMEOUT)
        except OSError:
            pass
    while active:
        remaining = idle_timeout - (time.monotonic() - last_activity)
        if remaining <= 0:
            return
        try:
            readable, _, _ = select.select(active, [], [], min(30.0, remaining))
        except (OSError, ValueError):
            return
        if not readable:
            continue
        for source in readable:
            destination = peers[source]
            try:
                data = source.recv(65536)
            except OSError:
                data = b""
            if not data:
                active.remove(source)
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                destination.sendall(data)
            except OSError:
                return
            last_activity = time.monotonic()


class NullSocksProxyHandler(socketserver.BaseRequestHandler):
    """Browser-facing SOCKS5 no-auth endpoint; Tor-side isolation remains authenticated."""

    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(SOCKS5_CLIENT_TIMEOUT)
        upstream: Optional[socket.socket] = None
        self.server.track_socket(client)  # type: ignore[attr-defined]
        stage = "SOCKS5 client greeting"
        connected = False
        try:
            version, method_count = recv_exact(client, 2)
            if version != 5 or method_count == 0:
                _socks5_reply(client, SOCKS5_REPLY_GENERAL_FAILURE)
                return
            methods = recv_exact(client, method_count)
            # Chrome's SOCKS5 implementation does not support proxy auth.
            # Offer only no-auth on the loopback-facing adapter.
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")

            stage = "SOCKS5 CONNECT request"
            version, command, reserved, address_type = recv_exact(client, 4)
            if version != 5 or reserved != 0:
                _socks5_reply(client, SOCKS5_REPLY_GENERAL_FAILURE)
                return
            if command != 1:
                _socks5_reply(client, SOCKS5_REPLY_COMMAND_UNSUPPORTED)
                return
            if address_type != 3:
                # IP literals are rejected to guarantee that Chrome sends a
                # hostname and Tor performs DNS resolution remotely.
                _socks5_reply(client, SOCKS5_REPLY_ADDRESS_UNSUPPORTED)
                return
            domain_length = recv_exact(client, 1)[0]
            if domain_length == 0:
                _socks5_reply(client, SOCKS5_REPLY_GENERAL_FAILURE)
                return
            try:
                host = recv_exact(client, domain_length).decode("ascii")
            except UnicodeDecodeError:
                _socks5_reply(client, SOCKS5_REPLY_GENERAL_FAILURE)
                return
            port = int.from_bytes(recv_exact(client, 2), "big")
            try:
                host, port = validate_connect_target(host, port)
            except ProxyPolicyError as exc:
                self.server.log_callback("Local SOCKS request rejected by destination policy: " + str(exc))  # type: ignore[attr-defined]
                _socks5_reply(client, SOCKS5_REPLY_NOT_ALLOWED)
                return

            isolation = select_stream_isolation_token(
                self.server.session_token, host, self.server.isolation_mode  # type: ignore[attr-defined]
            )
            stage = "opening a Tor-isolated SOCKS stream"
            upstream = socks5_connect(
                host,
                port,
                self.server.tor_socks_socket_path,  # type: ignore[attr-defined]
                isolation,
                timeout=TOR_STREAM_TIMEOUT,
            )
            self.server.track_socket(upstream)  # type: ignore[attr-defined]
            client.settimeout(10.0)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            connected = True
            client.settimeout(None)
            self.server.log_callback("Browser SOCKS5 stream established through Tor.")  # type: ignore[attr-defined]
            _relay_streams(client, upstream)
        except (OSError, ValueError, ConnectionError) as exc:
            if isinstance(exc, TimeoutError):
                message = f"Local SOCKS request timed out while {stage}: {exc}"
            else:
                message = f"Local SOCKS request failed while {stage}: {type(exc).__name__}: {exc}"
            self.server.log_callback(message)  # type: ignore[attr-defined]
            if not connected:
                _socks5_reply(client, SOCKS5_REPLY_GENERAL_FAILURE)
        finally:
            if upstream is not None:
                self.server.untrack_socket(upstream)  # type: ignore[attr-defined]
                try:
                    upstream.close()
                except OSError:
                    pass
            self.server.untrack_socket(client)  # type: ignore[attr-defined]


class NullSocksProxyServer(socketserver.ThreadingTCPServer):
    """Loopback SOCKS5 adapter with bounded fixed workers and a pending queue."""

    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True
    request_queue_size = PROXY_LISTEN_BACKLOG

    def __init__(
        self,
        port: int,
        tor_socks_socket_path: str,
        session_token: str,
        log_callback: Callable[[str], None],
        isolation_mode: str = "session",
    ) -> None:
        if isolation_mode not in {"session", "hostname"}:
            raise ValueError("Invalid SOCKS stream-isolation mode.")
        self.tor_socks_socket_path = tor_socks_socket_path
        self.session_token = session_token
        self.isolation_mode = isolation_mode
        self.log_callback = log_callback
        self._closing = threading.Event()
        self._active_lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        self._admission_log_lock = threading.Lock()
        self._last_admission_log = 0.0
        self._pending_requests: queue.Queue[tuple[socket.socket, Any]] = queue.Queue(
            maxsize=PROXY_PENDING_QUEUE_SIZE
        )
        self._worker_threads: list[threading.Thread] = []
        super().__init__(("127.0.0.1", port), NullSocksProxyHandler)
        for index in range(MAX_PROXY_CLIENTS):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"ProjectNullSocksWorker-{index + 1}",
                daemon=True,
            )
            worker.start()
            self._worker_threads.append(worker)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        """Enqueue promptly; never block the accept loop on a stream slot."""
        if self._closing.is_set():
            self.shutdown_request(request)
            return
        try:
            self._pending_requests.put_nowait((request, client_address))
        except queue.Full:
            self.shutdown_request(request)
            now = time.monotonic()
            with self._admission_log_lock:
                if now - self._last_admission_log >= 10.0:
                    self._last_admission_log = now
                    self.log_callback(
                        f"SOCKS pending queue is full ({PROXY_PENDING_QUEUE_SIZE}); "
                        "one new connection was refused. No direct fallback was attempted."
                    )

    def _worker_loop(self) -> None:
        while not self._closing.is_set():
            try:
                request, client_address = self._pending_requests.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                if self._closing.is_set():
                    self.shutdown_request(request)
                else:
                    super().process_request_thread(request, client_address)
            finally:
                self._pending_requests.task_done()

    def shutdown(self) -> None:
        self._closing.set()
        # Requests not yet assigned to a worker are discarded on disconnect.
        while True:
            try:
                request, _address = self._pending_requests.get_nowait()
            except queue.Empty:
                break
            try:
                self.shutdown_request(request)
            finally:
                self._pending_requests.task_done()
        super().shutdown()

    def server_close(self) -> None:
        self._closing.set()
        super().server_close()
        for worker in self._worker_threads:
            if worker.is_alive() and worker is not threading.current_thread():
                worker.join(timeout=1.0)

    def track_socket(self, sock: socket.socket) -> None:
        with self._active_lock:
            self._active_sockets.add(sock)

    def untrack_socket(self, sock: socket.socket) -> None:
        with self._active_lock:
            self._active_sockets.discard(sock)

    def close_active_sockets(self) -> None:
        with self._active_lock:
            sockets = list(self._active_sockets)
            self._active_sockets.clear()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def local_socks5_connect(
    host: str,
    port: int,
    proxy_address: tuple[str, int],
    timeout: float = 30.0,
) -> socket.socket:
    """Connect through the browser-facing SOCKS5 adapter; no local DNS lookup."""
    host, port = validate_connect_target(host, port)
    sock = socket.create_connection(proxy_address, timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise ConnectionError("Local Project NULL SOCKS5 adapter did not accept no-auth mode.")
        sock.sendall(encode_socks_target(host, port))
        version, reply, reserved, atyp = recv_exact(sock, 4)
        if version != 5 or reserved != 0 or reply != 0:
            raise ConnectionError(f"Local Project NULL SOCKS5 CONNECT failed with reply code {reply}.")
        if atyp == 1:
            recv_exact(sock, 4 + 2)
        elif atyp == 4:
            recv_exact(sock, 16 + 2)
        elif atyp == 3:
            length = recv_exact(sock, 1)[0]
            if length == 0:
                raise ConnectionError("Local Project NULL SOCKS5 adapter returned an invalid bind address.")
            recv_exact(sock, length + 2)
        else:
            raise ConnectionError("Local Project NULL SOCKS5 adapter returned an unknown address type.")
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


# ---------------------------------------------------------------------------
# Tor process / controller
# ---------------------------------------------------------------------------

def request_general_purpose_circuit(controller: Any) -> str:
    """Ask Tor to build a general-purpose circuit using its normal path selection.

    Tor generally builds circuits on demand when a client stream needs one.
    Project NULL checks circuit inventory before opening its proxy, so it must
    explicitly request a readiness circuit instead of waiting forever for a
    circuit that no stream has yet caused Tor to build.
    """
    circuit_id = controller.new_circuit(path=None, purpose="general", await_build=False)
    circuit_id = str(circuit_id)
    if not re.fullmatch(r"[0-9]{1,12}", circuit_id):
        raise RuntimeError("Tor Control returned an invalid circuit identifier.")
    return circuit_id


@dataclass
class CircuitInfo:
    circuit_id: str
    relays: list[tuple[str, str]]  # (fingerprint, nickname)

    @property
    def relay_count(self) -> int:
        return len(self.relays)

    @property
    def exit_name(self) -> str:
        fp, nickname = self.relays[-1]
        return f"{nickname or 'unnamed'} · {fp[-8:]}"

    @property
    def route_text(self) -> str:
        labels = []
        for index, (fingerprint, nickname) in enumerate(self.relays):
            role = ("ENTRY", "MIDDLE", "EXIT")[index] if index < 3 else f"HOP {index + 1}"
            labels.append(f"{role}: {nickname or 'relay'} ({fingerprint[-8:]})")
        return "  |  ".join(labels)


def find_tor_binary() -> Optional[str]:
    """Return only the exact per-user Tor bundle installed by the setup script.

    PATH lookup and PROJECT_NULL_TOR_BINARY overrides are deliberately
    disabled: an arbitrary executable must not become a trusted Tor transport.
    """
    candidate = MANAGED_TOR_BINARY
    try:
        info = candidate.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"Managed Tor path is not a regular non-symlink file: {candidate}")
    if not os.access(candidate, os.X_OK):
        raise PermissionError(f"Managed Tor executable is not executable: {candidate}")
    return str(candidate)


def _verify_directory_chain(path: Path, trusted_root: Path) -> None:
    """Verify every directory from trusted_root through path without following symlinks."""
    root = Path(os.path.abspath(trusted_root))
    target = Path(os.path.abspath(path))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("Managed Tor paths must remain beneath the current user's home directory.") from exc

    current = root
    paths = [current]
    for component in relative.parts:
        current = current / component
        paths.append(current)
    for directory in paths:
        try:
            info = directory.lstat()
        except OSError as exc:
            raise RuntimeError(f"Managed Tor directory is missing: {directory}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"Managed Tor directory must be a real directory, not a symlink: {directory}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise PermissionError(f"Managed Tor directory is not owned by the current user: {directory}")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(f"Managed Tor directory is group/world writable: {directory}")


def _verify_tor_bundle_manifest(
    binary_path: Path,
    manifest_path: Path,
    expected_archive_sha256: str = TOR_EXPERT_ARCHIVE_SHA256,
    trusted_root: Optional[Path] = None,
) -> dict[str, str]:
    """Verify regular files, ownership, directory chain and binary digest.

    The manifest is a local post-install drift check, not a publisher signature.
    A compromised process running as this same user could replace both files.
    """
    binary_path = Path(binary_path)
    manifest_path = Path(manifest_path)
    if trusted_root is not None:
        _verify_directory_chain(binary_path.parent, trusted_root)
        _verify_directory_chain(manifest_path.parent, trusted_root)

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        binary_lstat = binary_path.lstat()
    except OSError as exc:
        raise RuntimeError(f"Managed Tor binary is missing: {binary_path}") from exc
    if stat.S_ISLNK(binary_lstat.st_mode) or not stat.S_ISREG(binary_lstat.st_mode):
        raise RuntimeError("Managed Tor binary must be a regular, non-symlink file.")
    if hasattr(os, "getuid") and binary_lstat.st_uid != os.getuid():
        raise PermissionError("Managed Tor binary is not owned by the current user.")
    if stat.S_IMODE(binary_lstat.st_mode) & 0o022:
        raise PermissionError("Managed Tor binary is writable by group or other users.")
    if not os.access(binary_path, os.X_OK):
        raise PermissionError("Managed Tor binary is not executable.")

    try:
        manifest_lstat = manifest_path.lstat()
    except OSError as exc:
        raise RuntimeError("Tor bundle integrity manifest is missing; rerun setup_macos.sh.") from exc
    if stat.S_ISLNK(manifest_lstat.st_mode) or not stat.S_ISREG(manifest_lstat.st_mode):
        raise RuntimeError("Tor bundle integrity manifest must be a regular, non-symlink file.")
    if hasattr(os, "getuid") and manifest_lstat.st_uid != os.getuid():
        raise PermissionError("Tor bundle integrity manifest is not owned by the current user.")
    if stat.S_IMODE(manifest_lstat.st_mode) & 0o077:
        raise PermissionError("Tor bundle integrity manifest must not be accessible by group or other users.")
    if manifest_lstat.st_size > 16_384:
        raise RuntimeError("Tor bundle integrity manifest is unexpectedly large.")

    flags = os.O_RDONLY | nofollow | cloexec
    manifest_fd = os.open(manifest_path, flags)
    try:
        manifest_info = os.fstat(manifest_fd)
        if (not stat.S_ISREG(manifest_info.st_mode)
                or (manifest_info.st_dev, manifest_info.st_ino) != (manifest_lstat.st_dev, manifest_lstat.st_ino)):
            raise RuntimeError("Tor bundle manifest changed during verification.")
        with os.fdopen(manifest_fd, "r", encoding="utf-8", closefd=False) as stream:
            manifest = json.load(stream)
    finally:
        os.close(manifest_fd)

    if not isinstance(manifest, dict):
        raise RuntimeError("Tor bundle integrity manifest is malformed.")
    if manifest.get("bundle_version") != TOR_EXPERT_BUNDLE_VERSION:
        raise RuntimeError("Tor bundle version does not match the pinned release.")
    if manifest.get("archive_sha256") != expected_archive_sha256:
        raise RuntimeError("Tor bundle archive digest in the manifest is not the pinned digest.")
    expected_binary_hash = manifest.get("binary_sha256")
    if not isinstance(expected_binary_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_binary_hash):
        raise RuntimeError("Tor binary digest in the manifest is invalid.")
    if manifest.get("binary_relative_path") != "tor/tor":
        raise RuntimeError("Tor binary path in the manifest is invalid.")

    binary_fd = os.open(binary_path, flags)
    try:
        binary_info = os.fstat(binary_fd)
        if (not stat.S_ISREG(binary_info.st_mode)
                or (binary_info.st_dev, binary_info.st_ino) != (binary_lstat.st_dev, binary_lstat.st_ino)):
            raise RuntimeError("Managed Tor binary changed during verification.")
        digest = hashlib.sha256()
        while True:
            block = os.read(binary_fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(binary_fd)
    if not hmac.compare_digest(digest.hexdigest(), expected_binary_hash):
        raise RuntimeError("Managed Tor binary SHA-256 does not match the verified installation manifest.")
    return {str(key): str(value) for key, value in manifest.items()}


def verify_managed_tor_binary(binary_path: Path) -> dict[str, str]:
    """Only allow the pinned, locally managed Tor Expert Bundle installation."""
    supplied = Path(os.path.abspath(binary_path))
    expected = Path(os.path.abspath(MANAGED_TOR_BINARY))
    if supplied != expected:
        raise RuntimeError(
            "Unmanaged Tor binaries are disabled in this release. Run setup_macos.sh "
            "to install and verify the pinned Tor Expert Bundle."
        )
    return _verify_tor_bundle_manifest(
        supplied, MANAGED_TOR_MANIFEST, trusted_root=Path.home()
    )


def port_is_available(host: str, port: int) -> bool:
    """Return whether a TCP port can be safely rebound.

    First detect a live listener. Then use SO_REUSEADDR for the bind probe so
    harmless TCP TIME_WAIT sockets left by a previous clean Tor shutdown do
    not make the port appear occupied. An active listener still fails the
    connection probe and/or the bind operation; we never attach to it.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.35)
        if probe.connect_ex((host, port)) == 0:
            return False
    except OSError:
        # Continue to the bind test; it is the authoritative availability test.
        pass
    finally:
        probe.close()

    test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        test.close()


def _best_effort_controller_close(controller: Any) -> None:
    try:
        controller.close()
    except Exception:
        pass


class TorNetwork:
    def __init__(
        self,
        config: AppConfig,
        identity_manager: IdentityManager,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.config = config
        self.identity_manager = identity_manager
        self.log_callback = log_callback or (lambda _message: None)
        self.process: Optional[subprocess.Popen[str]] = None
        self.controller: Any = None
        self.proxy: Optional[NullSocksProxyServer] = None
        self.proxy_thread: Optional[threading.Thread] = None
        self.tor_log_thread: Optional[threading.Thread] = None
        # Retain recent Tor output so unexpected exits include their real cause.
        self.tor_log_tail: deque[str] = deque(maxlen=100)
        self._connect_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._closed_event = threading.Event()
        self._stopping = False
        self.last_circuit: Optional[CircuitInfo] = None
        self.tor_binary: Optional[str] = None

    @property
    def is_process_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    @property
    def is_proxy_alive(self) -> bool:
        return self.proxy_thread is not None and self.proxy_thread.is_alive()

    def _log(self, message: str) -> None:
        self.log_callback(message)

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set() or self._closed_event.is_set():
            raise RuntimeError("Project NULL connection was cancelled; no new traffic will be accepted.")

    def _register_process(self, process: subprocess.Popen[str]) -> None:
        """Publish a newly spawned Tor process atomically with cancellation."""
        with self._lifecycle_lock:
            if self._cancel_event.is_set() or self._closed_event.is_set():
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                raise RuntimeError("Project NULL connection was cancelled during Tor startup.")
            self.process = process

    def _register_controller(self, controller: Any) -> None:
        with self._lifecycle_lock:
            if self._cancel_event.is_set() or self._closed_event.is_set():
                try:
                    controller.close()
                except Exception:
                    pass
                raise RuntimeError("Project NULL connection was cancelled during Tor Control startup.")
            self.controller = controller

    def _register_proxy(self, proxy: NullSocksProxyServer) -> None:
        """Start and publish the listener as one lifecycle-locked operation."""
        thread = threading.Thread(target=proxy.serve_forever, name="ProjectNullProxy", daemon=True)
        with self._lifecycle_lock:
            if self._cancel_event.is_set() or self._closed_event.is_set():
                proxy.server_close()
                raise RuntimeError("Project NULL connection was cancelled before proxy startup.")
            self.proxy = proxy
            self.proxy_thread = thread
            try:
                thread.start()
            except Exception:
                self.proxy = None
                self.proxy_thread = None
                proxy.server_close()
                raise

    def _torrc_lines(self) -> tuple[str, ...]:
        return (
            f"DataDirectory {_tor_quote(TOR_DATA_DIR)}",
            f"SocksPort unix:{SOCKS_SOCKET_PATH} IsolateSOCKSAuth",
            "UnixSocksGroupWritable 0",
            "SafeSocks 1",
            "ClientRejectInternalAddresses 1",
            # ControlPort supports unix:path directly. Avoid ControlSocket's
            # path tokenization ambiguity and keep this path whitespace-free.
            f"ControlPort unix:{CONTROL_SOCKET_PATH}",
            "ControlSocketsGroupWritable 0",
            "CookieAuthentication 1",
            f"__OwningControllerProcess {os.getpid()}",
            "ClientOnly 1",
            "SafeLogging 1",
            "Log notice stdout",
        )
    def _write_torrc(self) -> Path:
        ensure_private_directory(APP_DIR)
        ensure_private_directory(TOR_DATA_DIR)
        ensure_private_runtime_directory()
        torrc = APP_DIR / "torrc-project-null"
        content = "\n".join((*self._torrc_lines(), ""))
        write_private_file(torrc, content)
        return torrc

    def _verify_tor_configuration(self, tor_binary: str, torrc: Path) -> None:
        """Ask the exact managed Tor binary to parse the generated torrc first."""
        try:
            result = subprocess.run(
                [tor_binary, "--verify-config", "-f", str(torrc)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Tor configuration preflight exceeded 20 seconds.") from exc
        output = (result.stdout or "").strip()
        bad = re.search(
            r"(?:unrecognized\s+.*option|skipping obsolete configuration option|\[err\]|\[fatal\])",
            output,
            re.IGNORECASE,
        )
        if result.returncode != 0 or bad:
            detail = output[-2000:] if output else "Tor returned no diagnostic output."
            raise RuntimeError(
                "Tor rejected or warned about the generated configuration; refusing to start.\n" + detail
            )
        self._log("Tor configuration passed the Tor binary's --verify-config preflight.")

    def _read_tor_logs(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        try:
            for line in process.stdout:
                clean = line.rstrip()
                if not clean:
                    continue
                self.tor_log_tail.append(clean)
                if self._stopping:
                    continue
                match = re.search(r"Bootstrapped\s+(\d+)%", clean)
                lower = clean.lower()
                if match:
                    self._log(f"Tor bootstrap: {match.group(1)}%")
                elif "opening socks listener" in lower:
                    self._log("Tor private SOCKS Unix socket opened.")
                elif "opening control listener" in lower:
                    self._log("Tor private Control Unix socket opened.")
                elif any(token in lower for token in ("[warn]", "[err]", "[fatal]", "warning:", "error:")):
                    # Surface actual Tor warnings/errors instead of hiding them.
                    self._log("Tor diagnostic: " + clean[-700:])
        except (OSError, ValueError):
            pass

    def _unexpected_exit_message(self, context: str) -> str:
        """Build an actionable error from the Tor exit code and captured logs."""
        process = self.process
        if self.tor_log_thread is not None and self.tor_log_thread.is_alive():
            self.tor_log_thread.join(timeout=1.5)
        code = process.poll() if process is not None else None
        lines = list(self.tor_log_tail)
        important = [
            line for line in lines
            if any(token in line.lower() for token in (
                "[warn]", "[err]", "[fatal]", "warning:", "error:",
                "failed", "failure", "no space", "permission denied", "cannot ",
            ))
        ]
        chosen = important[-12:] if important else lines[-12:]
        detail = "\n".join(chosen) if chosen else "Tor produced no captured diagnostic output."
        return (
            f"Tor stopped unexpectedly {context} (exit code {code}). "
            f"Last Tor output:\n{detail}"
        )

    def _bounded_controller_call(
        self,
        controller: Any,
        operation: Callable[[], Any],
        *,
        timeout: float,
        label: str,
        on_timeout: Optional[Callable[[], None]] = None,
        on_error: Optional[Callable[[], None]] = None,
    ) -> Any:
        """Run a Stem Control request with a hard caller-side deadline.

        Stem 1.8.x performs synchronous Control reads without a per-request
        timeout. A daemon worker bounds the caller; on timeout the Controller
        is closed asynchronously and the owning Tor lifecycle is torn down.
        The worker is daemonized because Python cannot safely kill a blocked
        thread. Terminating the managed Tor process closes the peer socket and
        normally releases the Stem reader/command wait.
        """
        finished = threading.Event()
        outcome: list[tuple[bool, Any]] = []

        def invoke() -> None:
            try:
                outcome.append((True, operation()))
            except BaseException as exc:
                outcome.append((False, exc))
            finally:
                finished.set()

        worker = threading.Thread(
            target=invoke,
            name=f"ProjectNullControl-{label}",
            daemon=True,
        )
        worker.start()
        if not finished.wait(timeout):
            controller_is_registered = getattr(self, "controller", None) is controller
            if on_timeout is not None:
                try:
                    on_timeout()
                except Exception:
                    pass
            if on_timeout is None or not controller_is_registered:
                # The caller may still be authenticating a not-yet-registered
                # Controller, so normal network teardown cannot own its close.
                closer = threading.Thread(
                    target=lambda: _best_effort_controller_close(controller),
                    name="ProjectNullControlCloser",
                    daemon=True,
                )
                closer.start()
            finished.wait(2.0)
            raise TimeoutError(
                f"Tor Control {label} operation exceeded its {timeout:.1f}s deadline; "
                "the session was stopped fail-closed."
            )
        succeeded, value = outcome[0]
        if not succeeded:
            if on_error is not None:
                try:
                    on_error()
                except Exception:
                    pass
            raise value
        return value

    def _connect_controller(self, deadline: float) -> Any:
        try:
            from stem.control import Controller
        except ImportError as exc:
            raise RuntimeError("Stem is required for Tor control. Install it with: python -m pip install stem") from exc
        last_error: Optional[Exception] = None
        while time.monotonic() < deadline:
            self._check_cancelled()
            if not self.is_process_alive:
                code = self.process.returncode if self.process else "unknown"
                raise RuntimeError(f"Tor exited during startup (code {code}). Check the event log and Tor installation.")
            controller = None
            try:
                controller = Controller.from_socket_file(path=str(CONTROL_SOCKET_PATH))
                self._bounded_controller_call(
                    controller,
                    controller.authenticate,
                    timeout=min(8.0, max(0.1, deadline - time.monotonic())),
                    label="authentication",
                    on_timeout=self.disconnect,
                )  # CookieAuthentication; no open/no-auth control port.
                self._check_cancelled()
                return controller
            except Exception as exc:
                last_error = exc
                if controller is not None and controller is not self.controller:
                    closer = threading.Thread(
                        target=lambda: _best_effort_controller_close(controller),
                        name="ProjectNullControlRetryCloser",
                        daemon=True,
                    )
                    closer.start()
                self._check_cancelled()
                time.sleep(0.5)
        raise TimeoutError(f"Timed out connecting to Tor Control socket: {last_error}")

    def _bootstrap_progress(self, controller: Any) -> int:
        status = self._bounded_controller_call(
            controller,
            lambda: controller.get_info("status/bootstrap-phase"),
            timeout=6.0,
            label="bootstrap status",
            on_timeout=self.disconnect,
            on_error=self.disconnect,
        )
        match = re.search(r"PROGRESS=(\d+)", status)
        return int(match.group(1)) if match else 0

    def _built_general_circuit(self, controller: Any) -> Optional[CircuitInfo]:
        from stem import CircStatus
        circuits = self._bounded_controller_call(
            controller,
            controller.get_circuits,
            timeout=8.0,
            label="circuit inspection",
            on_timeout=self.disconnect,
            on_error=self.disconnect,
        )
        candidates = [
            c for c in circuits
            if c.status == CircStatus.BUILT and c.purpose == "GENERAL" and len(c.path) >= 3
        ]
        if not candidates:
            return None
        # Prefer the shortest, standard three-hop general circuit.
        chosen = min(candidates, key=lambda c: (len(c.path), int(c.id)))
        return CircuitInfo(str(chosen.id), [(fp, nick) for fp, nick in chosen.path])

    def _requested_circuit_state(self, controller: Any, circuit_id: str) -> Optional[tuple[str, int, str]]:
        circuit = self._bounded_controller_call(
            controller,
            lambda: controller.get_circuit(circuit_id, default=None),
            timeout=6.0,
            label="requested circuit status",
            on_timeout=self.disconnect,
            on_error=self.disconnect,
        )
        if circuit is None:
            return None
        reason = str(getattr(circuit, "reason", "") or getattr(circuit, "remote_reason", "") or "")
        return str(circuit.status), len(circuit.path), reason

    def connect(self) -> CircuitInfo:
        with self._connect_lock:
            if self._closed_event.is_set():
                raise RuntimeError("This Project NULL instance has been shut down and cannot reconnect.")
            self._cancel_event.clear()
            self._stopping = False
            if self.is_process_alive or self.proxy is not None:
                raise RuntimeError("Project NULL is already running.")
            self._check_cancelled()
            self.config.validate()
            tor_binary = find_tor_binary()
            if not tor_binary:
                raise RuntimeError("Tor executable not found. Run ./setup_macos.sh to install the verified per-user Tor bundle.")
            self.tor_binary = tor_binary
            bundle_manifest = verify_managed_tor_binary(Path(tor_binary))
            self._log(
                "Tor executable SHA-256 matches the local installation manifest; "
                "the manifest records the pinned upstream archive digest "
                + bundle_manifest["archive_sha256"][:16] + "…"
            )
            self._log(f"Tor executable path: {tor_binary}")
            # Fail before opening listeners if the selected binary cannot run.
            # This also exposes accidental selection of an old PATH binary.
            try:
                version_probe = subprocess.run(
                    [tor_binary, "--version"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=12,
                    check=False,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Could not execute selected Tor binary {tor_binary}: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            version_text = (version_probe.stdout or "").strip()
            if version_probe.returncode != 0:
                raise RuntimeError(
                    f"Selected Tor binary failed its --version check "
                    f"(exit code {version_probe.returncode}). Output: "
                    f"{version_text[-1200:] or '<no output>'}"
                )
            version_match = re.search(
                r"Tor version\s+(\d+)\.(\d+)\.(\d+)\.(\d+)",
                version_text,
            )
            if not version_match:
                raise RuntimeError(
                    "Could not parse the selected Tor version. Use Tor 0.4.9.15 or newer."
                )
            tor_version = tuple(int(part) for part in version_match.groups())
            if tor_version < MIN_TOR_VERSION:
                raise RuntimeError(
                    f"Tor {'.'.join(map(str, tor_version))} is too old for current "
                    f"Tor network requirements. Install Tor {'.'.join(map(str, MIN_TOR_VERSION))} or newer."
                )
            self._check_cancelled()
            version_line = next(
                (line.strip() for line in version_text.splitlines() if line.strip()),
                "Tor version unknown",
            )
            self._log(version_line)
            if sys.platform == "darwin":
                # Setup verifies the official Expert Bundle archive digest and
                # may locally ad-hoc-sign its Tor executable for macOS launch.
                # This check detects post-install mutation; it is not publisher
                # authentication or Apple notarization.
                signature_check = subprocess.run(
                    ["/usr/bin/codesign", "--verify", "--strict", tor_binary],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=12,
                    check=False,
                )
                if signature_check.returncode != 0:
                    raise RuntimeError(
                        "macOS code-signature integrity check failed for the selected Tor binary. "
                        "Run setup_macos.sh to reinstall the checksum-verified Tor bundle."
                    )
            if not port_is_available("127.0.0.1", self.config.proxy_port):
                raise RuntimeError(
                    f"Project NULL SOCKS5 proxy port 127.0.0.1:{self.config.proxy_port} is already in use. "
                    "Change it in Settings; refusing to attach to an unknown service."
                )

            ensure_private_directory(APP_DIR)
            ensure_private_directory(TOR_DATA_DIR)
            ensure_private_runtime_directory()
            prepare_private_unix_socket_path(SOCKS_SOCKET_PATH)
            prepare_private_unix_socket_path(CONTROL_SOCKET_PATH)
            torrc = self._write_torrc()
            self._verify_tor_configuration(tor_binary, torrc)
            self._check_cancelled()
            self._log(f"Starting Tor client: {Path(tor_binary).name}")
            try:
                process = subprocess.Popen(
                    [tor_binary, "-f", str(torrc)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=str(APP_DIR),
                    close_fds=True,
                )
                self._register_process(process)
                self.tor_log_thread = threading.Thread(target=self._read_tor_logs, daemon=True)
                self.tor_log_thread.start()
                deadline = time.monotonic() + 35
                self._log(f"Waiting for authenticated Tor Control socket at {CONTROL_SOCKET_PATH}.")
                controller = self._connect_controller(deadline)
                self._register_controller(controller)
                self._check_cancelled()
                self._log("Tor Control Unix socket authenticated with cookie authentication.")
                for socket_path in (SOCKS_SOCKET_PATH, CONTROL_SOCKET_PATH):
                    info = socket_path.lstat()
                    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
                        raise RuntimeError(f"Tor did not create a regular Unix socket at the expected path: {socket_path}")
                    if hasattr(os, "getuid") and info.st_uid != os.getuid():
                        raise PermissionError(f"Tor socket is not owned by the current user: {socket_path}")
                    os.chmod(socket_path, 0o600)
                cookie_path = TOR_DATA_DIR / "control_auth_cookie"
                cookie_info = cookie_path.lstat()
                if stat.S_ISLNK(cookie_info.st_mode) or not stat.S_ISREG(cookie_info.st_mode):
                    raise RuntimeError("Tor Control authentication cookie is not a regular file.")
                if hasattr(os, "getuid") and cookie_info.st_uid != os.getuid():
                    raise PermissionError("Tor Control authentication cookie is not owned by the current user.")
                os.chmod(cookie_path, 0o600)

                bootstrap_deadline = time.monotonic() + self.config.bootstrap_timeout
                last_progress = -1
                self._log("Tor Control channel is authenticated; querying bootstrap status.")
                while time.monotonic() < bootstrap_deadline:
                    self._check_cancelled()
                    if not self.is_process_alive:
                        raise RuntimeError(self._unexpected_exit_message("during bootstrap"))
                    progress = self._bootstrap_progress(self.controller)
                    if progress != last_progress:
                        self._log(f"Tor bootstrap status: {progress}%")
                        last_progress = progress
                    if progress >= 100:
                        break
                    time.sleep(1)
                else:
                    raise TimeoutError("Tor did not finish bootstrapping before the configured timeout.")

                self._log("Tor network bootstrap completed (Control protocol reports 100%).")
                self._log("Inspecting Tor's circuit inventory for a BUILT three-hop GENERAL circuit.")
                circuit_deadline = time.monotonic() + self.config.circuit_timeout
                circuit = self._built_general_circuit(self.controller)
                requested_circuit_id: Optional[str] = None
                if circuit is None:
                    # Tor normally creates circuits lazily when a SOCKS stream
                    # needs one. Waiting for an existing circuit before starting
                    # the proxy is a startup deadlock. Request an unattached
                    # GENERAL circuit through authenticated Control instead.
                    self._log("No built GENERAL circuit exists yet. Asking Tor Control to build one using Tor's automatic path selection.")
                    requested_circuit_id = self._bounded_controller_call(
                        self.controller,
                        lambda: request_general_purpose_circuit(self.controller),
                        timeout=8.0,
                        label="general-purpose circuit request",
                        on_timeout=self.disconnect,
                        on_error=self.disconnect,
                    )
                    self._log(f"Tor accepted general-purpose circuit build request {requested_circuit_id}; waiting for BUILT status.")
                last_circuit_notice = 0.0
                while circuit is None and time.monotonic() < circuit_deadline:
                    self._check_cancelled()
                    if not self.is_process_alive:
                        raise RuntimeError(self._unexpected_exit_message("while building a general-purpose circuit"))
                    now = time.monotonic()
                    if now - last_circuit_notice >= 10:
                        suffix = ""
                        if requested_circuit_id:
                            state = self._requested_circuit_state(self.controller, requested_circuit_id)
                            if state is None:
                                suffix = f"; requested circuit {requested_circuit_id} is no longer listed"
                            else:
                                status, hops, reason = state
                                suffix = f"; requested circuit {requested_circuit_id}: {status}, {hops}/3 hops"
                                if reason:
                                    suffix += f", reason={reason}"
                                if status in ("FAILED", "CLOSED"):
                                    raise RuntimeError(
                                        f"Tor failed to build requested GENERAL circuit {requested_circuit_id}: "
                                        f"status={status}, reason={reason or 'not provided'}. No traffic was sent directly."
                                    )
                        self._log("Tor has not yet reported a BUILT three-hop GENERAL circuit" + suffix + "; waiting without direct fallback.")
                        last_circuit_notice = now
                    time.sleep(1)
                    circuit = self._built_general_circuit(self.controller)
                if circuit is None or circuit.relay_count < 3:
                    raise TimeoutError(
                        "Tor bootstrapped, but did not build a three-hop GENERAL circuit within "
                        f"{self.config.circuit_timeout} seconds. "
                        f"Control request ID: {requested_circuit_id or 'not issued'}. "
                        "Check Tor's relay connectivity and the preceding Tor diagnostic messages; no traffic was sent directly."
                    )

                identity = self.identity_manager.current
                if identity is None:
                    raise RuntimeError("No active local session context.")
                proxy = NullSocksProxyServer(
                    self.config.proxy_port,
                    str(SOCKS_SOCKET_PATH),
                    identity.isolation_token,
                    self._log,
                    self.config.stream_isolation,
                )
                self._register_proxy(proxy)
                self._check_cancelled()
                self.last_circuit = circuit
                self._log(f"Tor reports an available general-purpose circuit: {circuit.route_text}")
                if self.config.stream_isolation == "session":
                    self._log("Session isolation is active: streams from this browser session may share Tor circuits; the displayed route is not a guarantee for every stream.")
                else:
                    self._log("Hostname isolation is active: different hostnames may use different Tor circuits; the displayed route is not a guarantee for every stream.")
                self._log(f"Unauthenticated local SOCKS5 proxy listening on 127.0.0.1:{self.config.proxy_port} (loopback only).")
                self._log(
                    f"SOCKS capacity: {MAX_PROXY_CLIENTS} fixed workers; "
                    f"pending queue {PROXY_PENDING_QUEUE_SIZE}, listen backlog {PROXY_LISTEN_BACKLOG}; "
                    f"process file-descriptor soft limit {PROCESS_NOFILE_SOFT_LIMIT}."
                )
                if self.config.stream_isolation == "session":
                    self._log("Stream isolation mode: session-wide credential; destinations may share Tor circuits for faster page loading.")
                else:
                    self._log("Stream isolation mode: per-host credentials; different hostnames use separate Tor isolation groups and may load more slowly.")
                self._log("Browser-to-proxy authentication is disabled for Chrome compatibility; any local process can use this listener.")
                self._log("Tor SOCKS still uses private Unix-socket authentication; isolation scope is " + self.config.stream_isolation + ".")
                self._log("Ready for explicitly configured applications. This is not a system-wide tunnel.")
                return circuit
            except Exception:
                self.disconnect()
                raise

    def refresh_circuit(self) -> Optional[CircuitInfo]:
        if self.controller is None:
            return None
        circuit = self._built_general_circuit(self.controller)
        if circuit:
            self.last_circuit = circuit
        return circuit

    def rotate_session(self, identity: SessionContext) -> None:
        if self.proxy is not None:
            self.proxy.session_token = identity.isolation_token
        self._log(f"Session identity rotated: {identity.session_id}. New proxied streams use a new Tor isolation value.")

    @staticmethod
    def _verified_tls_context() -> ssl.SSLContext:
        """Create a verifying TLS context, preferring certifi when installed."""
        try:
            import certifi
        except ImportError:
            return ssl.create_default_context()
        return ssl.create_default_context(cafile=certifi.where())

    def external_tor_check(self) -> tuple[bool, Optional[str], float, str]:
        """Explicit opt-in check through the local SOCKS5 proxy, never direct."""
        started = time.perf_counter()
        tls_socket: Optional[ssl.SSLSocket] = None
        try:
            raw = local_socks5_connect(
                "check.torproject.org", 443,
                ("127.0.0.1", self.config.proxy_port), timeout=30.0,
            )
            tls_socket = self._verified_tls_context().wrap_socket(
                raw, server_hostname="check.torproject.org"
            )
            request = (
                "GET /api/ip HTTP/1.1\r\n"
                "Host: check.torproject.org\r\n"
                "Accept: application/json\r\n"
                "User-Agent: Project-NULL-Diagnostics/1.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_socket.sendall(request)
            response = http.client.HTTPResponse(tls_socket)
            response.begin()
            body = response.read(65536)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if response.status != 200:
                return False, None, elapsed_ms, f"Tor check endpoint returned HTTP {response.status}."
            parsed = json.loads(body.decode("utf-8"))
            observed_ip = str(parsed.get("IP")) if parsed.get("IP") else None
            is_tor = parsed.get("IsTor") is True
            if not is_tor:
                return False, observed_ip, elapsed_ms, "External endpoint did not identify this exit as a Tor exit."
            return True, observed_ip, elapsed_ms, "External endpoint confirmed a Tor exit IP."
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return False, None, elapsed_ms, f"External route check failed: {type(exc).__name__}: {exc}"
        finally:
            if tls_socket is not None:
                try:
                    tls_socket.close()
                except Exception:
                    pass

    def diagnostics(self, include_external_ip: bool) -> dict[str, Any]:
        results: dict[str, Any] = {
            "tor_process": self.is_process_alive,
            "local_proxy": self.is_proxy_alive,
            "bootstrap_percent": self._bootstrap_progress(self.controller) if self.controller else 0,
            "circuit": self.refresh_circuit(),
            "dns_remote_for_proxy": True,
            "tor_socks_transport": "private Unix-domain socket (0600 in per-user 0700 runtime directory)",
            "tor_control_transport": "private Unix-domain socket with cookie authentication (per-user 0700 runtime directory)",
            "local_proxy_authentication": "none; loopback-only adapter, any local process can use it",
            "system_dns_changed": False,
            "system_wide_tunnel": False,
            "browser_antifingerprinting": False,
            "proxy_policy": "hostname-based SOCKS5 CONNECT to TCP/443 only; TLS is not inspected",
            "stream_isolation": self.config.stream_isolation,
            "tls_enforcement": False,
            "external_check_requested": include_external_ip,
            "external_tor_confirmed": None,
            "observed_exit_ip": None,
            "latency_ms": None,
            "external_message": "Not run; external IP check is disabled." if not include_external_ip else "Pending",
        }
        if include_external_ip:
            ok, observed_ip, latency, detail = self.external_tor_check()
            results.update({
                "external_tor_confirmed": ok,
                "observed_exit_ip": observed_ip,
                "latency_ms": latency,
                "external_message": detail,
            })
        return results

    def disconnect(self) -> None:
        # Cancellation is visible before resources are detached.  Registration
        # helpers check the same event under this lock, closing the race where
        # shutdown previously happened just before Popen()/listener startup.
        with self._lifecycle_lock:
            self._cancel_event.set()
            self._stopping = True
            proxy, self.proxy = self.proxy, None
            proxy_thread, self.proxy_thread = self.proxy_thread, None
            controller, self.controller = self.controller, None
            process, self.process = self.process, None
        if proxy is not None:
            try:
                proxy.shutdown()
                proxy.close_active_sockets()
                proxy.server_close()
            except Exception:
                pass
            if proxy_thread is not None and proxy_thread.is_alive():
                proxy_thread.join(timeout=3)
        # Terminate the managed Tor peer before joining Stem's Control reader.
        # This forces blocked Control reads to observe peer closure. Do not use
        # controller.signal(SHUTDOWN): it is another unbounded Control roundtrip.
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception:
                    pass
            except Exception:
                pass
        if controller is not None:
            closer = threading.Thread(
                target=lambda: _best_effort_controller_close(controller),
                name="ProjectNullControlShutdown",
                daemon=True,
            )
            closer.start()
            closer.join(timeout=1.5)
        if self.tor_log_thread is not None and self.tor_log_thread.is_alive():
            self.tor_log_thread.join(timeout=2)
        self.last_circuit = None
        # Remove only our own Unix socket files after Tor has exited.
        for path in (SOCKS_SOCKET_PATH, CONTROL_SOCKET_PATH):
            try:
                if path.exists() and stat.S_ISSOCK(path.lstat().st_mode) and (
                    not hasattr(os, "getuid") or path.lstat().st_uid == os.getuid()
                ):
                    path.unlink()
            except OSError:
                pass

    def shutdown(self) -> None:
        """Permanently close this instance and wait for in-flight connect work."""
        self._closed_event.set()
        self.disconnect()
        # connect() checks cancellation in every wait loop and before publishing
        # each resource.  Acquiring the lock waits for that worker to unwind.
        with self._connect_lock:
            pass
        # A second idempotent cleanup catches any object that was published
        # immediately before the first disconnect detached its resources.
        self.disconnect()


# ---------------------------------------------------------------------------
# Self-test suite
# ---------------------------------------------------------------------------

class SelfTest:
    def __init__(self, progress: bool = False) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.lines: list[str] = []
        self.progress = progress

    def check(self, name: str, callback: Callable[[], None]) -> None:
        # Stream progress during CLI/setup runs. A blocked test must not look
        # like an installer hang with no indication of the last active check.
        if self.progress:
            print(f"RUNNING: {name}", flush=True)
        try:
            callback()
            self.passed += 1
            self.lines.append(f"PASS  {name}")
        except Exception as exc:
            self.failed += 1
            self.lines.append(f"FAIL  {name}: {type(exc).__name__}: {exc}")
        if self.progress:
            print(self.lines[-1], flush=True)

    def skip(self, name: str, detail: str) -> None:
        self.skipped += 1
        self.lines.append(f"SKIP  {name}: {detail}")
        if self.progress:
            print(self.lines[-1], flush=True)

    def report(self) -> int:
        print(f"\nPROJECT NULL {APP_VERSION} — SELF TEST")
        print("=" * 64)
        # Progress-mode checks have already been printed as they ran.
        if not self.progress:
            for line in self.lines:
                print(line)
        print("-" * 64)
        print(f"Passed: {self.passed}   Failed: {self.failed}   Skipped: {self.skipped}")
        return 1 if self.failed else 0


def run_self_tests(live: bool = False) -> int:
    suite = SelfTest(progress=True)
    suite.check("Ephemeral session context generation", _test_identity_generation)
    suite.check("Session isolation secret rotation", _test_identity_rotation)
    suite.check("Per-host SOCKS isolation derivation", _test_hostname_isolation)
    suite.check("Session versus hostname stream-isolation modes", _test_stream_isolation_modes)
    suite.check("Strict configuration type and range validation", _test_config_validation)
    suite.check("Remote-DNS SOCKS target encoding", _test_remote_dns_encoding)
    suite.check("SOCKS5 destination allow-list", _test_connect_policy)
    suite.check("Loopback/private destination rejection", _test_internal_target_rejection)
    suite.check("Legacy numeric IPv4 spelling rejection", _test_legacy_ipv4_rejection)
    suite.check("Private space-free Tor runtime directory", _test_private_runtime_directory)
    suite.check("Tor private Unix-socket configuration and ControlPort syntax", _test_safe_tor_configuration)
    suite.check("Pinned Tor bundle manifest, file identity and binary hash", _test_tor_bundle_manifest)
    suite.check("Arbitrary Tor binary override rejection", _test_managed_tor_only)
    suite.check("Managed Tor parent-directory symlink and write-permission rejection", _test_tor_directory_chain)
    suite.check("Private application directory parent and symlink safety", _test_private_directory_parent_safety)
    suite.check("Race-resistant nested private directory creation", _test_private_directory_nested_creation)
    suite.check("Explicit Tor GENERAL circuit build request", _test_general_circuit_request)
    suite.check("Private Unix-socket path safety", _test_private_unix_socket_path_safety)
    suite.check("Atomic private-file replacement", _test_atomic_private_file_write)
    suite.check("Config loader rejects type coercion", _test_config_store_rejects_coercion)
    suite.check("No session/proxy secrets persisted in config", _test_config_does_not_persist_secrets)
    suite.check("Chrome launch uses native SOCKS5 without auth or extension", _test_chrome_launch_policy)
    suite.check("Fail-closed SOCKS Unix-socket and transport-level policy enforcement", _test_fail_closed)
    suite.check("Loopback-only unauthenticated SOCKS5 bind policy", _test_proxy_bind_policy)
    suite.check("Raised per-process descriptor budget and bounded SOCKS worker queue", _test_proxy_concurrency)
    suite.check("Bounded worker queue accepts Chrome bursts without blocking the accept loop", _test_proxy_admission_backpressure)
    suite.check("Unauthenticated local SOCKS5-to-isolated-Tor forwarding (fake-upstream unit test)", _test_proxy_forwarding)
    suite.check("Local SOCKS5 client handshake and proxy-side DNS policy", _test_local_socks5_client)
    suite.check("SOCKS5 rejects clients that do not offer no-auth mode", _test_local_socks5_rejects_unsupported_methods)
    suite.check("SOCKS5 rejects IP-literal destinations", _test_local_socks5_rejects_ip_literals)
    suite.check("SOCKS5 rejects non-443 destinations", _test_local_socks5_rejects_non_443)
    suite.check("SOCKS5 fails closed when Tor upstream is unavailable", _test_local_socks5_fails_closed)
    suite.check("Shutdown cancellation state", _test_shutdown_cancellation)
    suite.check("Bounded Tor Control operations stop on timeout", _test_bounded_control_call_timeout)
    suite.check("Bounded Tor process shutdown path", _test_bounded_shutdown)
    suite.check("Dashboard buttons retain high-contrast text across states", _test_dashboard_button_contrast)
    if live:
        try:
            config = ConfigStore.load()
            identity = IdentityManager()
            network = TorNetwork(config, identity, lambda msg: print("  [live] " + msg))
            try:
                circuit = network.connect()
                if circuit.relay_count < 3:
                    raise AssertionError("Live route did not use at least three relays.")
                diag = network.diagnostics(include_external_ip=True)
                if not diag["external_tor_confirmed"]:
                    raise AssertionError(diag["external_message"])
                if not diag["observed_exit_ip"]:
                    raise AssertionError("Tor check endpoint did not return an exit IP.")
                suite.check("Live Tor relay availability (3-hop circuit)", lambda: None)
                suite.check("External website sees a Tor exit IP", lambda: None)
                suite.check("SOCKS5 hostname sent as domain for Tor-side resolution", lambda: _test_remote_dns_encoding())
            finally:
                network.disconnect()
        except Exception as exc:
            suite.check("Live Tor relay availability and routed IP check", lambda: (_ for _ in ()).throw(exc))
    else:
        suite.skip(
            "Live relay availability",
            "not tested offline; run `./start.command --self-test-live` to bootstrap Tor and verify a real three-hop circuit.",
        )
    return suite.report()


def _test_identity_generation() -> None:
    identity = IdentityManager().current
    assert identity is not None
    assert len(identity.session_id) == 24
    assert len(identity.isolation_token) == 64
    assert "isolation_token=<redacted>" in repr(identity)


def _test_identity_rotation() -> None:
    manager = IdentityManager()
    first = manager.current
    second = manager.rotate()
    assert first is not None and second is not None
    assert first.session_id != second.session_id
    assert first.isolation_token != second.isolation_token


def _test_hostname_isolation() -> None:
    session = secrets.token_hex(32)
    first = derive_stream_isolation_token(session, "www.example.com")
    same_host = derive_stream_isolation_token(session, "www.example.com.")
    other_host = derive_stream_isolation_token(session, "cdn.example.net")
    next_session = derive_stream_isolation_token(secrets.token_hex(32), "www.example.com")
    assert len(first) == 64
    assert first == same_host
    assert first != other_host
    assert first != next_session


def _test_stream_isolation_modes() -> None:
    session = secrets.token_hex(32)
    # Compatibility mode deliberately reuses the same Tor isolation credential
    # across hostnames in one app session so Tor can reuse circuits.
    assert select_stream_isolation_token(session, "www.example.com", "session") == session
    assert select_stream_isolation_token(session, "cdn.example.net", "session") == session
    # Strict mode keeps distinct hostname isolation groups.
    first = select_stream_isolation_token(session, "www.example.com", "hostname")
    second = select_stream_isolation_token(session, "cdn.example.net", "hostname")
    assert first != second
    assert select_stream_isolation_token(session, "www.example.com", "hostname") == first
    try:
        select_stream_isolation_token(session, "www.example.com", "invalid")
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown isolation mode was accepted.")


def _test_config_validation() -> None:
    AppConfig().validate()
    AppConfig(stream_isolation="hostname").validate()
    for mode in ("all", "none", 1, True):
        try:
            AppConfig(stream_isolation=mode).validate()
        except ValueError:
            continue
        raise AssertionError(f"Invalid stream-isolation mode was accepted: {mode!r}")
    for value in (80, 0, 65536, True):
        try:
            AppConfig(proxy_port=value).validate()
        except ValueError:
            continue
        raise AssertionError(f"Invalid proxy port was accepted: {value!r}")


def _test_remote_dns_encoding() -> None:
    encoded = encode_socks_target("www.example.com", 443)
    assert encoded[:4] == b"\x05\x01\x00\x03"
    length = encoded[4]
    assert encoded[5:5 + length] == b"www.example.com"
    assert int.from_bytes(encoded[-2:], "big") == 443


def _test_connect_policy() -> None:
    assert validate_connect_target("www.example.com", 443) == ("www.example.com", 443)
    # A valid v3 onion hostname remains usable through Tor.
    onion = "a" * 56 + ".onion"
    assert validate_connect_target(onion, 443) == (onion, 443)
    for port in (80, 8080, 8443, 9001):
        try:
            validate_connect_target("www.example.com", port)
        except ProxyPolicyError:
            continue
        raise AssertionError(f"Non-443 CONNECT port {port} was accepted.")


def _test_legacy_ipv4_rejection() -> None:
    for host in ("127.1", "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.1"):
        try:
            validate_connect_target(host, 443)
        except ProxyPolicyError:
            continue
        raise AssertionError(f"Legacy numeric IPv4 spelling was accepted: {host}")


def _test_internal_target_rejection() -> None:
    bad_targets = (
        ("127.0.0.1", 443),
        ("10.0.0.1", 443),
        ("192.168.1.1", 443),
        ("127.1", 443),
        ("localhost", 443),
        ("printer.local", 443),
        ("router.lan", 443),
        ("service.internal", 443),
        ("example.com.exit", 443),
        ("singlelabel", 443),
    )
    for host, port in bad_targets:
        try:
            validate_connect_target(host, port)
        except ProxyPolicyError:
            continue
        raise AssertionError(f"Unsafe CONNECT target was accepted: {host}")


def _test_atomic_private_file_write() -> None:
    with tempfile.TemporaryDirectory(prefix="null-atomic-file-test-") as temp_dir:
        root = Path(temp_dir)
        target = root / "original.txt"
        target.write_text("preserve", encoding="utf-8")
        hardlink = root / "hardlink.txt"
        os.link(target, hardlink)
        write_private_file(hardlink, "replacement")
        assert target.read_text(encoding="utf-8") == "preserve"
        assert hardlink.read_text(encoding="utf-8") == "replacement"
        assert stat.S_IMODE(hardlink.stat().st_mode) == 0o600

        symlink = root / "symlink.txt"
        symlink.symlink_to(target)
        write_private_file(symlink, "new contents")
        assert not symlink.is_symlink()
        assert symlink.read_text(encoding="utf-8") == "new contents"
        assert target.read_text(encoding="utf-8") == "preserve"


def _test_private_runtime_directory() -> None:
    assert RUNTIME_BASE in (Path("/private/tmp"), Path("/tmp"))
    assert not any(ch.isspace() for ch in str(SOCKS_SOCKET_PATH))
    assert not any(ch.isspace() for ch in str(CONTROL_SOCKET_PATH))
    assert SOCKS_SOCKET_PATH.parent == RUNTIME_DIR == CONTROL_SOCKET_PATH.parent


def _test_safe_tor_configuration() -> None:
    # Validate the actual torrc lines emitted by the application.
    network = TorNetwork(AppConfig(), IdentityManager())
    lines = network._torrc_lines()
    text = "\n".join(lines)
    required = (
        f"SocksPort unix:{SOCKS_SOCKET_PATH} IsolateSOCKSAuth",
        "UnixSocksGroupWritable 0",
        "SafeSocks 1",
        "ClientRejectInternalAddresses 1",
        f"ControlPort unix:{CONTROL_SOCKET_PATH}",
        "ControlSocketsGroupWritable 0",
        "CookieAuthentication 1",
        "ClientOnly 1",
        "SafeLogging 1",
    )
    assert all(item in text for item in required)
    assert f"ControlPort unix:{CONTROL_SOCKET_PATH}" in text
    assert "ControlSocket " not in text
    assert "WarnUnsafeSocks" not in text
    assert not any(ch.isspace() for ch in str(CONTROL_SOCKET_PATH))
    assert not any(ch.isspace() for ch in str(SOCKS_SOCKET_PATH))
    assert "SocksPort 127.0.0.1:" not in text


def _test_tor_bundle_manifest() -> None:
    with tempfile.TemporaryDirectory(prefix="null-tor-manifest-test-") as temp_dir:
        root = Path(temp_dir)
        binary = root / "tor" / "tor"
        binary.parent.mkdir(mode=0o700)
        binary.write_bytes(b"test Tor executable bytes")
        binary.chmod(0o700)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        manifest = root / ".project-null-tor-manifest.json"
        manifest.write_text(json.dumps({
            "bundle_version": TOR_EXPERT_BUNDLE_VERSION,
            "archive_sha256": TOR_EXPERT_ARCHIVE_SHA256,
            "binary_relative_path": "tor/tor",
            "binary_sha256": digest,
        }), encoding="utf-8")
        manifest.chmod(0o600)
        _verify_tor_bundle_manifest(binary, manifest)
        linked_binary = root / "tor" / "linked-tor"
        linked_binary.symlink_to(binary)
        try:
            _verify_tor_bundle_manifest(linked_binary, manifest)
        except RuntimeError:
            pass
        else:
            raise AssertionError("A symlinked Tor executable passed manifest validation.")
        linked_manifest = root / "linked-manifest.json"
        linked_manifest.symlink_to(manifest)
        try:
            _verify_tor_bundle_manifest(binary, linked_manifest)
        except RuntimeError:
            pass
        else:
            raise AssertionError("A symlinked Tor manifest passed manifest validation.")
        binary.write_bytes(b"modified executable")
        try:
            _verify_tor_bundle_manifest(binary, manifest)
        except RuntimeError as exc:
            assert "SHA-256" in str(exc)
        else:
            raise AssertionError("Modified Tor binary passed the bundle integrity check.")


def _test_managed_tor_only() -> None:
    with tempfile.TemporaryDirectory(prefix="null-unmanaged-tor-test-") as temp_dir:
        fake = Path(temp_dir) / "tor"
        fake.write_text("not Tor", encoding="utf-8")
        fake.chmod(0o700)
        previous = os.environ.get("PROJECT_NULL_TOR_BINARY")
        os.environ["PROJECT_NULL_TOR_BINARY"] = str(fake)
        try:
            found = find_tor_binary()
            assert found is None or Path(found) != fake
        finally:
            if previous is None:
                os.environ.pop("PROJECT_NULL_TOR_BINARY", None)
            else:
                os.environ["PROJECT_NULL_TOR_BINARY"] = previous


def _test_tor_directory_chain() -> None:
    with tempfile.TemporaryDirectory(prefix="null-tor-chain-test-") as temp_dir:
        root = Path(temp_dir)
        install = root / "Applications" / "ProjectNULL" / "tor-expert-16.0" / "tor"
        install.mkdir(parents=True, mode=0o700)
        for directory in (root / "Applications", root / "Applications" / "ProjectNULL",
                          root / "Applications" / "ProjectNULL" / "tor-expert-16.0", install):
            directory.chmod(0o700)
        _verify_directory_chain(install, root)
        (root / "Applications").chmod(0o720)
        try:
            _verify_directory_chain(install, root)
        except PermissionError:
            pass
        else:
            raise AssertionError("Group-writable parent directory passed Tor chain verification.")
        (root / "Applications").chmod(0o700)
        link = root / "link"
        link.symlink_to(root / "Applications", target_is_directory=True)
        try:
            _verify_directory_chain(link / "ProjectNULL", root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Symlinked parent directory passed Tor chain verification.")


def _test_chrome_launch_policy() -> None:
    import inspect
    source = inspect.getsource(ProjectNullApp.open_chrome)
    assert 'f"--proxy-server={proxy}"' in source
    assert 'socks5://127.0.0.1:' in source
    assert "--load-extension" not in source
    assert "proxy-auth-extension" not in source
    assert "--host-resolver-rules" not in source
    assert "--dns-prefetch-disable" in source
    assert 'direct://' not in source


def _test_private_directory_parent_safety() -> None:
    with tempfile.TemporaryDirectory(prefix="null-private-parent-test-") as temp_dir:
        root = Path(temp_dir)
        home = root / "home"
        outside = root / "outside"
        home.mkdir(mode=0o700)
        outside.mkdir(mode=0o700)
        link = home / "Library"
        link.symlink_to(outside, target_is_directory=True)
        try:
            ensure_private_directory(
                home / "Library" / "Application Support" / "Project NULL",
                trusted_home=home,
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("Private directory creation traversed a symlinked parent.")


def _test_private_directory_nested_creation() -> None:
    with tempfile.TemporaryDirectory(prefix="null-nested-private-test-") as temp_dir:
        root = Path(temp_dir)
        home = root / "home"
        home.mkdir(mode=0o700)
        nested = home / "Library" / "Application Support" / "Project NULL" / "browser-sessions"
        ensure_private_directory(nested, trusted_home=home)
        assert nested.is_dir()
        assert stat.S_IMODE(nested.stat().st_mode) == 0o700
        assert stat.S_IMODE((home / "Library").stat().st_mode) == 0o700


def _test_general_circuit_request() -> None:
    class FakeController:
        def __init__(self) -> None:
            self.calls: list[tuple[Any, ...]] = []

        def new_circuit(self, path=None, purpose="general", await_build=False):
            self.calls.append((path, purpose, await_build))
            return "42"

    fake = FakeController()
    result = request_general_purpose_circuit(fake)
    assert result == "42"
    assert fake.calls == [(None, "general", False)]

    class BadController(FakeController):
        def new_circuit(self, path=None, purpose="general", await_build=False):
            return "invalid-id"

    try:
        request_general_purpose_circuit(BadController())
    except RuntimeError:
        pass
    else:
        raise AssertionError("Malformed Tor circuit ID was accepted.")


def _test_private_unix_socket_path_safety() -> None:
    with tempfile.TemporaryDirectory(prefix="null-socket-path-test-") as temp_dir:
        root = Path(temp_dir)
        private_dir = root / "private"
        ensure_private_directory(private_dir)
        assert stat.S_IMODE(private_dir.stat().st_mode) == 0o700

        active_path = private_dir / "active.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(active_path))
        server.listen(1)
        try:
            try:
                prepare_private_unix_socket_path(active_path)
            except RuntimeError:
                pass
            else:
                raise AssertionError("An active Unix socket was accepted as stale.")
        finally:
            server.close()
        prepare_private_unix_socket_path(active_path)
        assert not active_path.exists()

        ordinary_file = private_dir / "not-a-socket"
        ordinary_file.write_text("keep", encoding="utf-8")
        try:
            prepare_private_unix_socket_path(ordinary_file)
        except RuntimeError:
            pass
        else:
            raise AssertionError("A non-socket path was replaced.")

        target = private_dir / "target"
        target.write_text("keep", encoding="utf-8")
        symlink = private_dir / "link.sock"
        symlink.symlink_to(target)
        try:
            prepare_private_unix_socket_path(symlink)
        except RuntimeError:
            pass
        else:
            raise AssertionError("A symlink socket path was accepted.")


def _test_config_store_rejects_coercion() -> None:
    original_app_dir, original_config = APP_DIR, CONFIG_PATH
    with tempfile.TemporaryDirectory(prefix="null-config-strict-") as temp_dir:
        root = Path(temp_dir) / "app"
        root.mkdir(mode=0o700)
        config_path = root / "config.json"
        try:
            globals()["APP_DIR"] = root
            globals()["CONFIG_PATH"] = config_path
            config_path.write_text('{"proxy_port": 28080}', encoding="utf-8")
            config_path.chmod(0o600)
            assert ConfigStore.load().stream_isolation == "session"
            for payload in (
                '{"proxy_port": "28080"}',
                '{"proxy_port": 28080.0}',
                '{"proxy_port": true}',
                '{"proxy_port": 28080, "stream_isolation": 1}',
            ):
                config_path.write_text(payload, encoding="utf-8")
                config_path.chmod(0o600)
                try:
                    ConfigStore.load()
                except RuntimeError:
                    continue
                raise AssertionError(f"Non-integer JSON proxy_port was accepted: {payload}")
        finally:
            globals()["APP_DIR"] = original_app_dir
            globals()["CONFIG_PATH"] = original_config


def _test_config_does_not_persist_secrets() -> None:
    global APP_DIR, CONFIG_PATH
    old_app_dir, old_config_path = APP_DIR, CONFIG_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="null-config-test-") as temp_dir:
            APP_DIR = Path(temp_dir) / "Project NULL"
            CONFIG_PATH = APP_DIR / "config.json"
            ConfigStore.save(AppConfig(proxy_port=28081, stream_isolation="hostname"))
            saved = CONFIG_PATH.read_text(encoding="utf-8")
            assert '"stream_isolation": "hostname"' in saved
            assert ConfigStore.load().stream_isolation == "hostname"
            assert "proxy_auth_token" not in saved
            assert "isolation_token" not in saved
            assert "session_id" not in saved
            assert stat.S_IMODE(CONFIG_PATH.stat().st_mode) == 0o600
            assert stat.S_IMODE(APP_DIR.stat().st_mode) == 0o700
    finally:
        APP_DIR, CONFIG_PATH = old_app_dir, old_config_path


def _test_proxy_concurrency() -> None:
    assert 1 <= MAX_PROXY_CLIENTS <= 128
    assert NullSocksProxyServer.request_queue_size == PROXY_LISTEN_BACKLOG
    assert PROXY_PENDING_QUEUE_SIZE == 128
    assert PROXY_LISTEN_BACKLOG >= PROXY_PENDING_QUEUE_SIZE
    assert PROXY_PENDING_QUEUE_SIZE >= MAX_PROXY_CLIENTS
    assert _proxy_client_limit_for_fd_budget(256) == 32
    assert _proxy_client_limit_for_fd_budget(512) == 128
    assert _proxy_client_limit_for_fd_budget(1024) == 128
    assert _proxy_client_limit_for_fd_budget(128) == 1
    assert _proxy_client_limit_for_fd_budget(-1) == 128


class _FakeTorSocksHandler(socketserver.BaseRequestHandler):
    """Local test-only Tor-SOCKS fixture that checks upstream isolation auth."""
    def handle(self) -> None:
        client = self.request
        client.settimeout(5)
        try:
            version, method_count = recv_exact(client, 2)
            methods = recv_exact(client, method_count)
            if version != 5 or 2 not in methods:
                raise AssertionError("Adapter did not offer Tor SOCKS username/password authentication upstream.")
            client.sendall(b"\x05\x02")
            auth_version, username_length = recv_exact(client, 2)
            username = recv_exact(client, username_length)
            password_length = recv_exact(client, 1)[0]
            password = recv_exact(client, password_length)
            expected = self.server.expected_password  # type: ignore[attr-defined]
            if auth_version != 1 or username != TOR_SOCKS_EXT_USERNAME or password.decode("ascii") != expected:
                raise AssertionError("Adapter sent an invalid Tor stream-isolation credential.")
            client.sendall(b"\x01\x00")
            ver, command, reserved, atyp = recv_exact(client, 4)
            if (ver, command, reserved, atyp) != (5, 1, 0, 3):
                raise AssertionError("Adapter did not send a SOCKS5 domain-name CONNECT request to Tor.")
            domain_length = recv_exact(client, 1)[0]
            domain = recv_exact(client, domain_length).decode("ascii")
            port = int.from_bytes(recv_exact(client, 2), "big")
            if domain != "example.com" or port != 443:
                raise AssertionError("Unexpected destination sent to fake Tor SOCKS server.")
            client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            while True:
                data = client.recv(4096)
                if not data:
                    break
                client.sendall(data)
        except (OSError, ConnectionError):
            return
        except Exception as exc:
            self.server.test_errors.append(f"{type(exc).__name__}: {exc}")  # type: ignore[attr-defined]


class _FakeTorSocksServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, socket_path: str) -> None:
        self.test_errors: list[str] = []
        self.expected_password = ""
        super().__init__(socket_path, _FakeTorSocksHandler)


def _test_proxy_admission_backpressure() -> None:
    """The fixed worker pool queues multiple clients without stalling accept()."""
    global MAX_PROXY_CLIENTS
    original_limit = MAX_PROXY_CLIENTS
    with tempfile.TemporaryDirectory(prefix="null-socks-admission-") as temp_dir:
        fake_path = str(Path(temp_dir) / "fake-socks.sock")
        fake_socks = _FakeTorSocksServer(fake_path)
        isolation_token = secrets.token_hex(32)
        fake_socks.expected_password = derive_stream_isolation_token(isolation_token, "example.com")
        fake_thread = threading.Thread(target=fake_socks.serve_forever, daemon=True)
        fake_thread.start()
        MAX_PROXY_CLIENTS = 1
        proxy = NullSocksProxyServer(0, fake_path, isolation_token, lambda _msg: None, "hostname")
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        clients: list[Optional[socket.socket]] = [None, None, None]
        try:
            address = ("127.0.0.1", proxy.server_address[1])
            first = clients[0] = socket.create_connection(address, timeout=3)
            first.settimeout(3)
            first.sendall(b"\x05\x01\x00")
            assert recv_exact(first, 2) == b"\x05\x00"
            first.sendall(encode_socks_target("example.com", 443))
            assert recv_exact(first, 4) == b"\x05\x00\x00\x01"
            recv_exact(first, 6)

            # While the sole worker relays the first tunnel, two additional
            # clients must be accepted into the bounded userspace queue. The
            # accept loop must remain responsive rather than wait on capacity.
            for index in (1, 2):
                client = clients[index] = socket.create_connection(address, timeout=3)
                client.settimeout(0.2)
                client.sendall(b"\x05\x01\x00")
            deadline = time.monotonic() + 2.0
            while proxy._pending_requests.qsize() < 2 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert proxy._pending_requests.qsize() == 2, "Accept loop did not enqueue both pending clients."
            for queued in (clients[1], clients[2]):
                assert queued is not None
                try:
                    unexpected = queued.recv(2)
                except socket.timeout:
                    unexpected = None
                assert unexpected is None, "Queued client was handled before the active worker became available."

            first.close()
            clients[0] = None
            for index in (1, 2):
                client = clients[index]
                assert client is not None
                client.settimeout(5)
                assert recv_exact(client, 2) == b"\x05\x00"
                client.sendall(encode_socks_target("example.com", 443))
                assert recv_exact(client, 4) == b"\x05\x00\x00\x01"
                recv_exact(client, 6)
                client.close()
                clients[index] = None
        finally:
            MAX_PROXY_CLIENTS = original_limit
            for client in clients:
                if client is not None:
                    try:
                        client.close()
                    except OSError:
                        pass
            proxy.shutdown()
            proxy.close_active_sockets()
            proxy.server_close()
            proxy_thread.join(timeout=3)
            fake_socks.shutdown()
            fake_socks.server_close()
            fake_thread.join(timeout=3)
        if fake_socks.test_errors:
            raise AssertionError("Fake Tor SOCKS errors: " + "; ".join(fake_socks.test_errors))


def _test_proxy_forwarding() -> None:
    """Exercise Chrome no-auth SOCKS5 to local adapter to authenticated Tor SOCKS."""
    with tempfile.TemporaryDirectory(prefix="null-test-") as temp_dir:
        fake_path = str(Path(temp_dir) / "fake-socks.sock")
        fake_socks = _FakeTorSocksServer(fake_path)
        fake_thread = threading.Thread(target=fake_socks.serve_forever, daemon=True)
        fake_thread.start()
        isolation_token = secrets.token_hex(32)
        fake_socks.expected_password = isolation_token
        proxy = NullSocksProxyServer(0, fake_path, isolation_token, lambda _msg: None, "session")
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        client: Optional[socket.socket] = None
        try:
            address = ("127.0.0.1", proxy.server_address[1])
            client = socket.create_connection(address, timeout=5)
            client.settimeout(5)
            # Chrome-style no-auth SOCKS5 greeting; no username/password exchange.
            client.sendall(b"\x05\x01\x00")
            assert recv_exact(client, 2) == b"\x05\x00"
            client.sendall(encode_socks_target("example.com", 443))
            version, reply, reserved, atyp = recv_exact(client, 4)
            assert (version, reply, reserved, atyp) == (5, 0, 0, 1)
            recv_exact(client, 6)
            marker = b"project-null-v0.4.9-socks-test"
            client.sendall(marker)
            echoed = recv_exact(client, len(marker))
            assert echoed == marker
        finally:
            if client is not None:
                try:
                    client.close()
                except OSError:
                    pass
            proxy.shutdown()
            proxy.close_active_sockets()
            proxy.server_close()
            fake_socks.shutdown()
            fake_socks.server_close()
            fake_thread.join(timeout=3)
        if fake_socks.test_errors:
            raise AssertionError("Fake Tor SOCKS errors: " + "; ".join(fake_socks.test_errors))


def _test_local_socks5_client() -> None:
    """Validate browser-facing SOCKS5 no-auth negotiation and fail-closed policies."""
    assert encode_socks_target("www.example.com", 443)[:4] == b"\x05\x01\x00\x03"
    # The adapter's own handler rejects IP-address forms and non-443 targets
    # before calling the Tor-side SOCKS transport.
    for host, port in (("127.0.0.1", 443), ("localhost", 443), ("example.com", 80)):
        try:
            validate_connect_target(host, port)
        except ProxyPolicyError:
            continue
        raise AssertionError(f"Local SOCKS5 policy accepted forbidden target {host}:{port}.")
    # Explicitly check that the helper does not try DNS locally.
    import inspect
    source = inspect.getsource(local_socks5_connect)
    assert "socket.create_connection(proxy_address" in source
    assert "socket.getaddrinfo" not in source


def _socks5_client_request(address: tuple[str, int], request: bytes, methods: bytes = b"\x00") -> tuple[bytes, bytes]:
    client = socket.create_connection(address, timeout=3)
    try:
        client.settimeout(3)
        client.sendall(bytes((5, len(methods))) + methods)
        selection = recv_exact(client, 2)
        if selection != b"\x05\x00":
            return selection, b""
        client.sendall(request)
        header = recv_exact(client, 4)
        atyp = header[3]
        if atyp == 1:
            tail = recv_exact(client, 6)
        elif atyp == 4:
            tail = recv_exact(client, 18)
        elif atyp == 3:
            length = recv_exact(client, 1)[0]
            tail = bytes((length,)) + recv_exact(client, length + 2)
        else:
            raise AssertionError("Invalid SOCKS5 reply address type.")
        return selection, header + tail
    finally:
        client.close()


def _test_local_socks5_rejects_unsupported_methods() -> None:
    with tempfile.TemporaryDirectory(prefix="null-socks-methods-") as temp_dir:
        proxy = NullSocksProxyServer(0, str(Path(temp_dir) / "missing.sock"), secrets.token_hex(32), lambda _msg: None)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        client = socket.create_connection(("127.0.0.1", proxy.server_address[1]), timeout=3)
        try:
            client.sendall(b"\x05\x01\x02")  # Offer only username/password, which Chrome does not use.
            assert recv_exact(client, 2) == b"\x05\xff"
        finally:
            client.close()
            proxy.shutdown(); proxy.server_close(); thread.join(timeout=2)


def _test_local_socks5_rejects_ip_literals() -> None:
    with tempfile.TemporaryDirectory(prefix="null-socks-ip-") as temp_dir:
        proxy = NullSocksProxyServer(0, str(Path(temp_dir) / "missing.sock"), secrets.token_hex(32), lambda _msg: None)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            _, response = _socks5_client_request(
                ("127.0.0.1", proxy.server_address[1]),
                b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb",
            )
            assert response[1] == SOCKS5_REPLY_ADDRESS_UNSUPPORTED
        finally:
            proxy.shutdown(); proxy.close_active_sockets(); proxy.server_close(); thread.join(timeout=2)


def _test_local_socks5_rejects_non_443() -> None:
    with tempfile.TemporaryDirectory(prefix="null-socks-port-") as temp_dir:
        proxy = NullSocksProxyServer(0, str(Path(temp_dir) / "missing.sock"), secrets.token_hex(32), lambda _msg: None)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            _, response = _socks5_client_request(
                ("127.0.0.1", proxy.server_address[1]),
                b"\x05\x01\x00\x03\x0bexample.com\x00\x50",
            )
            assert response[1] == SOCKS5_REPLY_NOT_ALLOWED
        finally:
            proxy.shutdown(); proxy.close_active_sockets(); proxy.server_close(); thread.join(timeout=2)


def _test_local_socks5_fails_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="null-socks-fail-closed-") as temp_dir:
        proxy = NullSocksProxyServer(0, str(Path(temp_dir) / "missing.sock"), secrets.token_hex(32), lambda _msg: None)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            _, response = _socks5_client_request(
                ("127.0.0.1", proxy.server_address[1]),
                encode_socks_target("example.com", 443),
            )
            assert response[1] == SOCKS5_REPLY_GENERAL_FAILURE
        finally:
            proxy.shutdown(); proxy.close_active_sockets(); proxy.server_close(); thread.join(timeout=2)


def _test_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="null-no-socks-") as temp_dir:
        missing_socket = str(Path(temp_dir) / "missing.sock")
        try:
            socks5_connect("example.com", 443, missing_socket, "a" * 64, timeout=0.5)
        except OSError:
            pass
        else:
            raise AssertionError("Missing Tor SOCKS Unix socket did not stop the request.")
        # Transport-level enforcement must reject disallowed targets before
        # attempting to connect to any upstream socket.
        for forbidden in ("127.1", "localhost", "2130706433"):
            try:
                socks5_connect(forbidden, 443, missing_socket, "a" * 64, timeout=0.5)
            except ProxyPolicyError:
                continue
            raise AssertionError(f"SOCKS transport accepted disallowed target {forbidden!r}.")
        try:
            socks5_connect("example.com", 443, missing_socket, "not-a-token", timeout=0.5)
        except ValueError:
            return
    raise AssertionError("Invalid SOCKS isolation token was accepted.")


def _test_proxy_bind_policy() -> None:
    # Verify the unauthenticated browser adapter binds only to IPv4 loopback.
    assert NullSocksProxyServer.__mro__[1] is socketserver.ThreadingTCPServer
    source = __import__("inspect").getsource(NullSocksProxyServer.__init__)
    assert '("127.0.0.1", port)' in source
    assert "proxy_auth_token" not in source


def _test_shutdown_cancellation() -> None:
    network = TorNetwork(AppConfig(), IdentityManager())
    network.shutdown()
    assert network._closed_event.is_set()
    assert network._cancel_event.is_set()
    try:
        network.connect()
    except RuntimeError as exc:
        assert "shut down" in str(exc)
    else:
        raise AssertionError("A permanently shut down network object allowed a new connection.")


def _test_bounded_control_call_timeout() -> None:
    released = threading.Event()
    started = threading.Event()

    class FakeController:
        closed = False
        def close(self) -> None:
            self.closed = True
            released.set()

    controller = FakeController()
    network = TorNetwork(AppConfig(), IdentityManager())
    network.controller = controller

    def blocked_operation() -> str:
        started.set()
        released.wait(3.0)
        return "unblocked"

    began = time.monotonic()
    try:
        network._bounded_controller_call(
            controller,
            blocked_operation,
            timeout=0.05,
            label="self-test",
            on_timeout=network.disconnect,
        )
    except TimeoutError as exc:
        assert "deadline" in str(exc)
    else:
        raise AssertionError("A blocked Control operation exceeded its deadline without failing.")
    elapsed = time.monotonic() - began
    assert started.is_set(), "The simulated Control operation did not start."
    assert elapsed < 2.5, f"Bounded Control call took too long: {elapsed:.2f}s"
    assert controller.closed and network.controller is None
    assert released.is_set(), "Closing the controller did not release the blocked operation fixture."


def _test_bounded_shutdown() -> None:
    class FakeController:
        closed = False
        signal_called = False
        def close(self) -> None:
            self.closed = True
        def signal(self, *_args: Any) -> None:
            self.signal_called = True
            raise AssertionError("Shutdown must not wait for a Tor Control command round-trip.")

    class FakeProcess:
        returncode = None
        terminated = False
        killed = False
        def poll(self) -> Optional[int]:
            return self.returncode
        def terminate(self) -> None:
            self.terminated = True
        def wait(self, timeout: Optional[float] = None) -> int:
            assert timeout is not None and timeout <= 8
            self.returncode = 0
            return 0
        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

    network = TorNetwork(AppConfig(), IdentityManager())
    controller = FakeController()
    process = FakeProcess()
    network.controller = controller
    network.process = process
    network.disconnect()
    assert controller.closed and not controller.signal_called
    assert process.terminated and not process.killed
    assert network.controller is None and network.process is None


# ---------------------------------------------------------------------------
# Tkinter dashboard
# ---------------------------------------------------------------------------

DASHBOARD_BUTTON_STYLES = {
    "primary": {
        "background": "#1d3c2b",
        "foreground": "#d8f5e2",
        "hover_background": "#274d37",
        "hover_foreground": "#ffffff",
        "disabled_background": "#101511",
        "disabled_foreground": "#829187",
        "border": "#3b5945",
    },
    "secondary": {
        "background": "#151e18",
        "foreground": "#e6eee8",
        "hover_background": "#274d37",
        "hover_foreground": "#ffffff",
        "disabled_background": "#101511",
        "disabled_foreground": "#829187",
        "border": "#27342b",
    },
}


def _relative_luminance(color: str) -> float:
    """Calculate WCAG relative luminance for a #RRGGBB color."""
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        raise ValueError(f"Invalid RGB color: {color!r}")
    channels = [int(color[index:index + 2], 16) / 255.0 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    first = _relative_luminance(foreground)
    second = _relative_luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def _test_dashboard_button_contrast() -> None:
    """Keep enabled and disabled label-buttons readable on dark backgrounds."""
    for name, palette in DASHBOARD_BUTTON_STYLES.items():
        assert _contrast_ratio(palette["foreground"], palette["background"]) >= 7.0, name
        assert _contrast_ratio(palette["hover_foreground"], palette["hover_background"]) >= 7.0, name
        assert _contrast_ratio(palette["disabled_foreground"], palette["disabled_background"]) >= 4.5, name


class DashboardButton(tk.Label if tk is not None else object):
    """A theme-independent clickable label used as a dashboard button.

    The native macOS Aqua button renderer may ignore Tk classic Button
    foreground/background settings, which can produce white-on-white controls
    in dark mode. A Label is drawn by Tk itself and honours the explicit colors.
    """

    def __init__(
        self,
        parent: tk.Widget,
        text: str,
        command: Callable[[], None],
        *,
        primary: bool = False,
    ) -> None:
        self._command = command
        palette = DASHBOARD_BUTTON_STYLES["primary" if primary else "secondary"]
        self._normal_bg = palette["background"]
        self._normal_fg = palette["foreground"]
        self._hover_bg = palette["hover_background"]
        self._hover_fg = palette["hover_foreground"]
        self._disabled_bg = palette["disabled_background"]
        self._disabled_fg = palette["disabled_foreground"]
        self._border = palette["border"]
        super().__init__(
            parent,
            text=text,
            anchor="center",
            justify="center",
            bg=self._normal_bg,
            fg=self._normal_fg,
            activebackground=self._hover_bg,
            activeforeground=self._hover_fg,
            disabledforeground=self._disabled_fg,
            relief="flat",
            bd=0,
            padx=13,
            pady=10,
            font=("Menlo", 8, "bold"),
            cursor="hand2",
            takefocus=True,
            highlightthickness=1,
            highlightbackground=self._border,
            highlightcolor="#65d995",
        )
        self.bind("<Enter>", self._on_enter, add="+")
        self.bind("<Leave>", self._on_leave, add="+")
        self.bind("<Button-1>", self._invoke, add="+")
        self.bind("<Return>", self._invoke, add="+")
        self.bind("<space>", self._invoke, add="+")

    def _on_enter(self, _event: Any = None) -> None:
        if self.cget("state") == "normal":
            self.configure(bg=self._hover_bg, fg=self._hover_fg)

    def _on_leave(self, _event: Any = None) -> None:
        if self.cget("state") == "normal":
            self.configure(bg=self._normal_bg, fg=self._normal_fg)

    def configure(self, cnf: Any = None, **kwargs: Any) -> Any:
        # Label widgets keep ordinary Tk colors on macOS, unlike Aqua-rendered
        # classic Buttons. Preserve that guarantee when callers toggle state.
        requested_state = kwargs.get("state")
        result = super().configure(cnf, **kwargs)
        if requested_state == "disabled":
            super().configure(bg=self._disabled_bg, fg=self._disabled_fg)
        elif requested_state == "normal":
            super().configure(bg=self._normal_bg, fg=self._normal_fg)
        return result

    config = configure

    def _invoke(self, _event: Any = None) -> str:
        if self.cget("state") == "normal":
            self._command()
        return "break"


class ProjectNullApp:
    BG = "#080b09"
    PANEL = "#111713"
    PANEL_2 = "#151e18"
    BORDER = "#27342b"
    TEXT = "#e6eee8"
    MUTED = "#8b9b90"
    GREEN = "#65d995"
    RED = "#ff6d75"
    YELLOW = "#e9c46a"

    def __init__(self, config: AppConfig, local_dev: bool = False) -> None:
        self.config = config
        self.local_dev = local_dev
        self.identity_manager = IdentityManager()
        self.network = TorNetwork(config, self.identity_manager, self._post_log)
        self.chrome_process: Optional[subprocess.Popen[bytes]] = None
        self.chrome_session_dir: Optional[Path] = None
        self.messages: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.root = tk.Tk()
        self.root.title(f"PROJECT NULL {APP_VERSION} — Hardened Tor Proxy Prototype")
        self.root.geometry("1060x760")
        self.root.minsize(900, 680)
        self.root.configure(bg=self.BG)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.external_check_var = tk.BooleanVar(value=False)
        self.status = "LOCAL DEV" if local_dev else "DISCONNECTED"
        self._build_ui()
        self._refresh_identity()
        self._set_status(self.status)
        if self.local_dev:
            self.connect_button.configure(state="disabled", text="LOCAL DEV ONLY")
            self.diag_button.configure(state="normal", text="LOCAL SELF-TEST")
        else:
            self._set_controls(connected=False)
        self._log("Local development mode: networking is disabled; no relays or traffic are simulated." if local_dev else "Ready. No traffic is routed until Tor connects and an application is configured to use the local proxy.")
        self.root.after(150, self._drain_messages)
        self.root.after(2000, self._health_tick)

    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, bg=self.BG, padx=24, pady=22)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=self.BG)
        header.pack(fill="x", pady=(0, 18))
        brand = tk.Frame(header, bg=self.BG)
        brand.pack(side="left", anchor="w")
        tk.Label(brand, text="PROJECT NULL", bg=self.BG, fg=self.TEXT,
                 font=("Menlo", 22, "bold")).pack(anchor="w")
        tk.Label(brand, text=f"TOR-BACKED SOCKS5 PROXY  /  VERSION {APP_VERSION}", bg=self.BG,
                 fg=self.MUTED, font=("Menlo", 9)).pack(anchor="w", pady=(4, 0))
        self.status_label = tk.Label(header, text="DISCONNECTED", bg=self.PANEL_2,
                                     fg=self.MUTED, font=("Menlo", 10, "bold"),
                                     padx=14, pady=8)
        self.status_label.pack(side="right", anchor="e")

        warning = tk.Frame(outer, bg="#191b12", highlightbackground="#47402a", highlightthickness=1, padx=12, pady=10)
        warning.pack(fill="x", pady=(0, 16))
        tk.Label(warning, text="SCOPE", bg="#191b12", fg=self.YELLOW,
                 font=("Menlo", 9, "bold")).pack(side="left", padx=(0, 12))
        tk.Label(warning, text="LOOPBACK SOCKS5 PROXY: hostname destinations on TCP/443 only; Project NULL does not inspect the tunnel to prove TLS. Tor SOCKS and Control use private Unix sockets. Websites see a Tor exit IP; the entry guard sees your source IP. Chrome is compatibility-only. Other Mac traffic/system DNS are not protected; no system-wide kill switch exists.",
                 bg="#191b12", fg="#c9c6b4", font=("Arial", 10), anchor="w", justify="left",
                 wraplength=820).pack(side="left", fill="x", expand=True)

        grid = tk.Frame(outer, bg=self.BG)
        grid.pack(fill="x")
        self.value_labels: dict[str, tk.Label] = {}
        cards = [
            ("EPHEMERAL SESSION LABEL", "session", "—"),
            ("ACTIVE RELAYS", "relays", "0 / 3"),
            ("EXIT GATEWAY", "exit", "Not connected"),
            ("ROUTING STATUS", "routing", "Inactive"),
            ("PROXY DNS", "dns", "Inactive"),
            ("ROUND-TRIP", "latency", "—"),
        ]
        for index, (heading, key, initial) in enumerate(cards):
            card = tk.Frame(grid, bg=self.PANEL, highlightbackground=self.BORDER, highlightthickness=1, padx=14, pady=13)
            card.grid(row=index // 3, column=index % 3, sticky="nsew", padx=(0 if index % 3 == 0 else 8, 0), pady=(0, 8))
            grid.grid_columnconfigure(index % 3, weight=1, uniform="cards")
            tk.Label(card, text=heading, bg=self.PANEL, fg=self.MUTED,
                     font=("Menlo", 8, "bold")).pack(anchor="w")
            value = tk.Label(card, text=initial, bg=self.PANEL, fg=self.TEXT,
                             font=("Menlo", 11, "bold"), anchor="w", justify="left", wraplength=280)
            value.pack(anchor="w", pady=(10, 0))
            self.value_labels[key] = value

        proxy_line = tk.Frame(outer, bg=self.PANEL_2, highlightbackground=self.BORDER, highlightthickness=1, padx=14, pady=10)
        proxy_line.pack(fill="x", pady=(7, 14))
        tk.Label(proxy_line, text="LOCAL SOCKS5 PROXY", bg=self.PANEL_2, fg=self.MUTED,
                 font=("Menlo", 8, "bold")).pack(side="left")
        self.proxy_endpoint = tk.Label(proxy_line, text=f"127.0.0.1:{self.config.proxy_port}  /  inactive", bg=self.PANEL_2,
                                       fg=self.TEXT, font=("Menlo", 10))
        self.proxy_endpoint.pack(side="right")

        controls = tk.Frame(outer, bg=self.BG)
        controls.pack(fill="x", pady=(0, 12))
        self.connect_button = self._make_button(controls, "CONNECT", self.connect, primary=True)
        self.disconnect_button = self._make_button(controls, "DISCONNECT", self.disconnect, primary=False)
        self.identity_button = self._make_button(controls, "ROTATE SESSION", self.new_identity, primary=False)
        self.diag_button = self._make_button(controls, "RUN DIAGNOSTICS", self.run_diagnostics, primary=False)
        self.settings_button = self._make_button(controls, "SETTINGS", self.open_settings, primary=False)
        self.chrome_button = self._make_button(controls, "OPEN CHROME (TEST)", self.open_chrome, primary=False)
        self.connect_button.pack(side="left", padx=(0, 8))
        for button in (self.disconnect_button, self.identity_button, self.diag_button,
                       self.settings_button, self.chrome_button):
            button.pack(side="left", padx=(0, 8))

        option_row = tk.Frame(outer, bg=self.BG)
        option_row.pack(fill="x", pady=(0, 10))
        self.external_check = tk.Checkbutton(
            option_row,
            text="Query check.torproject.org for the exit IP (external request; off by default)",
            variable=self.external_check_var,
            bg=self.BG, fg=self.MUTED, activebackground=self.BG, activeforeground=self.TEXT,
            selectcolor=self.PANEL, font=("Arial", 9), borderwidth=0,
        )
        self.external_check.pack(side="left")

        log_header = tk.Frame(outer, bg=self.BG)
        log_header.pack(fill="x", pady=(3, 6))
        tk.Label(log_header, text="EVENT LOG", bg=self.BG, fg=self.MUTED,
                 font=("Menlo", 9, "bold")).pack(side="left")
        tk.Label(log_header, text="EPHEMERAL SESSION  /  PROXY SECRETS NEVER LOGGED", bg=self.BG,
                 fg="#5e7164", font=("Menlo", 8)).pack(side="right")
        log_frame = tk.Frame(outer, bg=self.PANEL, highlightbackground=self.BORDER, highlightthickness=1)
        log_frame.pack(fill="both", expand=True)
        self.log_widget = tk.Text(
            log_frame, height=12, bg=self.PANEL, fg="#b9c9bd", insertbackground=self.GREEN,
            font=("Menlo", 9), relief="flat", borderwidth=0, padx=12, pady=10,
            wrap="word", state="disabled",
        )
        scrollbar = tk.Scrollbar(log_frame, command=self.log_widget.yview, bg=self.PANEL)
        self.log_widget.configure(yscrollcommand=scrollbar.set)
        self.log_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        footer = tk.Label(outer, text="TOR COMMUNITY RELAYS  •  LOOPBACK-ONLY PROXY  •  NO DIRECT FALLBACK  •  EXPERIMENTAL",
                          bg=self.BG, fg="#536459", font=("Menlo", 8))
        footer.pack(anchor="w", pady=(10, 0))
        if self.local_dev:
            self.connect_button.configure(state="disabled", text="LOCAL DEV ONLY")
            self.diag_button.configure(text="LOCAL SELF-TEST")
            self.chrome_button.configure(state="disabled")

    def _make_button(self, parent: tk.Widget, text: str, command: Callable[[], None], primary: bool) -> DashboardButton:
        return DashboardButton(parent, text, command, primary=primary)

    def _post_log(self, message: str) -> None:
        self.messages.put(("log", message))

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log_widget.configure(state="normal")
        self.log_widget.insert("end", f"{timestamp}  {message}\n")
        self.log_widget.see("end")
        self.log_widget.configure(state="disabled")

    def _drain_messages(self) -> None:
        try:
            while True:
                kind, payload = self.messages.get_nowait()
                if kind == "log":
                    self._log(str(payload))
                elif kind == "connected":
                    self._set_status("CONNECTED")
                    self._update_connection_view(payload)
                    self._set_controls(connected=True)
                elif kind == "disconnected":
                    self._set_status("DISCONNECTED")
                    self._reset_connection_view()
                    self._set_controls(connected=False)
                elif kind == "error":
                    self._set_status("ERROR")
                    self._set_controls(connected=False)
                    self._log("ERROR: " + str(payload))
                    messagebox.showerror("Project NULL", str(payload), parent=self.root)
                elif kind == "diagnostics":
                    self._render_diagnostics(payload)
                elif kind == "diagnostics_error":
                    self._log("DIAGNOSTICS ERROR: " + str(payload))
                    self.diag_button.configure(state="normal")
                elif kind == "enable_diag":
                    self.diag_button.configure(state="normal")
                elif kind == "local_diagnostics":
                    self._render_local_diagnostics(payload)
                elif kind == "settings_applied":
                    self._log("Settings saved. Ports take effect on the next connection.")
        except queue.Empty:
            pass
        self.root.after(150, self._drain_messages)

    def _health_tick(self) -> None:
        self._cleanup_closed_chrome()
        if self.status == "CONNECTED":
            if not self.network.is_process_alive or not self.network.is_proxy_alive:
                self._log("FAIL-CLOSED: Tor or the local proxy stopped. Disconnecting the local session; no direct fallback is available in this proxy.")
                self._set_status("ERROR")
                self.disconnect()
        self.root.after(2000, self._health_tick)

    def _set_status(self, status: str) -> None:
        self.status = status
        colors = {
            "CONNECTED": (self.GREEN, "#13251a"),
            "CONNECTING": (self.YELLOW, "#292313"),
            "ERROR": (self.RED, "#2c1719"),
            "LOCAL DEV": (self.YELLOW, "#292313"),
            "DISCONNECTED": (self.MUTED, self.PANEL_2),
        }
        fg, bg = colors.get(status, (self.MUTED, self.PANEL_2))
        self.status_label.configure(text=status, fg=fg, bg=bg)

    def _set_controls(self, connected: bool) -> None:
        self.connect_button.configure(state="disabled" if connected else "normal")
        self.disconnect_button.configure(state="normal" if connected else "disabled")
        self.settings_button.configure(state="disabled" if connected else "normal")
        self.identity_button.configure(state="normal")
        self.diag_button.configure(state="normal" if connected or self.local_dev else "disabled")
        self.chrome_button.configure(
            state="normal" if connected and sys.platform == "darwin" else "disabled"
        )

    def _refresh_identity(self) -> None:
        identity = self.identity_manager.current
        if identity:
            self.value_labels["session"].configure(text=identity.session_id)

    def _update_connection_view(self, circuit: CircuitInfo) -> None:
        self.value_labels["relays"].configure(text=f"{circuit.relay_count} / 3", fg=self.GREEN)
        self.value_labels["exit"].configure(text=circuit.exit_name)
        self.value_labels["routing"].configure(text="SOCKS5 hostname/TCP 443; app opt-in", fg=self.GREEN)
        self.value_labels["dns"].configure(text="Tor-side for proxied hostnames", fg=self.GREEN)
        self.value_labels["latency"].configure(text="Not measured")
        self.proxy_endpoint.configure(text=f"127.0.0.1:{self.config.proxy_port}  /  active")

    def _reset_connection_view(self) -> None:
        self.value_labels["relays"].configure(text="0 / 3", fg=self.TEXT)
        self.value_labels["exit"].configure(text="Not connected")
        self.value_labels["routing"].configure(text="Inactive", fg=self.TEXT)
        self.value_labels["dns"].configure(text="Inactive", fg=self.TEXT)
        self.value_labels["latency"].configure(text="—", fg=self.TEXT)
        self.proxy_endpoint.configure(text=f"127.0.0.1:{self.config.proxy_port}  /  inactive")

    def connect(self) -> None:
        if self.local_dev or self.status == "CONNECTING":
            return
        self._set_status("CONNECTING")
        self.connect_button.configure(state="disabled")
        self.settings_button.configure(state="disabled")
        self._log("Starting real Tor network connection. Browser traffic is accepted only through the loopback SOCKS5 adapter; no direct-route fallback is configured.")
        def worker() -> None:
            try:
                circuit = self.network.connect()
                self.messages.put(("connected", circuit))
            except Exception as exc:
                self.network.disconnect()
                self.messages.put(("error", f"{type(exc).__name__}: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def disconnect(self) -> None:
        if self.local_dev:
            return
        self.disconnect_button.configure(state="disabled")
        self._log("Stopping local proxy and Tor client.")
        def worker() -> None:
            self._stop_chrome_session()
            self.network.disconnect()
            self.messages.put(("disconnected", None))
        threading.Thread(target=worker, daemon=True).start()

    def open_chrome(self) -> None:
        """Launch a disposable Chrome profile using native unauthenticated SOCKS5."""
        if self.status != "CONNECTED" or not self.network.is_proxy_alive:
            messagebox.showwarning(
                "Project NULL",
                "Connect Project NULL before opening the proxied browser.",
                parent=self.root,
            )
            return
        if self.chrome_process is not None and self.chrome_process.poll() is None:
            messagebox.showinfo("Project NULL", "The Project NULL Chrome test session is already open.", parent=self.root)
            return
        proceed = messagebox.askyesno(
            "Chrome compatibility mode — not anonymity hardened",
            "This creates a fresh temporary Chrome profile using Chrome's native SOCKS5 proxy support. "
            "No proxy username/password or browser extension is used. The local SOCKS5 port has no authentication, "
            "so other local processes can use it while Project NULL is connected. This does NOT make Chrome "
            "equivalent to Tor Browser: fingerprinting and other identifying signals remain possible. Continue?",
            parent=self.root,
        )
        if not proceed:
            return
        if sys.platform != "darwin":
            messagebox.showinfo(
                "Browser setup",
                f"Configure a SOCKS5 proxy at 127.0.0.1:{self.config.proxy_port}. No browser proxy credentials are required.",
                parent=self.root,
            )
            return

        profile_dir: Optional[Path] = None
        try:
            chrome_binary = find_chrome_binary()
            if chrome_binary is None:
                raise FileNotFoundError("Google Chrome was not found in /Applications or your user Applications folder.")
            identity = self.identity_manager.current
            if identity is None:
                raise RuntimeError("No active local session is available.")
            # Include directory creation, chmod and profile setup in this error
            # boundary. Previously these calls were outside the try/except, so
            # a transient missing parent produced an uncaught Tkinter callback.
            ensure_private_directory(APP_DIR)
            session_root = APP_DIR / "browser-sessions"
            ensure_private_directory(session_root)
            profile_dir = session_root / f"chrome-{identity.session_id}"
            profile_dir.mkdir(parents=False, exist_ok=False, mode=0o700)
            self.chrome_session_dir = profile_dir
            ensure_private_directory(profile_dir)
            proxy = f"socks5://127.0.0.1:{self.config.proxy_port}"
            args = [
                str(chrome_binary),
                f"--user-data-dir={profile_dir}",
                f"--proxy-server={proxy}",
                # Chromium has implicit localhost/loopback proxy bypass rules.
                # <-loopback> removes those implicit exclusions for this profile.
                "--proxy-bypass-list=<-loopback>",
                # Chromium SOCKS5 URL loads resolve target hostnames through the proxy.
                # DNS prefetch is disabled separately; avoid host-resolver-rules because
                # recent Chrome builds warn on this command-line switch.
                "--disable-extensions",
                "--disable-quic",
                "--dns-prefetch-disable",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-sync",
                "--disable-background-mode",
                "--disable-background-networking",
                "--disable-component-update",
                "--no-first-run",
                "--no-default-browser-check",
            ]
            self.chrome_process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(profile_dir),
                close_fds=True,
                start_new_session=True,
            )
            # Do not report success solely because Popen returned. Detect a
            # very early launcher exit and surface an actionable error.
            time.sleep(0.35)
            if self.chrome_process.poll() is not None:
                code = self.chrome_process.returncode
                self.chrome_process = None
                raise RuntimeError(
                    f"Chrome exited immediately (exit code {code}). Check that Google Chrome is installed and can launch with a temporary profile."
                )
            self._log(f"Opened Chrome compatibility profile through native SOCKS5 proxy {proxy}; no proxy auth or extension required.")
            self._log("Chrome is not Tor Browser; this option is for compatibility testing, not high-anonymity browsing.")
            self._log("The loopback SOCKS5 listener has no local authentication; any local process can use it while connected.")
        except Exception as exc:
            self._stop_chrome_session()
            messagebox.showerror(
                "Could not open Chrome",
                f"{type(exc).__name__}: {exc}",
                parent=self.root,
            )

    def _stop_chrome_session(self) -> None:
        process, self.chrome_process = self.chrome_process, None
        profile_dir, self.chrome_session_dir = self.chrome_session_dir, None
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                try:
                    process.terminate()
                except OSError:
                    pass
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    try:
                        process.kill()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=3)
                except Exception:
                    pass
        if profile_dir is not None:
            shutil.rmtree(profile_dir, ignore_errors=True)

    def _cleanup_closed_chrome(self) -> None:
        if self.chrome_process is not None and self.chrome_process.poll() is not None:
            self._stop_chrome_session()
            self._log("Chrome test session exited; its temporary profile was removed.")

    def new_identity(self) -> None:
        identity = self.identity_manager.rotate()
        self._refresh_identity()
        if not self.local_dev:
            self.network.rotate_session(identity)
        else:
            self._log("New opaque local session label and random isolation secret generated; no network session exists in local-dev mode.")

    def run_diagnostics(self) -> None:
        if self.local_dev:
            suite = SelfTest()
            suite.check("Ephemeral session context", _test_identity_generation)
            suite.check("Routing configuration", _test_config_validation)
            suite.check("Remote DNS request encoding", _test_remote_dns_encoding)
            suite.check("Fail-closed SOCKS behavior", _test_fail_closed)
            self.messages.put(("local_diagnostics", suite))
            return
        if self.status != "CONNECTED":
            messagebox.showwarning("Diagnostics", "Connect to the Tor network first.", parent=self.root)
            return
        self.diag_button.configure(state="disabled")
        include_external = bool(self.external_check_var.get())
        self._log("Running diagnostics against the live Tor client.")
        if include_external:
            self._log("External IP check explicitly enabled; requesting check.torproject.org through the local SOCKS5 adapter.")
        def worker() -> None:
            try:
                results = self.network.diagnostics(include_external_ip=include_external)
                self.messages.put(("diagnostics", results))
            except Exception as exc:
                self.messages.put(("diagnostics_error", f"{type(exc).__name__}: {exc}"))
            finally:
                self.messages.put(("log", "Diagnostics finished."))
                self.messages.put(("enable_diag", None))
        threading.Thread(target=worker, daemon=True).start()

    def _render_diagnostics(self, data: dict[str, Any]) -> None:
        circuit: Optional[CircuitInfo] = data.get("circuit")
        checks = [
            ("Tor process", "PASS" if data["tor_process"] else "FAIL"),
            ("Local SOCKS5 proxy", "PASS" if data["local_proxy"] else "FAIL"),
            ("Tor bootstrap", f"{data['bootstrap_percent']}%"),
            ("Available general-purpose circuit", f"{circuit.relay_count} hops" if circuit else "FAIL / no built circuit"),
            ("Proxied hostname handling", "SOCKS5 domain-name request; Tor-side resolution by design (not a packet-capture audit)" if data["dns_remote_for_proxy"] else "FAIL"),
            ("SOCKS5 destination policy", data.get("proxy_policy", "unknown")),
            ("macOS system DNS", "UNCHANGED; not protected by this app"),
            ("System-wide tunnel", "NOT IMPLEMENTED"),
            ("Browser anti-fingerprinting", "NOT PROVIDED; use Tor Browser for anonymity"),
        ]
        if data["external_check_requested"]:
            checks.append(("External Tor check", "PASS" if data["external_tor_confirmed"] else "FAIL"))
            checks.append(("Observed public IP", data["observed_exit_ip"] or "Unavailable"))
            checks.append(("HTTP round-trip", f"{data['latency_ms']:.0f} ms" if data["latency_ms"] is not None else "Unavailable"))
            checks.append(("External result", data["external_message"]))
        else:
            checks.append(("External route verification", "NOT RUN — opt-in is disabled"))
        text = "\n".join(f"{name}: {value}" for name, value in checks)
        self._log("DIAGNOSTICS\n" + text.replace("\n", "\n  "))
        if circuit:
            self.value_labels["relays"].configure(text=f"{circuit.relay_count} / 3")
            self.value_labels["exit"].configure(text=circuit.exit_name)
        if data["latency_ms"] is not None:
            self.value_labels["latency"].configure(text=f"{data['latency_ms']:.0f} ms")
        if data["external_check_requested"] and data["external_tor_confirmed"]:
            self.value_labels["routing"].configure(text="Tor exit externally confirmed", fg=self.GREEN)
        elif data["external_check_requested"]:
            self.value_labels["routing"].configure(text="External check failed", fg=self.RED)
        else:
            self.value_labels["routing"].configure(text="Proxy structurally ready; unverified", fg=self.YELLOW)
        self.diag_button.configure(state="normal")

    def _render_local_diagnostics(self, suite: SelfTest) -> None:
        for line in suite.lines:
            self._log("LOCAL TEST  " + line)
        self._log("LOCAL DEV MODE: no relay availability or external routing has been tested.")

    def open_settings(self) -> None:
        if self.status in ("CONNECTED", "CONNECTING"):
            messagebox.showinfo("Settings", "Disconnect before changing port settings.", parent=self.root)
            return
        window = tk.Toplevel(self.root)
        window.title("Project NULL — Settings")
        window.configure(bg=self.BG)
        window.resizable(False, False)
        window.transient(self.root)
        frame = tk.Frame(window, bg=self.PANEL, padx=20, pady=18)
        frame.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(frame, text="LOCAL SOCKS5 PROXY", bg=self.PANEL, fg=self.TEXT,
                 font=("Menlo", 11, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        vars_by_name: dict[str, tk.StringVar] = {}
        tk.Label(frame, text="Browser SOCKS5 proxy port", bg=self.PANEL, fg=self.MUTED,
                 font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=5, padx=(0, 18))
        var = tk.StringVar(value=str(self.config.proxy_port))
        vars_by_name["proxy_port"] = var
        entry = tk.Entry(frame, textvariable=var, bg="#0b100d", fg=self.TEXT, insertbackground=self.GREEN,
                         relief="flat", width=10, font=("Menlo", 10))
        entry.grid(row=1, column=1, sticky="e", pady=5, ipady=5, ipadx=5)
        tk.Label(frame, text="Tor stream isolation", bg=self.PANEL, fg=self.MUTED,
                 font=("Arial", 10)).grid(row=2, column=0, sticky="w", pady=5, padx=(0, 18))
        isolation_var = tk.StringVar(value=self.config.stream_isolation)
        vars_by_name["stream_isolation"] = isolation_var
        isolation_menu = tk.OptionMenu(frame, isolation_var, "session", "hostname")
        isolation_menu.configure(bg="#0b100d", fg=self.TEXT, activebackground=self.PANEL_2,
                                 activeforeground=self.TEXT, highlightthickness=0, relief="flat")
        isolation_menu["menu"].configure(bg=self.PANEL_2, fg=self.TEXT)
        isolation_menu.grid(row=2, column=1, sticky="e", pady=5)
        tk.Label(frame, text="session = faster: all destinations in this browser session can share Tor circuits. hostname = stricter separation: each hostname gets its own isolation group and may create more circuits, making pages slower. The default is session.",
                 bg=self.PANEL, fg=self.MUTED, wraplength=360, justify="left", font=("Arial", 9)).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 8))
        tk.Label(frame, text="The browser-facing SOCKS5 listener is unauthenticated and loopback-only; any local process can use it while connected. Tor Control and Tor SOCKS remain private Unix sockets. This is not a system-wide VPN or kill switch.",
                 bg=self.PANEL, fg=self.MUTED, wraplength=360, justify="left", font=("Arial", 9)).grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 16))
        def apply() -> None:
            try:
                new_config = AppConfig(
                    proxy_port=int(vars_by_name["proxy_port"].get()),
                    stream_isolation=vars_by_name["stream_isolation"].get(),
                )
                new_config.validate()
                ConfigStore.save(new_config)
                self.config = new_config
                self.network = TorNetwork(new_config, self.identity_manager, self._post_log)
                self._reset_connection_view()
                self.proxy_endpoint.configure(text=f"127.0.0.1:{new_config.proxy_port}  /  inactive")
                self.messages.put(("settings_applied", None))
                window.destroy()
            except Exception as exc:
                messagebox.showerror("Invalid settings", str(exc), parent=window)
        buttons = tk.Frame(frame, bg=self.PANEL)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e")
        self._make_button(buttons, "CANCEL", window.destroy, primary=False).pack(side="left", padx=(0, 8))
        self._make_button(buttons, "SAVE", apply, primary=True).pack(side="left")
        window.grab_set()

    def on_close(self) -> None:
        self._stop_chrome_session()
        self._log("Closing Project NULL; cancelling startup and stopping managed network resources.")
        self.network.shutdown()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def startup_validation(local_dev: bool) -> None:
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required.")
    if not local_dev:
        try:
            import stem  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("Missing dependency: Stem. Install with `python -m pip install stem`.") from exc
    if TK_IMPORT_ERROR is not None:
        minor = f"{sys.version_info.major}.{sys.version_info.minor}"
        raise RuntimeError(
            "Tkinter is unavailable in this Python installation. "
            "Run ./setup_macos.sh to create the supported GUI environment. "
            f"Original import error: {TK_IMPORT_ERROR}"
        ) from TK_IMPORT_ERROR


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Project NULL {APP_VERSION} — Tor-backed loopback SOCKS5 proxy prototype")
    parser.add_argument("--version", action="version", version=f"Project NULL {APP_VERSION}")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--self-test", action="store_true", help="Run offline self-tests; live relay test is marked SKIP.")
    modes.add_argument("--self-test-live", action="store_true", help="Run tests, bootstrap Tor, build a real circuit, and verify the Tor exit IP.")
    modes.add_argument("--local-dev", action="store_true", help="Open the dashboard with networking disabled; no simulated relays or traffic.")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests(live=False)
    if args.self_test_live:
        try:
            import stem  # noqa: F401
        except ImportError:
            print("FAIL: Stem is not installed. Run: python -m pip install stem")
            return 1
        return run_self_tests(live=True)

    try:
        startup_validation(local_dev=args.local_dev)
        config = ConfigStore.load()
        app = ProjectNullApp(config, local_dev=args.local_dev)
        app.run()
        return 0
    except Exception as exc:
        print(f"Project NULL startup error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
