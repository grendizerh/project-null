#!/usr/bin/env python3
"""Project NULL — a Tor-backed, loopback-only HTTPS proxy prototype.

Python 3.11+. This is NOT a system-wide VPN. It exposes a local HTTP CONNECT
proxy for explicitly configured applications and forwards every CONNECT through
Tor SOCKS5. No direct-connect fallback exists in the proxy.

Cryptographic session keys are ephemeral and RAM-only. The Ed25519 key derives
an opaque session label and a Tor SOCKS stream-isolation token; it is NOT a Tor
network identity and does not authenticate the client to Tor relays.
"""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import queue
import re
import secrets
import select
import shutil
import socket
import socketserver
import ssl
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

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    CRYPTO_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:  # Startup validation reports the actionable error.
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    CRYPTO_IMPORT_ERROR = exc

APP_NAME = "PROJECT NULL"
APP_DIR = Path.home() / "Library" / "Application Support" / "Project NULL"
CONFIG_PATH = APP_DIR / "config.json"
TOR_DATA_DIR = APP_DIR / "tor-data"


# ---------------------------------------------------------------------------
# Configuration and identity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AppConfig:
    socks_port: int = 29050
    control_port: int = 29150
    proxy_port: int = 28080
    bootstrap_timeout: int = 180
    circuit_timeout: int = 90

    def validate(self) -> None:
        ports = (self.socks_port, self.control_port, self.proxy_port)
        if any(not isinstance(p, int) or p < 1024 or p > 65535 for p in ports):
            raise ValueError("Ports must be integers between 1024 and 65535.")
        if len(set(ports)) != 3:
            raise ValueError("SOCKS, Control, and local proxy ports must be different.")
        if self.bootstrap_timeout < 30 or self.bootstrap_timeout > 600:
            raise ValueError("Bootstrap timeout must be between 30 and 600 seconds.")
        if self.circuit_timeout < 15 or self.circuit_timeout > 300:
            raise ValueError("Circuit timeout must be between 15 and 300 seconds.")


class ConfigStore:
    @staticmethod
    def load() -> AppConfig:
        if not CONFIG_PATH.exists():
            return AppConfig()
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            allowed = {"socks_port", "control_port", "proxy_port"}
            clean = {k: int(v) for k, v in raw.items() if k in allowed}
            config = AppConfig(**clean)
            config.validate()
            return config
        except Exception:
            # Do not silently use a partially valid configuration.
            raise RuntimeError(f"Invalid configuration file: {CONFIG_PATH}. Open Settings or remove the file.")

    @staticmethod
    def save(config: AppConfig) -> None:
        config.validate()
        APP_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(APP_DIR, 0o700)
        except OSError:
            pass
        payload = {
            "socks_port": config.socks_port,
            "control_port": config.control_port,
            "proxy_port": config.proxy_port,
        }
        temp_path = CONFIG_PATH.with_suffix(".tmp")
        temp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        temp_path.replace(CONFIG_PATH)


@dataclass
class SessionIdentity:
    session_id: str
    public_fingerprint: str
    isolation_token: str
    private_key: Any

    def __repr__(self) -> str:
        # Never let repr/debug logs accidentally include key material.
        return (
            f"SessionIdentity(session_id={self.session_id!r}, "
            f"public_fingerprint={self.public_fingerprint!r}, private_key=<redacted>)"
        )


class IdentityManager:
    """Ephemeral Ed25519 identity. Private key is kept in process memory only."""

    def __init__(self) -> None:
        self.current: Optional[SessionIdentity] = None
        self.rotate()

    def rotate(self) -> SessionIdentity:
        if CRYPTO_IMPORT_ERROR is not None:
            raise RuntimeError("cryptography is required. Install it with: python -m pip install cryptography")
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        nonce = secrets.token_bytes(32)
        fingerprint = hashlib.sha256(public_bytes).hexdigest().upper()
        session_id = hashlib.sha256(b"PROJECT-NULL-SESSION-v1" + public_bytes + nonce).hexdigest()[:24].upper()

        # Standard HMAC-SHA256 over an ephemeral nonce derives a Tor stream
        # isolation value. It is not an encryption algorithm or a Tor identity.
        private_raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        isolation_token = hmac.new(
            private_raw,
            b"PROJECT-NULL-TOR-ISOLATION-v1" + nonce,
            hashlib.sha256,
        ).hexdigest()
        # Best-effort clearing of the temporary mutable copy. Python cannot
        # guarantee zeroization of immutable objects or crypto-library memory.
        scratch = bytearray(private_raw)
        for i in range(len(scratch)):
            scratch[i] = 0
        self.current = SessionIdentity(
            session_id=session_id,
            public_fingerprint=fingerprint,
            isolation_token=isolation_token,
            private_key=private_key,
        )
        return self.current


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


def socks5_connect(
    host: str,
    port: int,
    socks_host: str,
    socks_port: int,
    isolation_token: str,
    timeout: float = 90.0,
) -> socket.socket:
    """Open a TCP stream through Tor; never attempts a direct destination socket.

    Timeout errors identify the exact SOCKS phase. A fresh IsolateSOCKSAuth
    credential can require Tor to construct a separate circuit, so the default
    timeout is longer than the old 25-second value.
    """
    stage = "connecting to the Tor SOCKS listener"
    upstream: Optional[socket.socket] = None
    try:
        upstream = socket.create_connection((socks_host, socks_port), timeout=timeout)
        upstream.settimeout(timeout)

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
        if reply[0] != 5:
            raise ConnectionError("Invalid SOCKS5 response from Tor.")
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
# Local HTTP CONNECT proxy. It is loopback-only and HTTPS-tunnel-only.
# ---------------------------------------------------------------------------

class NullConnectProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(30)
        upstream: Optional[socket.socket] = None
        reader = None
        tunnel_established = False
        stage = "reading browser CONNECT headers"
        try:
            # IMPORTANT: unbuffered reads prevent makefile() from consuming
            # Chrome's TLS ClientHello bytes after the end of CONNECT headers.
            reader = client.makefile("rb", buffering=0)
            request_line = reader.readline(8192)
            if not request_line or len(request_line) >= 8192:
                self._reply(400, "Bad Request")
                return
            parts = request_line.decode("iso-8859-1").strip().split()
            if len(parts) != 3:
                self._reply(400, "Bad Request")
                return
            method, target, _version = parts
            header_bytes = 0
            while True:
                line = reader.readline(8192)
                if not line:
                    self._reply(400, "Incomplete Headers")
                    return
                header_bytes += len(line)
                if header_bytes > 65536:
                    self._reply(431, "Request Header Fields Too Large")
                    return
                if line in (b"\r\n", b"\n"):
                    break
                if line.lower().startswith(b"proxy-authorization:"):
                    self._reply(400, "Proxy Authentication Is Not Supported")
                    return

            if method.upper() != "CONNECT":
                self._reply(501, "HTTPS CONNECT Only")
                return
            host, port = self._parse_authority(target)
            token = self.server.session_token  # type: ignore[attr-defined]

            stage = "opening a Tor-isolated SOCKS stream"
            self.server.log_callback(  # type: ignore[attr-defined]
                "Proxy CONNECT received; requesting an isolated Tor stream."
            )
            upstream = socks5_connect(
                host,
                port,
                self.server.socks_host,  # type: ignore[attr-defined]
                self.server.socks_port,  # type: ignore[attr-defined]
                token,
                timeout=90.0,
            )

            stage = "sending HTTP 200 CONNECT response"
            client.sendall(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: Project-NULL\r\n\r\n"
            )
            tunnel_established = True
            client.settimeout(None)
            self.server.log_callback(  # type: ignore[attr-defined]
                "Proxy CONNECT established through Tor; relaying encrypted tunnel."
            )
            self._relay(client, upstream)
        except (OSError, ValueError, ConnectionError) as exc:
            # Do not log the target hostname or any isolation/session material.
            if isinstance(exc, TimeoutError):
                detail = f"Proxy request timed out while {stage}: {exc}"
            else:
                detail = f"Proxy connection blocked during {stage}: {type(exc).__name__}: {exc}"
            self.server.log_callback(detail)  # type: ignore[attr-defined]
            if not tunnel_established:
                try:
                    self._reply(502, "Tor Upstream Unavailable")
                except OSError:
                    pass
        finally:
            if reader is not None:
                try:
                    reader.close()
                except OSError:
                    pass
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    @staticmethod
    def _parse_authority(authority: str) -> tuple[str, int]:
        if authority.startswith("["):
            end = authority.find("]")
            if end < 0 or end + 1 >= len(authority) or authority[end + 1] != ":":
                raise ValueError("Invalid CONNECT authority.")
            host = authority[1:end]
            port_text = authority[end + 2:]
        else:
            host, sep, port_text = authority.rpartition(":")
            if not sep:
                raise ValueError("CONNECT must include a destination port.")
        if not host or any(c in host for c in "\r\n\x00"):
            raise ValueError("Invalid destination hostname.")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("Invalid destination port.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Destination port is out of range.")
        return host, port

    def _reply(self, code: int, phrase: str) -> None:
        body = (phrase + "\n").encode("utf-8")
        response = (
            f"HTTP/1.1 {code} {phrase}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        self.request.sendall(response)

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        peers = {left: right, right: left}
        active = [left, right]
        while active:
            readable, _, _ = select.select(active, [], [], 60)
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
                destination.sendall(data)


class NullConnectProxyServer(socketserver.ThreadingTCPServer):
    # Permit fast, safe rebind after shutdown when the old connection is in TIME_WAIT.
    # A currently listening socket still prevents binding to the same loopback endpoint.
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True

    def __init__(
        self,
        port: int,
        socks_port: int,
        session_token: str,
        log_callback: Callable[[str], None],
    ) -> None:
        self.socks_host = "127.0.0.1"
        self.socks_port = socks_port
        self.session_token = session_token
        self.log_callback = log_callback
        # Explicit loopback bind: never expose an unauthenticated proxy to the LAN.
        super().__init__(("127.0.0.1", port), NullConnectProxyHandler)


# ---------------------------------------------------------------------------
# Tor process / controller
# ---------------------------------------------------------------------------

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
    """Find Tor, preferring an explicit per-process override.

    PROJECT_NULL_TOR_BINARY avoids ambiguous PATH selection when multiple Tor
    installations exist (for example, an old Homebrew service and a local
    Tor Expert Bundle). The override is validated and never silently ignored.
    """
    explicit = os.environ.get("PROJECT_NULL_TOR_BINARY", "").strip()
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_file():
            raise FileNotFoundError(
                f"PROJECT_NULL_TOR_BINARY does not point to a file: {candidate}"
            )
        if not os.access(candidate, os.X_OK):
            raise PermissionError(
                f"PROJECT_NULL_TOR_BINARY is not executable: {candidate}"
            )
        return str(candidate.resolve())

    # Prefer the per-user Expert Bundle installed by setup_macos.sh. This
    # prevents an older Homebrew Tor earlier on PATH from being selected.
    home = Path.home()
    candidates = (
        home / "Applications" / "ProjectNULL" / "tor-expert-16.0" / "tor" / "tor",
        home / ".local" / "share" / "project-null" / "tor" / "tor",
        Path("/opt/homebrew/bin/tor"),
        Path("/opt/homebrew/opt/tor/bin/tor"),
        Path("/usr/local/bin/tor"),
        Path("/usr/local/opt/tor/bin/tor"),
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
    found = shutil.which("tor")
    if found:
        return str(Path(found).resolve())
    return None


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
        self.proxy: Optional[NullConnectProxyServer] = None
        self.proxy_thread: Optional[threading.Thread] = None
        self.tor_log_thread: Optional[threading.Thread] = None
        # Retain recent Tor output so unexpected exits include their real cause.
        self.tor_log_tail: deque[str] = deque(maxlen=100)
        self._connect_lock = threading.Lock()
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

    @staticmethod
    def _tor_quote(path: Path) -> str:
        value = str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{value}"'

    def _write_torrc(self) -> Path:
        TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(TOR_DATA_DIR, 0o700)
        except OSError:
            pass
        torrc = APP_DIR / "torrc-project-null"
        content = "\n".join((
            f"DataDirectory {self._tor_quote(TOR_DATA_DIR)}",
            f"SocksPort 127.0.0.1:{self.config.socks_port} IsolateSOCKSAuth",
            "SocksPolicy accept 127.0.0.1",
            f"ControlPort 127.0.0.1:{self.config.control_port}",
            "CookieAuthentication 1",
            f"__OwningControllerProcess {os.getpid()}",
            "ClientOnly 1",
            "SafeLogging 1",
            "Log notice stdout",
            "",
        ))
        torrc.write_text(content, encoding="utf-8")
        try:
            os.chmod(torrc, 0o600)
        except OSError:
            pass
        return torrc

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
                    self._log("Tor SOCKS listener opened on loopback.")
                elif "opening control listener" in lower:
                    self._log("Tor Control listener opened on loopback.")
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

    def _connect_controller(self, deadline: float) -> Any:
        try:
            from stem.control import Controller
        except ImportError as exc:
            raise RuntimeError("Stem is required for Tor control. Install it with: python -m pip install stem") from exc
        last_error: Optional[Exception] = None
        while time.monotonic() < deadline:
            if not self.is_process_alive:
                code = self.process.returncode if self.process else "unknown"
                raise RuntimeError(f"Tor exited during startup (code {code}). Check the event log and Tor installation.")
            controller = None
            try:
                controller = Controller.from_port(address="127.0.0.1", port=self.config.control_port)
                controller.authenticate()  # CookieAuthentication; no open/no-auth control port.
                return controller
            except Exception as exc:
                last_error = exc
                if controller is not None:
                    try:
                        controller.close()
                    except Exception:
                        pass
                time.sleep(0.5)
        raise TimeoutError(f"Timed out connecting to Tor ControlPort: {last_error}")

    @staticmethod
    def _bootstrap_progress(controller: Any) -> int:
        try:
            status = controller.get_info("status/bootstrap-phase")
            match = re.search(r"PROGRESS=(\d+)", status)
            return int(match.group(1)) if match else 0
        except Exception:
            return 0

    @staticmethod
    def _built_general_circuit(controller: Any) -> Optional[CircuitInfo]:
        try:
            from stem import CircStatus
            circuits = controller.get_circuits()
            candidates = [
                c for c in circuits
                if c.status == CircStatus.BUILT and c.purpose == "GENERAL" and len(c.path) >= 3
            ]
            if not candidates:
                return None
            # Prefer the shortest, standard three-hop general circuit.
            chosen = min(candidates, key=lambda c: (len(c.path), int(c.id)))
            return CircuitInfo(str(chosen.id), [(fp, nick) for fp, nick in chosen.path])
        except Exception:
            return None

    def connect(self) -> CircuitInfo:
        with self._connect_lock:
            if self.is_process_alive or self.proxy is not None:
                raise RuntimeError("Project NULL is already running.")
            self.config.validate()
            tor_binary = find_tor_binary()
            if not tor_binary:
                raise RuntimeError("Tor executable not found. Run ./setup_macos.sh to install the verified per-user Tor bundle.")
            self.tor_binary = tor_binary
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
            if tor_version < (0, 4, 9, 15):
                raise RuntimeError(
                    f"Tor {'.'.join(map(str, tor_version))} is too old for current "
                    "Tor network requirements. Install Tor 0.4.9.15 or newer."
                )
            version_line = next(
                (line.strip() for line in version_text.splitlines() if line.strip()),
                "Tor version unknown",
            )
            self._log(version_line)
            for name, port in (
                ("Tor SOCKS", self.config.socks_port),
                ("Tor Control", self.config.control_port),
                ("Project NULL HTTP proxy", self.config.proxy_port),
            ):
                if not port_is_available("127.0.0.1", port):
                    raise RuntimeError(f"{name} port 127.0.0.1:{port} is already in use. Change it in Settings; refusing to attach to an unknown service.")

            APP_DIR.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(APP_DIR, 0o700)
            except OSError:
                pass
            torrc = self._write_torrc()
            self._stopping = False
            self._log(f"Starting Tor client: {Path(tor_binary).name}")
            try:
                self.process = subprocess.Popen(
                    [tor_binary, "-f", str(torrc)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=str(APP_DIR),
                    close_fds=True,
                )
                self.tor_log_thread = threading.Thread(target=self._read_tor_logs, daemon=True)
                self.tor_log_thread.start()
                deadline = time.monotonic() + 35
                self.controller = self._connect_controller(deadline)
                self._log("Tor ControlPort authenticated with cookie authentication.")

                bootstrap_deadline = time.monotonic() + self.config.bootstrap_timeout
                last_progress = -1
                while time.monotonic() < bootstrap_deadline:
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

                self._log("Tor network bootstrap completed. Waiting for a real three-hop circuit.")
                circuit_deadline = time.monotonic() + self.config.circuit_timeout
                circuit = self._built_general_circuit(self.controller)
                while circuit is None and time.monotonic() < circuit_deadline:
                    time.sleep(1)
                    circuit = self._built_general_circuit(self.controller)
                if circuit is None:
                    # Ask Tor to construct a normal general-purpose circuit.
                    try:
                        circuit_id = self.controller.new_circuit(await_build=True)
                        actual = self.controller.get_circuit(circuit_id)
                        if len(actual.path) >= 3:
                            circuit = CircuitInfo(str(actual.id), [(fp, nick) for fp, nick in actual.path])
                    except Exception as exc:
                        self._log(f"Tor could not build a circuit: {type(exc).__name__}")
                if circuit is None or circuit.relay_count < 3:
                    raise RuntimeError("No built three-hop Tor circuit is available. No traffic will be sent directly.")

                identity = self.identity_manager.current
                if identity is None:
                    raise RuntimeError("No active cryptographic session identity.")
                self.proxy = NullConnectProxyServer(
                    self.config.proxy_port,
                    self.config.socks_port,
                    identity.isolation_token,
                    self._log,
                )
                self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
                self.proxy_thread.start()
                self.last_circuit = circuit
                self._log(f"Built Tor circuit: {circuit.route_text}")
                self._log(f"Local HTTPS proxy listening on 127.0.0.1:{self.config.proxy_port}.")
                self._log("Ready for applications explicitly configured to use the local proxy.")
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

    def rotate_session(self, identity: SessionIdentity) -> None:
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
        """Explicit opt-in check. It traverses the local CONNECT proxy, never direct."""
        started = time.perf_counter()
        connection: Optional[http.client.HTTPSConnection] = None
        try:
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                self.config.proxy_port,
                timeout=30,
                context=self._verified_tls_context(),
            )
            connection.set_tunnel("check.torproject.org", 443)
            connection.request(
                "GET",
                "/api/ip",
                headers={"Accept": "application/json", "User-Agent": "Project-NULL-Diagnostics/1.0", "Connection": "close"},
            )
            response = connection.getresponse()
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
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def diagnostics(self, include_external_ip: bool) -> dict[str, Any]:
        results: dict[str, Any] = {
            "tor_process": self.is_process_alive,
            "local_proxy": self.is_proxy_alive,
            "bootstrap_percent": self._bootstrap_progress(self.controller) if self.controller else 0,
            "circuit": self.refresh_circuit(),
            "dns_remote_for_proxy": True,
            "system_dns_changed": False,
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
        self._stopping = True
        proxy, self.proxy = self.proxy, None
        self.proxy_thread = None
        if proxy is not None:
            try:
                proxy.shutdown()
                proxy.server_close()
            except Exception:
                pass
        controller, self.controller = self.controller, None
        if controller is not None:
            try:
                from stem import Signal
                controller.signal(Signal.SHUTDOWN)
            except Exception:
                pass
            try:
                controller.close()
            except Exception:
                pass
        process, self.process = self.process, None
        if process is not None:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            except Exception:
                pass
        self.last_circuit = None


# ---------------------------------------------------------------------------
# Self-test suite
# ---------------------------------------------------------------------------

class SelfTest:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.lines: list[str] = []

    def check(self, name: str, callback: Callable[[], None]) -> None:
        try:
            callback()
            self.passed += 1
            self.lines.append(f"PASS  {name}")
        except Exception as exc:
            self.failed += 1
            self.lines.append(f"FAIL  {name}: {type(exc).__name__}: {exc}")

    def skip(self, name: str, detail: str) -> None:
        self.skipped += 1
        self.lines.append(f"SKIP  {name}: {detail}")

    def report(self) -> int:
        print("\nPROJECT NULL — SELF TEST")
        print("=" * 64)
        for line in self.lines:
            print(line)
        print("-" * 64)
        print(f"Passed: {self.passed}   Failed: {self.failed}   Skipped: {self.skipped}")
        return 1 if self.failed else 0


def run_self_tests(live: bool = False) -> int:
    suite = SelfTest()
    suite.check("Ed25519 identity generation", lambda: _test_identity_generation())
    suite.check("Session identity regeneration", lambda: _test_identity_rotation())
    suite.check("Private-key serialization and signature verification", lambda: _test_key_handling())
    suite.check("Routing configuration validation", lambda: _test_config_validation())
    suite.check("Remote-DNS SOCKS target encoding", lambda: _test_remote_dns_encoding())
    suite.check("Fail-closed SOCKS upstream handling", lambda: _test_fail_closed())
    suite.check("Loopback-only proxy bind policy", lambda: _test_proxy_bind_policy())
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
                suite.check("Proxied hostname resolution does not use local DNS", lambda: _test_remote_dns_encoding())
            finally:
                network.disconnect()
        except Exception as exc:
            suite.check("Live Tor relay availability and routed IP check", lambda: (_ for _ in ()).throw(exc))
    else:
        suite.skip(
            "Live relay availability",
            "not tested offline; run `python project_null.py --self-test-live` to bootstrap Tor and verify a real three-hop circuit.",
        )
    return suite.report()


def _test_identity_generation() -> None:
    identity = IdentityManager().current
    assert identity is not None
    assert len(identity.session_id) == 24
    assert len(identity.public_fingerprint) == 64
    assert len(identity.isolation_token) == 64
    assert identity.private_key is not None


def _test_identity_rotation() -> None:
    manager = IdentityManager()
    first = manager.current
    second = manager.rotate()
    assert first is not None and second is not None
    assert first.session_id != second.session_id
    assert first.public_fingerprint != second.public_fingerprint
    assert first.isolation_token != second.isolation_token


def _test_key_handling() -> None:
    manager = IdentityManager()
    identity = manager.current
    assert identity is not None
    challenge = secrets.token_bytes(64)
    signature = identity.private_key.sign(challenge)
    identity.private_key.public_key().verify(signature, challenge)
    raw = identity.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    restored = Ed25519PrivateKey.from_private_bytes(raw)
    restored.public_key().verify(signature, challenge)
    assert "private_key=<redacted>" in repr(identity)


def _test_config_validation() -> None:
    AppConfig().validate()
    try:
        AppConfig(socks_port=19050, control_port=19050, proxy_port=18080).validate()
    except ValueError:
        pass
    else:
        raise AssertionError("Duplicate ports were accepted.")
    try:
        AppConfig(proxy_port=80).validate()
    except ValueError:
        pass
    else:
        raise AssertionError("Privileged port was accepted.")


def _test_remote_dns_encoding() -> None:
    encoded = encode_socks_target("www.example.com", 443)
    assert encoded[:4] == b"\x05\x01\x00\x03"
    length = encoded[4]
    assert encoded[5:5 + length] == b"www.example.com"
    assert int.from_bytes(encoded[-2:], "big") == 443


def _test_fail_closed() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    try:
        socks5_connect("example.com", 443, "127.0.0.1", port, "a" * 64, timeout=0.5)
    except OSError:
        return
    raise AssertionError("SOCKS failure did not stop the request.")


def _test_proxy_bind_policy() -> None:
    # Verify the implementation's bind address contract without starting a listener.
    assert NullConnectProxyServer.__mro__[1] is socketserver.ThreadingTCPServer
    assert "127.0.0.1" in NullConnectProxyServer.__init__.__code__.co_consts


# ---------------------------------------------------------------------------
# Tkinter dashboard
# ---------------------------------------------------------------------------

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
        self.messages: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.root = tk.Tk()
        self.root.title("PROJECT NULL — Privacy Network Prototype")
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

    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, bg=self.BG, padx=24, pady=22)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=self.BG)
        header.pack(fill="x", pady=(0, 18))
        brand = tk.Frame(header, bg=self.BG)
        brand.pack(side="left", anchor="w")
        tk.Label(brand, text="PROJECT NULL", bg=self.BG, fg=self.TEXT,
                 font=("Menlo", 22, "bold")).pack(anchor="w")
        tk.Label(brand, text="PRIVACY NETWORK PROTOTYPE  /  TOR CLIENT", bg=self.BG,
                 fg=self.MUTED, font=("Menlo", 9)).pack(anchor="w", pady=(4, 0))
        self.status_label = tk.Label(header, text="DISCONNECTED", bg=self.PANEL_2,
                                     fg=self.MUTED, font=("Menlo", 10, "bold"),
                                     padx=14, pady=8)
        self.status_label.pack(side="right", anchor="e")

        warning = tk.Frame(outer, bg="#191b12", highlightbackground="#47402a", highlightthickness=1, padx=12, pady=10)
        warning.pack(fill="x", pady=(0, 16))
        tk.Label(warning, text="SCOPE", bg="#191b12", fg=self.YELLOW,
                 font=("Menlo", 9, "bold")).pack(side="left", padx=(0, 12))
        tk.Label(warning, text="Only applications explicitly configured for the local HTTPS proxy are routed. Websites see the Tor exit IP; the entry relay can see your source IP. This is not a system-wide VPN or kill switch.",
                 bg="#191b12", fg="#c9c6b4", font=("Arial", 10), anchor="w", justify="left",
                 wraplength=820).pack(side="left", fill="x", expand=True)

        grid = tk.Frame(outer, bg=self.BG)
        grid.pack(fill="x")
        self.value_labels: dict[str, tk.Label] = {}
        cards = [
            ("SESSION IDENTITY", "session", "—"),
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
        tk.Label(proxy_line, text="LOCAL HTTPS PROXY", bg=self.PANEL_2, fg=self.MUTED,
                 font=("Menlo", 8, "bold")).pack(side="left")
        self.proxy_endpoint = tk.Label(proxy_line, text="127.0.0.1:18080  /  inactive", bg=self.PANEL_2,
                                       fg=self.TEXT, font=("Menlo", 10))
        self.proxy_endpoint.pack(side="right")

        controls = tk.Frame(outer, bg=self.BG)
        controls.pack(fill="x", pady=(0, 12))
        self.connect_button = self._make_button(controls, "CONNECT", self.connect, primary=True)
        self.disconnect_button = self._make_button(controls, "DISCONNECT", self.disconnect, primary=False)
        self.identity_button = self._make_button(controls, "NEW IDENTITY", self.new_identity, primary=False)
        self.diag_button = self._make_button(controls, "RUN DIAGNOSTICS", self.run_diagnostics, primary=False)
        self.settings_button = self._make_button(controls, "SETTINGS", self.open_settings, primary=False)
        self.chrome_button = self._make_button(controls, "OPEN CHROME", self.open_chrome, primary=False)
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
        tk.Label(log_header, text="SESSION-LOCAL  /  PRIVATE KEYS NEVER LOGGED", bg=self.BG,
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

    def _make_button(self, parent: tk.Widget, text: str, command: Callable[[], None], primary: bool) -> tk.Button:
        bg = "#1d3c2b" if primary else self.PANEL_2
        fg = self.GREEN if primary else self.TEXT
        return tk.Button(
            parent, text=text, command=command, bg=bg, fg=fg, activebackground="#274d37",
            activeforeground="white", disabledforeground="#56635a", relief="flat",
            bd=0, padx=13, pady=10, font=("Menlo", 8, "bold"), cursor="hand2",
        )

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
        self.value_labels["routing"].configure(text="Proxy ready; browser opt-in", fg=self.GREEN)
        self.value_labels["dns"].configure(text="Remote for proxied hosts", fg=self.GREEN)
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
        self._log("Starting real Tor network connection. No direct-route fallback is configured.")
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
            self.network.disconnect()
            self.messages.put(("disconnected", None))
        threading.Thread(target=worker, daemon=True).start()

    def open_chrome(self) -> None:
        """Open a dedicated Chrome profile configured for the loopback proxy."""
        if self.status != "CONNECTED" or not self.network.is_proxy_alive:
            messagebox.showwarning(
                "Project NULL",
                "Connect Project NULL before opening the proxied browser.",
                parent=self.root,
            )
            return
        if sys.platform != "darwin":
            messagebox.showinfo(
                "Browser setup",
                f"Set your browser's HTTP proxy to 127.0.0.1:{self.config.proxy_port}.",
                parent=self.root,
            )
            return
        try:
            check = subprocess.run(
                ["open", "-Ra", "Google Chrome"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
            if check.returncode != 0:
                raise FileNotFoundError("Google Chrome was not found in Applications.")
            profile = Path.home() / "Project-NULL-Chrome"
            profile.mkdir(parents=True, exist_ok=True)
            proxy = f"http://127.0.0.1:{self.config.proxy_port}"
            subprocess.Popen(
                [
                    "open", "-na", "Google Chrome", "--args",
                    f"--user-data-dir={profile}",
                    f"--proxy-server={proxy}",
                    "--disable-quic",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self._log(f"Opened dedicated Chrome profile through {proxy}.")
            self._log("Only this Chrome profile is configured for Project NULL; other apps are not routed.")
        except Exception as exc:
            messagebox.showerror(
                "Could not open Chrome",
                f"{type(exc).__name__}: {exc}\n\n"
                f"Configure another browser's HTTP proxy manually: "
                f"127.0.0.1:{self.config.proxy_port}",
                parent=self.root,
            )

    def new_identity(self) -> None:
        identity = self.identity_manager.rotate()
        self._refresh_identity()
        if not self.local_dev:
            self.network.rotate_session(identity)
        else:
            self._log("New local Ed25519 session identity generated. No network session exists in local-dev mode.")

    def run_diagnostics(self) -> None:
        if self.local_dev:
            suite = SelfTest()
            suite.check("Ed25519 identity", _test_identity_generation)
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
            self._log("External IP check explicitly enabled; requesting check.torproject.org through the local proxy.")
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
            ("Local HTTPS proxy", "PASS" if data["local_proxy"] else "FAIL"),
            ("Tor bootstrap", f"{data['bootstrap_percent']}%"),
            ("Built relay path", f"{circuit.relay_count} hops" if circuit else "FAIL / no built circuit"),
            ("Proxy DNS", "REMOTE through Tor SOCKS (design verified)" if data["dns_remote_for_proxy"] else "FAIL"),
            ("macOS system DNS", "UNCHANGED; other applications are outside this proxy"),
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
        tk.Label(frame, text="LOOPBACK PORTS", bg=self.PANEL, fg=self.TEXT,
                 font=("Menlo", 11, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        vars_by_name: dict[str, tk.StringVar] = {}
        for row, (label, key) in enumerate((
            ("Tor SOCKS", "socks_port"),
            ("Tor Control", "control_port"),
            ("Browser HTTP proxy", "proxy_port"),
        ), start=1):
            tk.Label(frame, text=label, bg=self.PANEL, fg=self.MUTED, font=("Arial", 10)).grid(row=row, column=0, sticky="w", pady=5, padx=(0, 18))
            var = tk.StringVar(value=str(getattr(self.config, key)))
            vars_by_name[key] = var
            entry = tk.Entry(frame, textvariable=var, bg="#0b100d", fg=self.TEXT, insertbackground=self.GREEN,
                             relief="flat", width=10, font=("Menlo", 10))
            entry.grid(row=row, column=1, sticky="e", pady=5, ipady=5, ipadx=5)
        tk.Label(frame, text="All listeners bind to 127.0.0.1. Changing ports does not create a VPN kill switch.",
                 bg=self.PANEL, fg=self.MUTED, wraplength=360, justify="left", font=("Arial", 9)).grid(row=4, column=0, columnspan=2, sticky="w", pady=(12, 16))
        def apply() -> None:
            try:
                new_config = AppConfig(
                    socks_port=int(vars_by_name["socks_port"].get()),
                    control_port=int(vars_by_name["control_port"].get()),
                    proxy_port=int(vars_by_name["proxy_port"].get()),
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
        tk.Button(buttons, text="CANCEL", command=window.destroy, bg=self.PANEL_2, fg=self.TEXT,
                  relief="flat", padx=12, pady=7).pack(side="left", padx=(0, 8))
        tk.Button(buttons, text="SAVE", command=apply, bg="#1d3c2b", fg=self.GREEN,
                  relief="flat", padx=16, pady=7).pack(side="left")
        window.grab_set()

    def on_close(self) -> None:
        if self.network.is_process_alive or self.network.proxy is not None:
            self._log("Closing Project NULL and stopping Tor.")
            self.network.disconnect()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def startup_validation(local_dev: bool) -> None:
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required.")
    if CRYPTO_IMPORT_ERROR is not None:
        raise RuntimeError("Missing dependency: cryptography. Install with `python -m pip install cryptography`.")
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
    parser = argparse.ArgumentParser(description="Project NULL — Tor-backed HTTPS proxy prototype")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--self-test", action="store_true", help="Run offline self-tests; live relay test is marked SKIP.")
    modes.add_argument("--self-test-live", action="store_true", help="Run tests, bootstrap Tor, build a real circuit, and verify the Tor exit IP.")
    modes.add_argument("--local-dev", action="store_true", help="Open the dashboard with networking disabled; no simulated relays or traffic.")
    args = parser.parse_args()

    if args.self_test:
        if CRYPTO_IMPORT_ERROR is not None:
            print("FAIL: cryptography is not installed. Run: python -m pip install cryptography")
            return 1
        return run_self_tests(live=False)
    if args.self_test_live:
        if CRYPTO_IMPORT_ERROR is not None:
            print("FAIL: cryptography is not installed. Run: python -m pip install cryptography")
            return 1
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
