# Project NULL

**A Tor-backed, loopback-only HTTPS proxy prototype with ephemeral session isolation.**

Project NULL starts a local Tor client, waits for a real three-relay circuit, and exposes a local HTTP `CONNECT` proxy. Applications explicitly configured to use that proxy send HTTPS connections through Tor. Websites see the Tor exit relay's IP address instead of the client's public IP address.

> **Experimental software. Not a system-wide VPN.** Project NULL does not install a macOS Network Extension, route all device traffic, or provide a system-wide kill switch. Only applications configured to use its local proxy are in scope.

## Features

- Starts and manages a separate Tor process with its own data directory.
- Uses Tor Control Protocol cookie authentication on loopback.
- Waits for Tor to bootstrap and confirms a built circuit with at least three relays.
- Provides a loopback-only HTTP `CONNECT` proxy for HTTPS traffic.
- Forwards destination hostnames to Tor through SOCKS5; it does not resolve proxied destination hostnames locally in the proxy code.
- Uses Tor SOCKS username/password authentication with `IsolateSOCKSAuth` for stream isolation.
- Generates an ephemeral Ed25519 keypair per application session. The key is used to derive an opaque session label and SOCKS isolation token; it is **not** a Tor network identity.
- Can launch a dedicated Chrome profile preconfigured to use Project NULL.
- Includes offline self-tests and a live Tor integration test.
- Has no direct-connect fallback in its own proxy implementation.

## Quick start — macOS Apple Silicon

The easiest setup is the included script. It installs dependencies under your user account; it does not require `sudo`, Homebrew, or Xcode Command Line Tools.

### 1. Clone the repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL> project-null
cd project-null
```

Replace `<YOUR-GITHUB-REPOSITORY-URL>` with the HTTPS or SSH URL of your GitHub repository.

### 2. Run setup once

```bash
bash setup_macos.sh
```

The setup script:

1. Checks that the Mac is Apple Silicon and has sufficient free disk space.
2. Reuses `~/miniforge3` if it is already installed; otherwise it downloads Miniforge into your home directory and verifies the installer checksum.
3. Creates a Python 3.12 environment containing Tkinter.
4. Installs `cryptography`, `stem`, and `certifi`.
5. Downloads the Tor Project macOS ARM64 Expert Bundle 16.0 if it is not already installed, verifies its SHA-256 checksum, and installs it under `~/Applications/ProjectNULL/`.
6. Applies a local ad-hoc code signature to the checksum-verified Tor executable if macOS does not accept its embedded signature. This is **not** an Apple Developer signature or notarization.

The setup is designed for a first install and can be run again to repair or complete the environment.

### 3. Start Project NULL

```bash
./start.command
```

You can also double-click `start.command` in Finder. The launcher selects the dedicated Python environment and the per-user Tor binary automatically. It does not depend on whichever older `tor` executable happens to appear first on `PATH`.

### 4. Connect and browse

1. Click **CONNECT** and wait for the dashboard to report **CONNECTED** and show a three-relay circuit.
2. Click **OPEN CHROME**. Project NULL opens a separate Chrome profile at `~/Project-NULL-Chrome` and configures it to use the local proxy.
3. Visit <https://check.torproject.org/> to check whether the browser is using Tor.
4. To stop routing, close the proxied browser window and click **DISCONNECT**.

The regular Chrome profile is not modified. The separate profile is reused on subsequent launches.

### Proxy address

The default proxy is bound only to loopback:

```text
HTTP proxy: 127.0.0.1
Port:       28080
```

If configuring a different browser manually, select an HTTP proxy at `127.0.0.1:28080`. Project NULL currently supports HTTPS `CONNECT` tunnels; it is not a general-purpose forward proxy for arbitrary HTTP, UDP, or other protocols.

## Diagnostics and tests

Use the Python environment installed by the setup script:

```bash
# Offline unit/self-tests. Does not connect to Tor.
./start.command --self-test

# Live integration test. Starts Tor, builds a circuit, checks the exit IP,
# then shuts down the Tor process and local proxy.
./start.command --self-test-live

# Local-only dashboard mode. Networking is disabled; no relays are simulated.
./start.command --local-dev
```

The live test makes an external request to `check.torproject.org` through the Project NULL proxy. It requires internet access and a working Tor network connection.

## How it works

```text
Dedicated Chrome profile
        |
        | HTTP CONNECT to 127.0.0.1:28080
        v
Project NULL local proxy
        |
        | SOCKS5 + per-session isolation credentials
        | Hostname passed to Tor (remote resolution)
        v
Tor client on 127.0.0.1:29050
        |
        v
Entry relay -> Middle relay -> Exit relay
                                      |
                                      v
                              Public HTTPS website
```

The Tor ControlPort is bound to `127.0.0.1:29150` and uses cookie authentication. The SOCKS listener is bound to `127.0.0.1:29050`; the HTTP proxy is bound to `127.0.0.1:28080`. All three ports can be changed in **SETTINGS**.

Application configuration and Tor state are stored under:

```text
~/Library/Application Support/Project NULL/
```

## What Project NULL does — and does not — protect

| Area | Current behaviour |
|---|---|
| HTTPS traffic from an explicitly proxied app | Forwarded through Tor when the proxy is connected |
| Destination website's observed IP | Tor exit relay IP |
| Entry relay | Can observe the client's source IP and the next relay |
| Middle relay | Observes adjacent relays, not the full client-to-destination path |
| Exit relay | Connects to the destination and can observe destination metadata; plaintext protocols are not protected from the exit |
| DNS for hostnames sent in proxied CONNECT requests | Hostname is passed to Tor's SOCKS interface for remote resolution |
| macOS system DNS | Unchanged; this app does not control system-wide DNS |
| Other applications | Not routed unless separately configured to use the proxy |
| UDP, QUIC, arbitrary IP traffic | Not supported by this HTTP CONNECT proxy |
| VPN kill switch / device-wide tunnel | Not implemented |
| Browser fingerprinting, cookies, account logins | Not prevented |

Project NULL's proxy does not implement a direct destination fallback. That is not the same as an operating-system kill switch, and it does not prove that every behaviour of every browser or macOS service is fail-closed. Do not treat this prototype as a device-wide anonymity solution.

### About the ephemeral identity

The Ed25519 keypair is generated locally for the application session and kept in process memory. Its public-key fingerprint contributes to a local session label; an HMAC-derived value is used as a Tor SOCKS isolation credential. Tor relays do not use this key as a new Internet address or as a replacement for IP routing.

Pressing **NEW IDENTITY** changes the isolation credential used for new proxied streams. It does not guarantee a new exit IP, erase browser cookies, change logged-in account identities, or retroactively move already-open connections to a different circuit.

### Anonymity limitations

Tor is not perfect anonymity. The entry relay can see the client's IP address. The destination sees the exit relay's IP address. A website can still identify a user through logins, cookies, browser fingerprinting, tracking links, or information voluntarily supplied. HTTPS protects content between the browser and destination, but does not hide all traffic metadata from every party.

For higher-risk anonymity use cases, use the Tor Project's supported Tor Browser rather than assuming a general-purpose Chrome profile has equivalent anti-fingerprinting protections.

## Requirements

- macOS on Apple Silicon (the setup script is currently scoped to `arm64`).
- Internet access for initial setup and Tor operation.
- Approximately 3 GB of free disk space for the first setup; more is preferable.
- Python 3.12 with Tkinter (created by `setup_macos.sh`).
- Tor 0.4.9.15 or newer. The bundled/tested Expert Bundle is 16.0.
- Python packages: `cryptography`, `stem`, `certifi`.

The Tor Expert Bundle is downloaded from the Tor Project's distribution server. Its SHA-256 is checked against the value recorded for that release before extraction. Miniforge is downloaded from the conda-forge release page with its accompanying checksum file.

## Repository files

```text
project-null/
├── project_null.py      # Application, Tor manager, proxy, GUI and self-tests
├── setup_macos.sh       # One-time per-user setup for macOS Apple Silicon
├── start.command        # Launcher; selects the Python and Tor installations
├── requirements.txt     # Python package dependencies
├── README.md
└── .gitignore
```

The core application is kept in one Python source file. The setup and launcher scripts are separate convenience files so first-time installation is less error-prone.

## Troubleshooting

### `Tkinter is unavailable` or `No module named _tkinter`

Run `bash setup_macos.sh` and start the app with `./start.command`. Do not launch it using a different Python interpreter that lacks Tcl/Tk.

### Tor is too old or the wrong Tor executable is selected

Run `bash setup_macos.sh` again. The app prefers the per-user Expert Bundle installed under `~/Applications/ProjectNULL/tor-expert-16.0/`. You can override it explicitly with `PROJECT_NULL_TOR_BINARY=/absolute/path/to/tor`.

### A port is already in use

Disconnect Project NULL and check the configured ports:

```bash
lsof -nP -iTCP:29050 -sTCP:LISTEN
lsof -nP -iTCP:29150 -sTCP:LISTEN
lsof -nP -iTCP:28080 -sTCP:LISTEN
```

Do not kill a process until you have identified it. Use **SETTINGS** to select different ports if another application legitimately owns one.

### Chrome cannot load a page

Confirm the dashboard is **CONNECTED**, then use **OPEN CHROME** to open the dedicated profile. Run `./start.command --self-test-live` to test Tor independently of the browser proxy. The event log distinguishes failures in the Tor SOCKS handshake from failures in the local HTTP proxy.

## Security status

This is a research and development prototype, not a security-audited product. It has not undergone an independent audit, formal verification, penetration test, or comprehensive DNS/traffic-leak assessment. Do not rely on it to protect sensitive activity or to bypass a hostile network without separately assessing the risks.

## References

- [Tor Project downloads](https://www.torproject.org/download/)
- [Tor Expert Bundle distribution](https://dist.torproject.org/torbrowser/16.0/)
- [Tor Expert Bundle SHA-256 manifest](https://archive.torproject.org/tor-package-archive/torbrowser/16.0/sha256sums-unsigned-build.txt)
- [Miniforge releases](https://github.com/conda-forge/miniforge/releases)
- [Stem documentation](https://stem.torproject.org/)
- [Python cryptography documentation](https://cryptography.io/)
