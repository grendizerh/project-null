# Project NULL v0.4.9

**A loopback-only Chrome-compatible SOCKS5 adapter backed by Tor.**

Project NULL starts a dedicated Tor client and exposes a SOCKS5 listener on `127.0.0.1:<port>`. Chrome uses native SOCKS5: no browser username/password, no HTTP 407 challenge, and no web extension. The adapter validates each destination and forwards it through Tor's private Unix-domain SOCKS interface. The default stream-isolation mode is **session-wide** to avoid building a separate Tor isolation group for every page hostname and asset domain.

This is an experimental browser proxy, **not** a system-wide VPN, packet filter, anonymity certification, or protection against an attacker controlling the Mac. It does not provide an OS-level kill switch, system DNS control, UDP forwarding, or Tor Browser anti-fingerprinting.

## What changed in v0.4.9

- Fixed dashboard buttons appearing as white controls with unreadable text on macOS. The interface now uses explicit-color Tk label-based action controls instead of Aqua-rendered native buttons; hover, disabled, mouse and keyboard activation are supported.
- Settings dialog actions use the same high-contrast controls.
- No Tor, proxy, DNS, or routing behaviour changed from v0.4.8.

## What changed in v0.4.8

- Removed Chrome's `--host-resolver-rules` launch argument because your Chrome build displayed an unsupported-command-line warning for it. Kept DNS prefetch disabled. Chromium documents that SOCKS5 URL requests resolve destination hostnames through the proxy; this is not a claim that every browser/OS background component is prevented from making DNS requests.
- Changed the default Tor SOCKS isolation scope from per-hostname to per-Project-NULL-session. All destinations in one temporary browser session use the same ephemeral Tor SOCKS auth credential, allowing Tor to reuse compatible circuits instead of forcing new isolation groups for every asset hostname.
- Retained optional **hostname** isolation in Settings for users who prefer stronger separation and accept additional circuit churn and slower page loads.
- Replaced the accept-loop wait with a bounded fixed worker pool and bounded pending queue. The accept loop no longer blocks while waiting for a stream worker.
- Raises only this process's soft file-descriptor limit to 512 when the inherited hard limit allows it; the hard limit and system settings are not changed. The active worker pool is capped at 128, with a 128-connection pending queue and a 256-entry kernel listen backlog.
- Added tests for session/hostname isolation selection, legacy config defaults, Chrome flags, and simultaneous queued client bursts.

## Important local security trade-off

The browser-facing SOCKS5 listener has **no authentication** because Chrome's native SOCKS5 support does not implement SOCKS5 authentication. The listener binds only to `127.0.0.1`, so it is not exposed to the LAN, but any process on this Mac that can connect to that loopback port can use Project NULL while it is running. This is not a boundary against malware or another local account. The upstream Tor SOCKS interface remains private and uses SOCKS authentication for stream isolation.

## Stream-isolation modes

The Settings menu offers two choices:

- **`session` (default / faster):** all destination hostnames used by the current temporary Chrome session share one Tor SOCKS isolation credential. Tor may reuse a circuit for streams to different websites. This reduces circuit churn and usually makes complex pages with many asset domains more practical. The trade-off is that a hostile exit or observer at the exit side may be able to associate those streams as belonging to the same Tor isolation group.
- **`hostname` (stricter / slower):** each canonical hostname receives a distinct credential. This separates hostnames into different Tor isolation groups, but can cause a large website with many CDN and challenge hostnames to build or wait for many circuits. A generic SOCKS proxy cannot infer the browser's top-level first-party site, so hostname isolation is not equivalent to Tor Browser's first-party isolation.

Changing the mode requires disconnecting Project NULL, opening Settings, selecting the desired mode, saving, and reconnecting. Older config files without `stream_isolation` default to `session`.

## Requirements

- macOS on Apple Silicon (`arm64`).
- Internet access for initial setup and Tor bootstrap.
- Approximately 5 GB free for a first-time Miniforge installation; an existing environment needs less.
- No `sudo`, Homebrew compilation, or full Xcode installation required by the setup script.

## Install and run

### 1. Extract the ZIP

Download `project-null-v0.4.9.zip`, then in Terminal:

```bash
cd ~/Downloads
unzip -q project-null-v0.4.9.zip
cd project-null-v0.4.9
```

### 2. Install dependencies and the verified Tor bundle

```bash
bash setup_macos.sh
```

The setup script reuses/installs Miniforge under `~/miniforge3`, creates or updates the `project-null-gui` Python 3.12 + Tk environment, installs hash-pinned Python dependencies, and installs Tor Expert Bundle 16.0 only after checking its pinned archive SHA-256.

### 3. Run offline tests

```bash
./start.command --version
./start.command --self-test
```

This build reports **36 passed, 0 failed, 1 skipped** in the available build environment. The skipped test is live Tor connectivity. Unit tests use local fake SOCKS fixtures and do not prove anonymity or live network operation.

### 4. Run the live Tor integration test

```bash
./start.command --self-test-live
```

This starts Tor, waits for a built three-hop general-purpose circuit, connects to `check.torproject.org` through the local SOCKS5 adapter, verifies `IsTor: true`, and shuts Tor down. It is a routing smoke test, not a packet-capture leak audit or security certification.

### 5. Launch the application

```bash
./start.command
```

Click **CONNECT**, wait for Tor bootstrap and circuit construction, and then click **OPEN CHROME**. The managed temporary Chrome profile uses:

```text
socks5://127.0.0.1:28080
```

No proxy credentials or browser extension are required. The managed profile has DNS prefetch disabled and QUIC disabled (SOCKS5 here relays TCP, not UDP). Chrome is not Tor Browser.

## Browser protocol and destination policy

- Browser-side protocol: SOCKS5, no-auth method, bound only to `127.0.0.1`.
- SOCKS command: CONNECT only.
- Address type: hostname/domain only; IP-literal requests are rejected.
- Destination port: TCP/443 only.
- Hostnames are passed through SOCKS5 to Tor for proxy-side resolution; the local adapter does not resolve page destination hostnames.
- Chromium's SOCKS5 implementation performs proxy-side resolution for URL requests. DNS prefetch is also disabled. This does not constitute system-wide DNS control or prove that every Chrome subsystem/OS service is incapable of issuing DNS traffic.
- Tor-side SOCKS is a private Unix socket with `IsolateSOCKSAuth`; Project NULL sends an ephemeral session credential by default or a derived per-host credential when strict hostname mode is selected.
- If Tor's private SOCKS socket is unavailable or a Tor stream fails, the adapter returns a SOCKS failure. It never opens a direct destination socket.
- The SOCKS adapter uses a fixed worker pool sized against the process descriptor budget and a bounded pending queue. The accept loop does not wait for an active worker slot. If the pending queue is full, the new connection is refused; no direct fallback is attempted.

## Architecture

```text
Chrome (temporary profile)
        |
        | SOCKS5 CONNECT, no proxy credentials
        v
Project NULL loopback adapter (127.0.0.1:28080)
        |
        | hostname + TCP/443 policy; session or hostname isolation
        v
Private Tor SOCKS Unix socket (0700 directory, socket 0600)
        |
        | Tor SOCKS username/password isolation authentication
        v
Tor client: entry guard -> middle relay -> exit relay
        |
        v
Destination hostname:443
```

Tor Control uses a separate private Unix-domain socket with cookie authentication. No Tor SOCKS or Control TCP listener is configured.

## Cloudflare, performance and website compatibility

Session isolation reduces one avoidable source of delay: a different Tor circuit group for every distinct hostname. It cannot make Tor low-latency or guarantee that Cloudflare accepts a Tor exit IP. Cloudflare challenges and rate limits can depend on exit-IP reputation, network latency, browser signals and site policy. Project NULL does not bypass or weaken those challenges.

The current profile intentionally permits only hostname TCP/443. Plain HTTP on port 80, custom destination ports, IP-literal targets and UDP/QUIC are not supported. Sites relying on a nonstandard port or UDP-only feature may not work. If a page still loads incompletely, inspect the Project NULL log for policy rejection or Tor stream timeout; do not add a `DIRECT` proxy fallback.

## Security limitations

- The ISP can observe that the Mac connects to Tor; the entry guard sees the source IP.
- A sufficiently capable observer with visibility at both ends of a low-latency Tor connection may correlate traffic timing and volume.
- Session isolation allows streams to different websites in the same browser session to share a Tor isolation group. Use `hostname` mode for stricter separation at the cost of circuit churn and performance.
- Chrome is not Tor Browser and does not reproduce its anti-fingerprinting protections. Use the official Tor Browser for privacy-sensitive browsing.
- Other Mac applications, OS services, system DNS, UDP, IPv6 flows not sent through this proxy, and traffic outside the managed Chrome profile are not covered by a system-wide tunnel or kill switch.
- The local SOCKS5 listener is unauthenticated; other local processes can use it while the app is connected.
- Malware on the Mac, a compromised kernel, website accounts/cookies, physical compromise and global traffic correlation are outside this tool's protection.
- No independent penetration test, packet-capture leak audit, or live on-device Chrome/Tor load test is claimed by the offline build tests.

## Troubleshooting

- **Chrome shows an unsupported `--host-resolver-rules` warning:** v0.4.8 removes that argument. Quit old Project NULL Chrome windows before launching the new temporary profile.
- **Chrome says proxy unavailable / `ERR_PROXY_CONNECTION_FAILED`:** check that Project NULL is connected and the loopback SOCKS listener is alive. No credentials are required.
- **Cloudflare challenge is slow or repeats:** verify Settings uses `session` isolation. A Tor exit may still be rate-limited or challenged; changing mode cannot change Cloudflare's policy.
- **A destination fails:** the current profile permits only hostname TCP/443 requests. Plain HTTP on port 80, custom ports and IP-literal destinations are intentionally rejected.
- **Port already in use:** change the SOCKS5 proxy port in Settings, then reconnect.

## Verify package contents

The package includes `SHA256SUMS.txt`. Verify files from the extracted directory with:

```bash
shasum -a 256 -c SHA256SUMS.txt
```
