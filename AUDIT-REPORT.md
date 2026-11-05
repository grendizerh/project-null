# Project NULL v0.4.9 — macOS GUI contrast and browser startup audit

## v0.4.9 GUI finding

The macOS GUI displayed the dashboard's native Tk buttons as white controls with unreadable text. The native Aqua button renderer may ignore or reinterpret classic Tk button foreground/background options. Replaced the dashboard and Settings dialog controls with label-based Tk action widgets that draw explicit foreground/background colors, expose visible hover/disabled states, and support mouse, Return and Space activation. Automated contrast checks cover normal, hover and disabled palettes; a widget smoke test was run under Xvfb. This change does not alter networking or Tor behaviour.

## Findings from the v0.4.7 user report

### 1. Chrome warning for `--host-resolver-rules`

The managed browser command line included `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`, and the user's Chrome build surfaced an unsupported-command-line warning for it. The flag is removed. Chromium's SOCKS5 documentation states that URL hostname resolution is performed by the SOCKS proxy. `--dns-prefetch-disable` is retained. This removes the warning and preserves proxy-side DNS for URL loads, but does not claim that all background browser or macOS components are globally prevented from resolving names.

### 2. Per-hostname SOCKS isolation caused circuit churn

v0.4.7 derived a unique Tor SOCKS authentication credential for every canonical hostname. With `IsolateSOCKSAuth`, different credentials form separate isolation profiles. A modern page may contact the main site, multiple CDN hosts, font hosts, challenge hosts and API hosts; this creates many independent isolation groups and can require multiple Tor circuits. That is an avoidable performance cost for the single temporary Chrome session.

**Remediation:** `session` is now the default isolation mode. All streams from the current temporary browser session use one fresh random credential and may share compatible Tor circuits. `hostname` retains the stricter v0.4.7 behaviour as an explicit option in Settings. Session mode increases the amount of cross-destination association possible at the Tor exit side; the trade-off is documented in README and SECURITY.

This proxy cannot infer Chrome's top-level first-party origin from a generic SOCKS5 CONNECT request. The hostname option must not be described as equivalent to Tor Browser's first-party isolation.

### 3. Accept-loop blocking and concurrency exhaustion

v0.4.7 waited for active-stream capacity in `process_request`, which is called by the server accept loop. When workers were occupied by persistent browser tunnels, the accept loop itself stopped accepting more sockets. The 256 kernel backlog did not fix the architectural blockage.

**Remediation:** a bounded fixed worker pool processes SOCKS clients; accepted sockets are placed into a bounded 128-request userspace queue plus a requested 256-entry kernel listen backlog immediately. The accept loop remains responsive. When the pending queue is full, one new connection is refused; there is no direct fallback. The process raises only its soft `RLIMIT_NOFILE` to 512 if the inherited hard limit permits. The hard limit is unchanged. Workers are capped at 128, the pending queue at 128, and a 64-descriptor reserve is retained for Tor Control, files and overhead.

### 4. Test coverage

- Stream isolation modes: session mode returns the same ephemeral credential for every destination in one session; hostname mode returns distinct deterministic HMAC-derived credentials.
- Legacy config without `stream_isolation` defaults to `session`.
- Chrome launch arguments omit `--host-resolver-rules` and retain DNS prefetch disablement.
- Worker-queue regression test holds one worker busy and verifies that two more accepted clients enter the userspace queue without blocking the accept loop, then complete in sequence.

## Verification

- `python -m py_compile project_null.py`: passed.
- Shell syntax checks: passed.
- Offline application self-tests: **36 passed, 0 failed, 1 skipped**.
- The skipped check is live Tor integration. No real Tor network, actual Chrome build, Cloudflare challenge, packet capture, or Mac load test was available in the build environment.

## Residual risks and caveats

- Session isolation allows Tor to associate streams to different destination hostnames with one SOCKS isolation group. The exit-side correlation surface is broader than hostname mode.
- Hostname mode may be slow because modern pages use numerous hostnames and Tor circuit construction is not instant.
- Cloudflare can challenge or rate-limit Tor exit IPs. Project NULL cannot force a site to trust a Tor exit or bypass a challenge.
- `--dns-prefetch-disable` and SOCKS5 proxy-side URL DNS are not system-wide DNS enforcement.
- Browser access remains limited to TCP/443 hostname CONNECT. Nonstandard ports, HTTP-only pages, UDP and QUIC are not relayed.
- The local SOCKS listener is unauthenticated on loopback; local processes can use it.
- No direct-route fallback exists.
- This remains a browser proxy, not a system-wide VPN or kill switch. No claim of airtight anonymity or independent security certification is made.
