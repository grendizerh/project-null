# Changelog

## v0.4.9

- Fixed macOS dashboard controls rendering as white-on-white under the native Aqua button renderer.
- Replaced native `tk.Button` controls with theme-independent Tk `Label`-based action buttons that explicitly render the application's dark background and high-contrast foreground colors.
- Added hover, disabled, mouse-click, Return-key and Space-key behaviour; Settings dialog buttons use the same component.
- Added automated contrast checks for normal, hover and disabled button states.
- No networking, Tor, proxy, DNS or stream-isolation behaviour changed from v0.4.8.

## v0.4.8

- Removed the Chrome `--host-resolver-rules` switch that produced an unsupported-command-line warning in the user's installed Chrome build. Retained DNS prefetch disablement. Chromium SOCKS5 URL loads resolve destination names through the proxy; this does not claim system-wide DNS coverage.
- Changed default Tor stream isolation from per-hostname to per-application-session. A single ephemeral auth credential per temporary Chrome session allows compatible site/asset streams to reuse Tor circuits, reducing circuit churn.
- Added an explicit Settings choice for `session` (faster, cross-destination circuit reuse) or `hostname` (stricter separation, potentially slower).
- Added a bounded fixed SOCKS worker pool and bounded pending request queue. Accepted connections are queued without blocking the server accept loop.
- Raises only the Project NULL process's soft file-descriptor limit to 512 when the existing hard limit allows it; no system-wide limit is changed. The worker pool remains capped at 128 and the pending queue at 128 (with a requested 256-entry kernel listen backlog).
- Added regression tests for isolation modes, legacy configuration default, Chrome launch switches, and multiple pending SOCKS client bursts.
- Preserved Tor-side Unix-socket authentication, remote hostname resolution, loopback-only bind, destination allow-list and no-direct-fallback behaviour.

## v0.4.7

- Fixed premature browser connection rejection at the local SOCKS5 adapter's active-stream limit.
- Increased the bounded listen backlog to 256.
- Added bounded admission back-pressure, with a 30-second active-stream wait.
- Calculated active streams from the process file-descriptor soft limit; capped at 128.

## v0.4.6

- Replaced Chrome's authenticated HTTP CONNECT proxy path with a native SOCKS5 loopback adapter.
- Removed the HTTP 407 proxy challenge and the Manifest V3 proxy-auth extension from Chrome launch.
- Chrome uses `socks5://127.0.0.1:<port>`; Chromium performs hostname resolution through the SOCKS5 proxy.
- The local adapter accepts no-auth SOCKS5 only, binds exclusively to IPv4 loopback, rejects IP literals, local/reserved hostnames and non-TCP/443 ports, and fails closed if Tor's private Unix SOCKS socket is unavailable.
- Tor-side SOCKS username/password authentication and stream isolation remain enabled.
- Explicitly documented the trade-off: any local process able to reach the loopback listener can use it.

## Earlier releases

See previous release history in the conversation.
