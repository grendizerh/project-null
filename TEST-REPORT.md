# Project NULL v0.4.9 — test report

Build validation in the available Linux environment:

- Python compilation: passed.
- Shell syntax (`bash -n setup_macos.sh start.command`): passed.
- Offline application self-tests: **36 passed, 0 failed, 1 skipped**.
- The skipped test is live Tor connectivity; run `./start.command --self-test-live` on the target Mac.

New/updated coverage verifies:

- Dashboard button normal, hover and disabled foreground/background contrast (all tested states meet the configured WCAG contrast thresholds).
- Session isolation reuses one ephemeral SOCKS credential across hostnames within one session.
- Hostname isolation still derives a distinct HMAC credential per hostname.
- Legacy configuration files without an isolation-mode key default to session mode.
- Chrome launch no longer passes `--host-resolver-rules`; `--dns-prefetch-disable` remains.
- The process descriptor-budget calculation and fixed worker queue are bounded.
- A worker-queue integration fixture holds one proxy worker busy while two additional clients connect; both are accepted into the pending queue without blocking the accept loop and proceed in order when capacity is released.
- The local no-auth SOCKS5 adapter still forwards to a fake Tor Unix SOCKS endpoint with upstream isolation authentication; there is no direct destination socket fallback.

The fake upstream is a local test fixture, not a Tor simulation or live anonymity test. Offline tests do not prove live Tor circuit construction, Chrome runtime behaviour on macOS, Cloudflare acceptance, packet-level leak resistance, or anonymity. A real Chrome-on-Mac load test remains outstanding.


GUI widget smoke test under Xvfb:

- Created enabled and disabled `DashboardButton` widgets.
- Verified explicit foreground/background colors remain applied after state transitions.
- Verified mouse, Return and Space bindings are registered and callback invocation is suppressed while disabled.
- Verified hover colors restore on pointer leave.

A separate visual verification on the user's macOS display remains outstanding; the widget no longer uses the native Aqua button renderer that caused the reported contrast problem.
