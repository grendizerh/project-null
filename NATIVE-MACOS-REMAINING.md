# Native macOS work not included in v0.4.9

Project NULL remains a loopback SOCKS5 browser proxy, not a system-wide VPN. A native macOS Network Extension is still required for system-wide flow routing, system DNS control, IPv4/IPv6 route enforcement, UDP support, crash-safe kill-switch behaviour, sleep/wake recovery and per-app network policy. This requires Apple's entitlement/provisioning/signing workflow and testing on macOS.
