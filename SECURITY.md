# Project NULL Security Notes — v0.4.9

## Scope

Project NULL is a local browser-compatible Tor SOCKS5 adapter, not a VPN, endpoint security product, or guarantee of anonymity. It accepts SOCKS5 CONNECT requests on `127.0.0.1` only, uses no authentication on the browser-facing listener for Chrome compatibility, accepts hostname targets on TCP/443 only, and forwards them through Tor's private Unix-domain SOCKS interface.

## Local trust trade-off

The local SOCKS5 adapter has no username/password authentication. This is deliberate because Chromium's native SOCKS5 proxy support does not support SOCKS5 authentication, and its HTTP proxy authentication flow caused repeated browser credential prompts. Any local process that can reach `127.0.0.1:<configured-port>` while Project NULL is connected can use the proxy. The loopback bind prevents LAN exposure; it does not isolate the listener between local users or against local malware. Do not run untrusted local software while connected.

## Tor-side isolation modes

The Tor upstream always uses a private Unix-domain SOCKS socket with `IsolateSOCKSAuth` and a random credential that is not written to persistent configuration.

- `session` (default): one random credential is used for all destination hostnames in one temporary browser session. Compatible streams may share Tor circuits. This reduces circuit churn and improves page-load practicality, but a hostile exit or observer at the exit side may infer that streams to different sites belong to the same isolation group.
- `hostname`: a distinct HMAC-derived credential is used for each canonical hostname. This gives stronger separation between hostnames but can create many circuit groups and slow pages that rely on numerous host/CDN/challenge domains.

The generic SOCKS interface does not tell Project NULL which top-level first-party site initiated a subresource request. Hostname mode is not equivalent to Tor Browser's site isolation. The session mode deliberately does not promise cross-site isolation.

## DNS and Chrome

Chrome uses native `socks5://` proxy routing. Chromium documents that SOCKS5 URL requests resolve destination hostnames through the proxy. Project NULL removes the `--host-resolver-rules` command-line switch because the user's Chrome build warned about it; DNS prefetch remains disabled. This does not guarantee that every browser background component or the macOS operating system never performs DNS lookups. Project NULL does not change system DNS settings.

## Concurrency and resource bounds

Project NULL raises only its own soft file-descriptor limit to 512 when the existing hard limit permits it. It leaves the hard/system limit unchanged. The adapter uses up to 128 fixed worker threads and a bounded 128-connection pending queue and a requested kernel listen backlog of 256. If that queue fills, new connections can be refused. No direct connection fallback is attempted. The queue prevents the accept loop from blocking while workers are occupied; it does not make the proxy unlimited.

## Preserved Tor-side controls

- Tor SOCKS and Control interfaces remain private Unix-domain sockets in a per-user `0700` runtime directory.
- Tor Control uses cookie authentication.
- Project NULL authenticates to Tor SOCKS using Tor's SOCKS username/password isolation extension.
- Destination hostnames are forwarded as SOCKS5 domain names for Tor-side DNS resolution.
- IP-literal destinations, local/reserved names and non-TCP/443 destinations are rejected.
- If the Tor Unix SOCKS socket is unavailable or a Tor stream fails, Project NULL returns a SOCKS error; it never connects directly to the destination.
- UDP is not relayed. QUIC is disabled in the managed Chrome profile.

## Adversaries not defeated

Project NULL does not defeat a global passive observer capable of correlating traffic at both ends of a Tor circuit, a compromised endpoint, malware running as the local user, website account/cookie identification, physical compromise, or browser fingerprinting. Tor entry guards can see the client's source IP; the ISP can observe Tor connectivity. Session isolation can make destination streams in one browser session more linkable at the Tor exit than hostname isolation.

## Operational guidance

Use the official Tor Browser for privacy-sensitive browsing and keep its defaults. Project NULL Chrome mode is a compatibility/test path. Cloudflare and other anti-abuse services may challenge or rate-limit Tor exit IPs; the proxy does not bypass those checks. Disconnect Project NULL when the local SOCKS5 listener is not needed.
