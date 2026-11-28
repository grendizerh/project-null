# Project NULL v0.4.9

**A macOS application that routes a managed Chrome session through Tor using a local SOCKS5 proxy.**

Project NULL starts a dedicated Tor client and exposes a SOCKS5 listener on **127.0.0.1**. Its managed Chrome profile uses that proxy. The application does not require a browser extension, proxy username/password, or manual Chrome proxy configuration.

> **Scope:** Project NULL is a browser-specific Tor proxy, not a system-wide VPN. It does not route every Mac application or every operating-system connection through Tor. It is experimental software, not an anonymity guarantee or a replacement for Tor Browser.

## Contents

- [1. Download the packaged release](#1-download-the-packaged-release)
- [2. Check the requirements](#2-check-the-requirements)
- [3. Verify and install](#3-verify-and-install)
- [4. Run the checks](#4-run-the-checks)
- [5. Connect and open Chrome](#5-connect-and-open-chrome)
- [6. Disconnect and quit](#6-disconnect-and-quit)
- [7. Update Project NULL](#7-update-project-null)
- [8. Download the source with Git](#8-download-the-source-with-git)
- [Settings and stream isolation](#settings-and-stream-isolation)
- [Browser protocol and destination policy](#browser-protocol-and-destination-policy)
- [Troubleshooting](#troubleshooting)
- [Security and limitations](#security-and-limitations)

---

## 1. Download the packaged release

### Download the correct ZIP

1. Open the [Project NULL Releases page](https://github.com/grendizerh/project-null/releases).
2. Open **Project NULL v0.4.9**.
3. Under **Assets**, download **project-null-v0.4.9.zip**.
4. Save it in your **Downloads** folder.

**Important:** Download the named ZIP under the release's **Assets** section. Do not download GitHub's automatically generated **Source code (zip)** or **Source code (tar.gz)** links. Those are repository snapshots, not the packaged application release.

The exact v0.4.9 release asset is:

- ZIP filename: `project-null-v0.4.9.zip`
- Extracted folder: `project-null-v0.4.9`
- Published asset SHA-256: `a05f7dafce7c71e5eff227e43ab3c862b0aa4b66bd5e7e3780c2a7370e4d267c`

### Extract the ZIP

You can double-click the ZIP in Finder, or use Terminal:

```bash
cd ~/Downloads
unzip -q project-null-v0.4.9.zip
cd ~/Downloads/project-null-v0.4.9
```

If Terminal says it cannot find the ZIP but the folder **`~/Downloads/project-null-v0.4.9`** already exists, the archive may already have been extracted or moved. **Do not run unzip again.** Just enter the existing folder:

```bash
cd ~/Downloads/project-null-v0.4.9
```

If you are unsure which files are present, inspect Downloads:

```bash
ls -lh ~/Downloads | grep -i project-null
```

Keep the extracted folder intact. Do not move `project_null.py`, `setup_macos.sh`, `start.command`, or the other package files out of it.

## 2. Check the requirements

Project NULL v0.4.9 supports:

- macOS on Apple Silicon (arm64: M1, M2, M3, or M4).
- An internet connection for downloading setup components and bootstrapping Tor.
- Google Chrome installed on the Mac.
- About **5 GB of free disk space** for a first-time Miniforge/Python/Tk installation. If the existing Project NULL Conda environment is detected, at least **1 GB free** is recommended.

The setup script installs or uses:

- Miniforge under `~/miniforge3`.
- A Python 3.12 environment named `project-null-gui`.
- Tor Expert Bundle 16.0 under `~/Applications/ProjectNULL/`.

The setup script verifies pinned hashes for the downloaded Miniforge installer and Tor bundle before using them.

**No sudo, Homebrew, or full Xcode installation is required by the setup script.**

## 3. Verify and install

Open Terminal and enter the extracted release folder:

```bash
cd ~/Downloads/project-null-v0.4.9
```

### Verify the package files

Run:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

Every listed file should report **OK**. If a file fails verification, do not run the package. Download the packaged release ZIP again from the official Releases page.

You can also verify the ZIP itself before extracting it. From Downloads:

```bash
echo 'a05f7dafce7c71e5eff227e43ab3c862b0aa4b66bd5e7e3780c2a7370e4d267c  project-null-v0.4.9.zip' | shasum -a 256 -c -
```

The ZIP check is optional if you no longer have the archive; the extracted-file check above is the relevant check once the folder is extracted.

### Run setup

From inside `project-null-v0.4.9`, run:

```bash
bash setup_macos.sh
```

Let the script finish. It checks available disk space, prepares the Python/Tk environment, installs the pinned Python dependencies, verifies or installs the Tor bundle, and runs the offline self-tests.

A successful setup ends with:

```text
Setup complete — Project NULL 0.4.9.
```

The first installation downloads Miniforge, Python packages, and Tor, so it can take longer than later updates. Do not close Terminal while setup is running.

## 4. Run the checks

Remain in the extracted project folder and run:

```bash
./start.command --version
./start.command --self-test
```

The v0.4.9 build test report records **36 passed, 0 failed, 1 skipped** in the build environment. The skipped test requires a live Tor connection and is run separately below. These offline tests check local application logic and fixtures; they do not certify anonymity or prove the absence of all network leaks.

### Optional: test a live Tor connection

Run:

```bash
./start.command --self-test-live
```

This starts the managed Tor client, waits for a usable three-hop general-purpose circuit, routes a request to **check.torproject.org** through the local SOCKS5 proxy, checks whether the site reports **IsTor: true**, and shuts down the test connection.

This is a connectivity/routing check, not a packet-capture audit or an anonymity certification. Initial Tor bootstrap can take time and requires working network access.

## 5. Connect and open Chrome

1. Start the graphical application:

   ```bash
   ./start.command
   ```

2. In the Project NULL window, click **CONNECT**.
3. Watch the log panel. Wait for Tor to finish bootstrapping and for Project NULL to report that a usable circuit and proxy are ready.
4. Click **OPEN CHROME (TEST)**.
5. Project NULL opens a managed temporary Chrome profile configured to use:

   ```text
   socks5://127.0.0.1:28080
   ```

6. Browse in the Chrome window opened by Project NULL. Keep Project NULL running and connected while using this managed browser session.

You do not need to install an extension or enter proxy credentials. An ordinary Chrome window opened separately is **not** routed through Project NULL; use the window launched by the application.

### Connection status

- **CONNECTING:** Project NULL is starting Tor and waiting for its circuit and proxy to become ready.
- **CONNECTED:** the local proxy is available for applications explicitly configured to use it, including the managed Chrome profile.
- **DISCONNECTED:** the local proxy is not active.

Project NULL binds its browser-facing SOCKS5 listener to loopback (**127.0.0.1**) only. If Tor or its private SOCKS interface is unavailable, the proxy fails the request; it does not open a direct connection to the destination as a fallback.

## 6. Disconnect and quit

1. Close the managed Chrome window when you finish browsing.
2. Return to Project NULL and click **DISCONNECT**.
3. Wait for the log to confirm that the local proxy and Tor client have stopped.
4. Close the Project NULL window.

Do not force-quit the application during an active connection unless it is unresponsive. Disconnecting through the application gives it an opportunity to clean up the managed Chrome session, proxy, and Tor process.

## 7. Update Project NULL

When a newer release is published:

1. Download that release's **packaged ZIP asset** from the [GitHub Releases page](https://github.com/grendizerh/project-null/releases). Do not use the automatically generated source archive.
2. Extract it into a new version-named folder in Downloads.
3. Enter that folder in Terminal.
4. Run `bash setup_macos.sh`.
5. Run `./start.command --self-test`.
6. Launch with `./start.command`.

The setup script is designed to reuse the existing `~/miniforge3` installation, `project-null-gui` environment, and verified Tor bundle when they match the release requirements. Keep the old project folder until the new version has passed its checks.

Do not delete Miniforge or the Tor installation just to update Project NULL. The project folder, Miniforge installation, and Tor installation are separate locations.

## 8. Download the source with Git

Developers who want to inspect or modify the source can clone the repository:

```bash
git clone https://github.com/grendizerh/project-null.git
cd project-null
bash setup_macos.sh
./start.command --self-test
./start.command
```

The packaged release ZIP is the recommended route for ordinary installation. A Git clone follows the repository's **main** branch, which may contain unreleased changes and may not match the packaged release.

## Settings and stream isolation

Open **Settings** while Project NULL is disconnected.

- **session (default):** destination hostnames in the same temporary Project NULL browser session share one ephemeral Tor SOCKS isolation credential. This permits Tor to reuse compatible circuits and generally reduces circuit churn.
- **hostname:** each canonical destination hostname receives a separate derived credential. This provides stricter separation between hostnames but may trigger more Tor circuit creation and slower page loads. It is not equivalent to Tor Browser's first-party isolation because a generic SOCKS proxy cannot determine the top-level website for each browser request.

Save the setting and reconnect for it to take effect. Older configuration files without a stream-isolation entry default to **session**.

## Browser protocol and destination policy

- Browser-side protocol: SOCKS5, no-auth method, bound to **127.0.0.1** only.
- SOCKS command: CONNECT only.
- Address type: hostname/domain only; IP-literal requests are rejected.
- Destination port: TCP/443 only.
- Hostnames are passed to Tor through SOCKS5 for Tor-side resolution; the local adapter does not resolve the destination hostname itself.
- DNS prefetch is disabled in the managed Chrome profile. This does not provide system-wide DNS control or guarantee that every browser/OS background component never performs DNS requests.
- UDP/QUIC and nonstandard destination ports are not supported by this proxy.
- The Tor SOCKS interface is a private Unix-domain socket. Tor Control uses a separate private Unix-domain socket with cookie authentication; neither service is exposed as a TCP listener.
- The local SOCKS adapter uses a bounded worker pool and pending queue. If capacity is exhausted, a new request is refused rather than sent directly.

## Troubleshooting

### The ZIP cannot be found

Check the exact files and folders in Downloads:

```bash
ls -lh ~/Downloads | grep -i project-null
```

The packaged release ZIP is named `project-null-v0.4.9.zip`; the extracted folder is named `project-null-v0.4.9`. If the folder exists but the ZIP does not, the folder may already have been extracted. Enter the folder directly instead of running `unzip` again:

```bash
cd ~/Downloads/project-null-v0.4.9
```

If neither the ZIP nor the folder exists, return to the official [Releases page](https://github.com/grendizerh/project-null/releases) and download the named asset under **Assets**.

### Setup reports an incomplete Miniforge directory

The setup script expects Miniforge at `~/miniforge3`. If that path exists but `~/miniforge3/bin/conda` is missing or not executable, setup stops rather than overwriting the directory.

First inspect it:

```bash
ls -la "$HOME/miniforge3"
ls -l "$HOME/miniforge3/bin/conda" "$HOME/miniforge3/bin/python" 2>&1
```

If it contains a working Miniforge installation or environments used by another project, **do not delete it**. Stop and investigate that installation first.

Only if you have confirmed that `~/miniforge3` is an abandoned, incomplete installation with no environments or files you need, remove that one directory:

```bash
rm -rf "$HOME/miniforge3"
```

Then, from the extracted Project NULL folder, retry:

```bash
bash setup_macos.sh
```

Do not run a broader cleanup command and do not delete `~/Applications/ProjectNULL` as a fix for this Miniforge error. The Miniforge directory and Tor installation are separate.

### Setup says there is not enough disk space

Free disk space and rerun:

```bash
bash setup_macos.sh
```

A first-time Miniforge installation requires about 5 GB free. When the existing Project NULL environment is detected, the script recommends at least 1 GB free for a safe update.

### The start.command file reports Permission denied

Run setup again; it marks the launcher executable:

```bash
bash setup_macos.sh
```

Then retry `./start.command`.

### Project NULL says its Python environment or Tor installation is missing

From the extracted project folder, rerun:

```bash
bash setup_macos.sh
```

The setup process checks the expected paths and verifies the Tor bundle before launch. If it reports an incomplete Miniforge directory, follow the dedicated instructions above; do not delete a working Python installation.

### Chrome reports ERR_PROXY_CONNECTION_FAILED or says the proxy is unavailable

- Confirm Project NULL shows **CONNECTED**.
- Use **OPEN CHROME (TEST)** in Project NULL, rather than a separate Chrome window.
- Check the Project NULL log for Tor bootstrap errors or SOCKS policy rejections.
- If the local proxy port was changed in Settings, reconnect and let Project NULL launch the managed Chrome profile again.

### A website does not load or displays a Cloudflare challenge

Tor exit IP addresses may be rate-limited, blocked, or challenged by individual websites. Project NULL cannot guarantee that a site accepts a Tor exit. This release only allows hostname TCP/443 through the proxy; plain HTTP on port 80, IP-literal targets, custom ports, and UDP/QUIC are not supported.

### A button is difficult to read

Use the v0.4.9 packaged release. It replaces the affected native Aqua-rendered controls with high-contrast Tk-drawn controls. If the problem persists, open a [GitHub issue](https://github.com/grendizerh/project-null/issues) and include your macOS version and a screenshot that does not expose private information.

## Security and limitations

Read **SECURITY.md** before relying on Project NULL.

- The ISP can see that the Mac connects to Tor. The Tor entry guard sees the connecting IP address; the destination website sees a Tor exit IP.
- A sufficiently capable observer with visibility at both ends of a low-latency Tor connection may correlate traffic timing and volume.
- Project NULL routes only the managed Chrome profile it launches. It is not a system-wide tunnel and does not protect other applications, macOS system services, or traffic outside that browser profile.
- There is no OS-level kill switch, system-wide DNS enforcement, or general UDP forwarding.
- Chrome is not Tor Browser and does not include Tor Browser's anti-fingerprinting hardening. For higher-risk privacy needs, use the official [Tor Browser](https://www.torproject.org/download/) and follow its documentation.
- The browser-facing SOCKS5 listener is unauthenticated for Chrome compatibility. It binds to loopback, but other local processes on the Mac may be able to use it while Project NULL is connected. This is not a defence against malware or a compromised local account.
- No anonymity guarantee, independent penetration test, or comprehensive packet-capture leak audit is claimed.

## Project files

| File | Purpose |
|---|---|
| `project_null.py` | Application, GUI, Tor management, SOCKS5 adapter, and self-tests |
| `setup_macos.sh` | macOS environment setup and verified Tor bundle installation |
| `start.command` | Launches the application with its managed Python environment |
| `requirements.txt` | Hash-pinned Python dependencies |
| `SHA256SUMS.txt` | Checksums for packaged project files |
| `SECURITY.md` | Security scope, assumptions, and limitations |
| `AUDIT-REPORT.md` | Implementation review notes |
| `TEST-REPORT.md` | Build and test results |
| `CHANGELOG.md` | Version history |

## Support

For bug reports and questions, open an issue at [github.com/grendizerh/project-null/issues](https://github.com/grendizerh/project-null/issues). Include the Project NULL version, macOS version, relevant error messages, and steps to reproduce. Remove personal information, onion-service credentials, tokens, and other secrets before posting logs.
