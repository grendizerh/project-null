# Project NULL v0.4.9

**A macOS application that routes a managed Chrome session through Tor using a local SOCKS5 proxy.**

Project NULL starts a dedicated Tor client and exposes a SOCKS5 listener on **127.0.0.1**. Its managed Chrome profile uses that proxy. The application does not require a browser extension, proxy username/password, or manual Chrome proxy configuration.

> **Scope:** Project NULL is a browser-specific Tor proxy, not a system-wide VPN. It does not route every Mac application or every operating-system connection through Tor. It is experimental software, not an anonymity guarantee or a replacement for Tor Browser.


## Contents

- [1. Download the project](#1-download-the-project)
- [2. Check the requirements](#2-check-the-requirements)
- [3. Install Project NULL](#3-install-project-null)
- [4. Run the checks](#4-run-the-checks)
- [5. Connect and open Chrome](#5-connect-and-open-chrome)
- [6. Disconnect and quit](#6-disconnect-and-quit)
- [7. Update Project NULL](#7-update-project-null)
- [8. Download the source with Git](#8-download-the-source-with-git)
- [Settings and stream isolation](#settings-and-stream-isolation)
- [Troubleshooting](#troubleshooting)
- [Security and limitations](#security-and-limitations)

---

## 1. Download the project

### Recommended: download the packaged release

1. Open the [Project NULL GitHub repository](https://github.com/grendizerh/project-null).
2. Select **Releases** on the repository page, or open the [Releases page directly](https://github.com/grendizerh/project-null/releases).
3. Open **Project NULL v0.4.9** (or the newest release shown there).
4. Under **Assets**, download the file named **project-null-v0.4.9.zip**.
   - Download the release ZIP asset, not GitHub's automatically generated **Source code (zip)** archive. The release asset contains the packaged application, setup script, dependency pins, checksum file, and documentation.
5. Save the ZIP in your **Downloads** folder.

If the v0.4.9 release asset is not yet listed, the release has not been published yet. Do not use a different version's asset by mistake.

### Extract the ZIP

1. Open **Finder** and select **Downloads**.
2. Double-click **project-null-v0.4.9.zip** (or right-click it and choose **Open With → Archive Utility**).
3. macOS should create a folder named **project-null-v0.4.9**.
4. Keep the extracted folder together; do not move the application source, dependency file, setup script, or launcher out of it.

You can also extract it in Terminal:

~~~bash
cd ~/Downloads
unzip -q project-null-v0.4.9.zip
cd project-null-v0.4.9
~~~

If Finder has already extracted the ZIP, skip the unzip command and run the final cd command.

## 2. Check the requirements

Project NULL v0.4.9 currently supports:

- macOS on Apple Silicon (arm64, such as M1, M2, M3, or M4 Macs).
- An internet connection for downloading setup components and bootstrapping Tor.
- Google Chrome installed on the Mac.
- About **5 GB of free disk space** for a first-time Miniforge/Python/Tk installation. If the Project NULL environment already exists, the setup script requires less free space (at least 1 GB is recommended).

The setup script installs Miniforge under **~/miniforge3** if needed, creates or updates the **project-null-gui** Python 3.12 environment, and installs Tor Expert Bundle 16.0 under **~/Applications/ProjectNULL/**. It verifies the pinned hashes before using the downloaded installers and Tor bundle.

**No sudo, Homebrew, or full Xcode installation is required by the setup script.**

## 3. Install Project NULL

1. Open **Terminal**.
2. Move into the extracted project folder:

   ~~~bash
   cd ~/Downloads/project-null-v0.4.9
   ~~~

3. Run the setup script:

   ~~~bash
   bash setup_macos.sh
   ~~~

4. Let setup finish. It checks available disk space, prepares the Python/Tk environment, installs the pinned Python dependencies, verifies or installs the Tor bundle, and runs the offline self-tests.
5. Setup ends with **Setup complete — Project NULL 0.4.9** when the installation steps succeed.

The first installation downloads Miniforge, Python packages, and Tor. It may take longer than later updates. Do not close Terminal while the setup script is running.

## 4. Run the checks

After setup completes, remain in the **project-null-v0.4.9** folder and run:

~~~bash
./start.command --version
./start.command --self-test
~~~

The v0.4.9 build test report records **36 passed, 0 failed, 1 skipped** in the available build environment. The skipped test requires a live Tor connection and is run separately below. Offline tests check local application logic and fixtures; they do not certify anonymity or prove the absence of all network leaks.

### Optional: test a live Tor connection

Run:

~~~bash
./start.command --self-test-live
~~~

This starts the managed Tor client, waits for a usable three-hop general-purpose circuit, routes a request to **check.torproject.org** through the local SOCKS5 proxy, checks that the site reports **IsTor: true**, and shuts down the test connection. It is a connectivity/routing check, not a packet-capture audit or an anonymity certification. An initial Tor bootstrap can take time; it requires working network access.

## 5. Connect and open Chrome

1. Start the graphical application:

   ~~~bash
   ./start.command
   ~~~

2. In the Project NULL window, click **CONNECT**.
3. Watch the log panel. Wait for Tor to finish bootstrapping and for Project NULL to report that a usable circuit and proxy are ready.
4. Click **OPEN CHROME (TEST)**.
5. Project NULL opens a managed temporary Chrome profile configured to use:

   ~~~text
   socks5://127.0.0.1:28080
   ~~~

6. Browse in the Chrome window opened by Project NULL. Keep Project NULL running and connected while using this managed browser session.

You do not need to install an extension or enter proxy credentials. Do not assume that an ordinary Chrome window you opened separately is routed through Project NULL; use the window launched by the application.

### What the connection status means

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

1. Download its packaged ZIP from the [GitHub Releases page](https://github.com/grendizerh/project-null/releases).
2. Extract it into a new version-named folder in Downloads (for example, **project-null-v0.5.0**).
3. Open Terminal and use cd to enter that new folder.
4. Run **bash setup_macos.sh** again.
5. Run **./start.command --self-test**, then launch with **./start.command**.

The setup script is designed to reuse the existing **~/miniforge3** installation, **project-null-gui** environment, and verified Tor bundle when they match the release's requirements. Keep the old project folder until the new version has passed its checks. Do not delete your Miniforge or Tor installation just to update the application.

## 8. Download the source with Git

Developers who want to inspect or modify the source can clone the repository instead of downloading a packaged release ZIP:

~~~bash
git clone https://github.com/grendizerh/project-null.git
cd project-null
bash setup_macos.sh
./start.command --self-test
./start.command
~~~

The packaged release ZIP is the recommended route for ordinary installation. A Git clone follows the repository's **main** branch, which may contain unreleased changes.

## Settings and stream isolation

Open **Settings** while Project NULL is disconnected. The stream-isolation options are:

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

### Setup says there is not enough disk space

Free disk space and rerun:

~~~bash
bash setup_macos.sh
~~~

A first-time Miniforge installation needs about 5 GB free. An existing environment needs less, but the script recommends at least 1 GB for a safe update.

### The start.command file reports Permission denied

Run setup again; it marks the launcher executable:

~~~bash
bash setup_macos.sh
~~~

Then retry **./start.command**.

### Project NULL says its Python environment or Tor installation is missing

From the extracted project folder, rerun:

~~~bash
bash setup_macos.sh
~~~

The setup process checks the expected paths and verifies the Tor bundle before launch.

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

Key points:

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
| project_null.py | Application, GUI, Tor management, SOCKS5 adapter, and self-tests |
| setup_macos.sh | macOS environment setup and verified Tor bundle installation |
| start.command | Launches the application with its managed Python environment |
| requirements.txt | Hash-pinned Python dependencies |
| SHA256SUMS.txt | Checksums for packaged project files |
| SECURITY.md | Security scope, assumptions, and limitations |
| AUDIT-REPORT.md | Implementation review notes |
| TEST-REPORT.md | Build and test results |
| CHANGELOG.md | Version history |

### Verify the packaged files

From the extracted **project-null-v0.4.9** directory, run:

~~~bash
shasum -a 256 -c SHA256SUMS.txt
~~~

Every listed file should report **OK**. If a file fails verification, do not run the package; download the release ZIP again from the official repository.

## Support

For bug reports and questions, open an issue at [github.com/grendizerh/project-null/issues](https://github.com/grendizerh/project-null/issues). Include the Project NULL version, macOS version, the relevant error messages, and steps to reproduce. Remove personal information, onion-service credentials, tokens, and other secrets before posting logs.
