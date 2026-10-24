# PS5 Web Lab — project updates and setup report

**Project path:** `/tmp/ps5-test`  
**Report date:** October 25, 2026  
**Purpose:** inventory of the current features and instructions for recreating a second repository.

> This report describes the files and features present when it was reviewed. The `/tmp/ps5-test` root has no `.git` directory, so a complete source diff or reliable per-file revision history cannot be reconstructed. A separate Git repository was previously nested under `Chiral-FTP/` and has been moved to the cleanup archive described below.

## 1. Architecture

The project contains a PC-hosted web lab, a browser dashboard, a separate PC file-transfer server, and an optional server for cross-origin fixtures.

| Component | Launch file | Default port | Purpose |
|---|---|---:|---|
| Web Lab and backend | `start_server.sh` → `server.py` | 8000 | Dashboard, static pages, event APIs, catalog and dossier generation |
| Local file transfer | `tools/local-transfer-server.py` | 8765 | Authenticated transfer page and access to the selected PC folder |
| Optional Canvas cross-origin fixture | `canvas-cross-origin-server.py` | 8001 | Serves a synthetic test image and, when configured, an exact CORS header |

The PS5 browser is a web client. The server on port 8000 runs on the PC; the server on port 8765 also runs on the PC and forwards dashboard and page requests to the first server while keeping the transfer APIs on the browser's current origin.

## 2. Dashboard and pages

`dashboard.html` is the hub. It dynamically lists HTML pages in `pages/`, displays the read-only Security Analysis Center, links to the research lab, and embeds the file-transfer page. The Security Analysis Center reads historical events and supports filtering and export.

| Page | Purpose |
|---|---|
| `pages/active-vulnerability-research-lab.html` | Canvas/Web IDL, bitmap, Blob URL and origin-clean suites; repeat runs and deterministic fuzzing capped at 100 cases; isolated snippets; manual JavaScript import, preview, hash and result export. |
| `pages/canvas-security-impact.html` | Measures Canvas context options, pixel behavior and controlled origin/security cases. |
| `pages/vulnerability-scanner.html` | API/capability diagnostics and evidence comparison against a CVE catalog; declared firmware and user agent do not attest to the browser model or build. |
| `pages/browser.html` | Simple address bar with a **Search** button. Supports HTTP/HTTPS navigation and text search; it is not an FTP/SFTP client and does not execute transferred JavaScript by itself. |
| `pages/local-transfer.html` | Browses, downloads and uploads files in the transfer server's configured folder. Requires the token generated at server startup. |
| `pages/canvas-reentrancy-audit.html` | Focused audit of Canvas options and reentrant getters. |
| `pages/bitmaprenderer-options-check.html` | Targeted `bitmaprenderer` options check. |
| `pages/context-options.html`, `pages/context-options-diagnostic.html` | Tests and diagnostics for `getContext()` options. |
| `pages/features.html`, `pages/hardware-check.html`, `pages/net-check.html`, `pages/worker-check.html` | API, declared environment, local-network and Worker diagnostics. |
| `pages/p166.html`, `pages/p166-desync.html` | Canvas/identity and desynchronization tests related to earlier checks. |
| `pages/home-page-originale.html` | Original page retained in the project. |

`pages/browser.html` is not a full browser and does not implement protocols other than HTTP/HTTPS. For example, an `sftp://` address must be opened with a native SFTP client; a web page cannot directly create an SFTP connection.

## 3. Analysis, logging and export

- `pages/active-vulnerability-research-lab-core.js` and `pages/active-vulnerability-research-lab.js` contain the test catalog and suite logic.
- `pages/canvas-security-impact-core.js` and `pages/canvas-security-impact.js` implement Canvas cases and event logging.
- `pages/vulnerability-scanner-core.js` and `pages/vulnerability-scanner.js` implement the checks, catalog and scanner UI.
- `pages/research-transfer-core.js` and `pages/research-transfer.js` provide manual transfer import, preview, hashing, explicit execution and result export/upload.
- Imported snippets run in an isolated Worker in the current runner, without DOM or network access. Importing a file does not execute it automatically.
- Four JavaScript probes are in `research-payloads/`: `probe-canvas-alpha.js`, `probe-canvas-reentrancy.js`, `probe-bitmap-lifecycle.js` and `probe-canvas-origin-clean.js`.
- The first three use Canvas APIs in a Worker when available. `probe-canvas-origin-clean.js` requires a local fixture image and a context with `document`/`Image`; in the current Worker runner it returns `SKIPPED` and makes no network request.
- `server.py` handles `/api/health`, `/api/scan-log`, `/api/analysis-events` and catalog endpoints. Campaign results are written to `logs/` as JSONL, JSON summaries and Markdown reports. The Security Analysis Center reads historical events without rewriting logs.
- `data/cve-catalog.json` is the local catalog; `data/canvas-cross-origin.png` is the synthetic fixture. Updating from NVD is an explicit scanner action and requires Internet access from the PC.
- `VULNERABILITY_SCANNER.md` documents the APIs, logging, catalog and backend checks.

These are diagnostic observations. They do not by themselves confirm vulnerabilities, CVEs, native-memory access or a sandbox escape.

## 4. File-transfer server

`tools/local-transfer-server.py` exposes a single selected root folder with `--root`. The default is `$HOME/PS5-Transfer`; the folder is created if missing. The server:

- generates a new token at each startup;
- requires the token for list, download and upload APIs;
- permits writes unless started with `--read-only`;
- limits uploads to 128 MiB and does not overwrite existing files;
- rejects paths outside the shared root;
- forwards dashboard and page requests to the main backend port configured by `PS5_WEB_LAB_PORT` (8000 by default).

The token travels over HTTP. Use this service only on a trusted local network and do not expose it to the Internet. Do not put the token in reports or URLs.

## 5. Starting the servers

### Terminal 1 — Web Lab (port 8000)

```bash
cd /tmp/ps5-test
./start_server.sh
```

By default, the script uses `PS5_WEB_LAB_HOST=0.0.0.0` and `PS5_WEB_LAB_PORT=8000`. It checks whether the port is occupied and refuses to start a second instance. Stop it with `Ctrl+C` in the terminal running the process.

Direct URLs:

- PC: `http://127.0.0.1:8000/dashboard.html`
- PS5: `http://PC_LAN_IP:8000/dashboard.html`
- Scanner page: `http://PC_LAN_IP:8000/pages/vulnerability-scanner.html`
- Browser page: `http://PC_LAN_IP:8000/pages/browser.html`

Do not use `localhost` or `127.0.0.1` on the PS5; those addresses refer to the console itself. Replace `PC_LAN_IP` with the PC's current LAN address.

### Terminal 2 — File transfer (port 8765)

```bash
cd /tmp/ps5-test
python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer" --bind 0.0.0.0
```

The process prints its LAN addresses and temporary token. Leave it running while using file transfer or importing tests. Put the snippets in the shared folder, for example:

```bash
cp /tmp/ps5-test/research-payloads/*.js "$HOME/PS5-Transfer/"
```

URLs from the PS5:

- Forwarded dashboard: `http://PC_LAN_IP:8765/dashboard`
- Transfer page: `http://PC_LAN_IP:8765/pages/local-transfer.html`
- Browser page: `http://PC_LAN_IP:8765/pages/browser.html`

The transfer page requires the token printed by the process. In the lab, use the import panel to select a file from the shared folder, review its contents and SHA-256, then explicitly start execution.

### Optional fixture server (port 8001)

For cross-origin checks that use the local fixture only:

```bash
cd /tmp/ps5-test
python3 canvas-cross-origin-server.py --host 0.0.0.0 --port 8001
```

The server exposes only the synthetic PNG at `/canvas-cross-origin.png`. For a positive CORS check, add `--allow-origin` with the exact origin open in the browser, such as `http://PC_LAN_IP:8000` or `http://PC_LAN_IP:8765`, depending on which URL is in use. Stop the process with `Ctrl+C` when finished.

### Changing the main server port

If port 8000 is occupied and you deliberately choose another port, use the same variable in both terminals, for example `8080`:

```bash
PS5_WEB_LAB_PORT=8080 ./start_server.sh
```

```bash
PS5_WEB_LAB_PORT=8080 python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer" --bind 0.0.0.0
```

The transfer server remains on port 8765; `/dashboard` forwards to the backend on port 8080.

## 6. Importing the four probes

1. Copy the files to `$HOME/PS5-Transfer/` as shown above.
2. On the PS5, open `http://PC_LAN_IP:8765/dashboard`.
3. Open **Active Vulnerability Research Lab**.
4. Connect to the transfer server using the current process token.
5. Select a file in the import panel, choose **Import and preview**, review the source, then choose **Run imported test**.
6. Repeat for each probe and export or download the results as needed.

Importing does not read PS5 memory or run code inside Chiral-FTP. The tests run in the Web Lab browser. The origin-clean probe requires a fixture and a DOM-capable profile; it remains `SKIPPED` in the current imported Worker mode. To test origin-clean in the lab, use the built-in D1 case with the fixture server running.

## 7. Chiral-FTP

The Chiral-FTP source checkout, including its `.git` directory, was moved outside the project to `/home/IBM/ps5-test-cleanup-archive-20261025/Chiral-FTP-source/`. Its regenerable artifacts (`.build/`, `.deps/`, compiled Linux executable) and the root `chiral-ftp-1.1-x86_64.AppImage` are kept in `/home/IBM/ps5-test-cleanup-archive-20261025/build-artifacts/`. Chiral-FTP is a separate app, not one of the Web Lab servers: transferring a file with Chiral-FTP does not execute it in the browser. Its license is GPL-3.0.

Official installation and download links:

- [PS5 instructions in the official README](https://github.com/Herbrax/Chiral-FTP#ps5)
- [Official Chiral-FTP releases](https://github.com/Herbrax/Chiral-FTP/releases)

The README lists a jailbroken PS5, ShadowMountPlus and an ELF loader (`elfldr`) listening on port 9021 as prerequisites for full storage access. It reports testing on firmware 13.60 and does not confirm compatibility with firmware 14.10. Review the current instructions and release notes before proceeding.

## 8. Preparing a second repository

The project root has no Git history of its own. To create a new repository, copy the application sources and review local artifacts separately. Typically include:

- `dashboard.html`, `dashboard-security-center.js`, `server.py`, `start_server.sh`;
- `pages/` and `research-payloads/`;
- `tools/local-transfer-server.py`, `canvas-cross-origin-server.py`;
- `data/cve-catalog.json` and `data/canvas-cross-origin.png`;
- `tests/`, `VULNERABILITY_SCANNER.md` and this report.

`.gitignore` excludes Python caches, bytecode, generated logs, backups, any restored nested Chiral-FTP checkout and AppImages. The Chiral-FTP checkout, caches, backups and compiled artifacts removed from the project were preserved outside the repository in `/home/IBM/ps5-test-cleanup-archive-20261025/`; they were not permanently deleted. `reports/` retains distinct reports and instructions; they are not duplicates. Do not copy session tokens or any `.env` files that may exist outside the inventoried project.

Decide separately whether to include Chiral-FTP in the new repository: its nested `.git` history is independent, and the project is licensed under GPL-3.0.

## 9. Checks and known limitations

- For the four probes, `node --check` passed on all files; execution with simulated Canvas APIs produced parseable JSON output. No probe was run on the PS5 in that verification.
- Actual compatibility with the console browser requires testing on the device; results from Node or another browser do not prove PS5 compatibility.
- The main server and transfer server require separate processes/terminals. The fixture server is an optional third process.
- The PC's LAN address can change. Port 8765 requires the token; port 8000 serves Web Lab pages and APIs.
- `pages/browser.html` is only an HTTP/HTTPS web-navigation launcher; it does not support `sftp://` or act as a proxy.
