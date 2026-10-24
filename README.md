# PS5 Web Lab Kit 14.10 — Browser and Canvas Research

A local web lab for documenting browser capabilities and testing observable Canvas, Web IDL, bitmap and origin-security behavior in the PS5 browser. It includes a dashboard, a local research runner, event logging and a token-protected PC file-transfer service.

The firmware label is supplied by the operator. The exact WebKit/JavaScriptCore build is not verified. Results gathered in another browser do not establish PS5 behavior.

## Scope and interpretation

This project is for controlled, non-destructive diagnostics. It does not claim a working jailbreak or Debug Settings unlock. API behavior, context identity, pixel values, or successful tests do not by themselves prove memory corruption, arbitrary read/write, code execution, a sandbox escape or a vulnerability.

The test pages use synthetic data and local fixtures. Do not point tests at systems or resources you do not control.

## Contents

### Dashboard and analysis pages

- `dashboard.html` — hub and read-only Security Analysis Center for historical Canvas and scanner events.
- `pages/active-vulnerability-research-lab.html` — selectable Canvas/Web IDL, bitmap lifecycle, Blob URL and origin-clean tests; deterministic option fuzzing capped at 100 cases; isolated snippet runner; manual file import and result export.
- `pages/canvas-security-impact.html` — Canvas behavior tests and result logging.
- `pages/vulnerability-scanner.html` — browser capability checks and evidence comparison with the local CVE catalog. CVE matches do not establish applicability to a specific PS5 build.
- `pages/browser.html` — simple HTTP/HTTPS address launcher with text search. It does not support `sftp://` or proxy arbitrary protocols.
- `pages/local-transfer.html` — browser interface to the single folder selected for the PC transfer server.
- Supporting diagnostics include `pages/canvas-reentrancy-audit.html`, `pages/bitmaprenderer-options-check.html`, `pages/context-options.html`, `pages/context-options-diagnostic.html`, `pages/features.html`, `pages/hardware-check.html`, `pages/net-check.html`, `pages/worker-check.html`, `pages/p166.html` and `pages/p166-desync.html`.

### Research probes

`research-payloads/` contains four independently importable probes:

- `probe-canvas-alpha.js` — compares fresh and preinitialized 2D contexts with `alpha: false` and `alpha: true`.
- `probe-canvas-reentrancy.js` — records custom getter reads and one bounded reentrant `getContext()` call.
- `probe-bitmap-lifecycle.js` — checks `createImageBitmap()` while the source canvas is resized and repainted; at most 10 iterations.
- `probe-canvas-origin-clean.js` — compares `getImageData()`, `toDataURL()` and `toBlob()` against a configured local cross-origin fixture.

Imported snippets run only after explicit user confirmation in an isolated Worker. The current imported-snippet runner blocks DOM and network access. Consequently, the origin-clean probe reports `SKIPPED` in that Worker context; use the lab's built-in D1 test with the local fixture server for an actual origin-clean test.

### Backend and local data

- `server.py` — dashboard backend, health and catalog APIs, validated event logging and report generation.
- `tools/local-transfer-server.py` — token-protected file listing, download and upload scoped to one configured directory.
- `canvas-cross-origin-server.py` — optional server for the synthetic PNG fixture only.
- `data/cve-catalog.json` — local CVE catalog.
- `data/canvas-cross-origin.png` — synthetic Canvas fixture.
- `tests/` — available automated tests.
- `VULNERABILITY_SCANNER.md` and `PROJECT_UPDATES_REPORT.en.md` — scanner details and full project inventory/setup report.

## Run locally

The Web Lab and transfer service run as separate processes in separate terminals.

### 1. Start the Web Lab backend

```bash
cd /tmp/ps5-test
./start_server.sh
```

The default bind is `0.0.0.0:8000`. The launcher checks whether the port is already occupied and refuses to start a second instance. On the PC, open `http://127.0.0.1:8000/dashboard.html`.

### 2. Start the transfer server

```bash
cd /tmp/ps5-test
python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer" --bind 0.0.0.0
```

The server creates the selected folder if necessary and prints its LAN URL and a temporary token. On the PS5, open:

```text
http://PC_LAN_IP:8765/dashboard
```

Replace `PC_LAN_IP` with the current LAN address of the PC. Do not use `localhost` or `127.0.0.1` from the console. The `/dashboard` route on port 8765 forwards to the backend on port 8000 while keeping transfer APIs available on the same origin.

The transfer token is sent over plain HTTP. Use this service only on a trusted local network; do not expose it to the Internet or put the token in URLs, logs or exported reports.

## Import and run a probe

Copy the probe files into the configured transfer folder on the PC:

```bash
cp /tmp/ps5-test/research-payloads/*.js "$HOME/PS5-Transfer/"
```

In the PS5 browser, open **Active Vulnerability Research Lab**, connect to the transfer service with its current token, select a `.js` file, choose **Import and preview**, review it, then choose **Run imported test**. Files are never run automatically. Results can be exported locally or uploaded through the authenticated transfer API.

Chiral-FTP is not required for this workflow: the runner imports files from the PC transfer folder and executes them in the Web Lab browser. Chiral-FTP transfers files but does not run JavaScript inside its native app or the console operating system.

## Optional cross-origin fixture

In a third terminal, start the fixture server when a test requires a separate origin:

```bash
cd /tmp/ps5-test
python3 canvas-cross-origin-server.py --host 0.0.0.0 --port 8001
```

It serves only `data/canvas-cross-origin.png` at `/canvas-cross-origin.png`. For a CORS-enabled control, supply the exact page origin with `--allow-origin`, for example `--allow-origin http://PC_LAN_IP:8765` when the lab is opened through port 8765. Stop the fixture server with `Ctrl+C` when done.

## Evidence and reports

The backend writes campaign event streams as JSONL, structured summaries as JSON, and human-readable reports as Markdown under `logs/`. The Security Analysis Center reads historical events without modifying them. Keep generated logs and machine-specific tokens out of a public repository.

See [VULNERABILITY_SCANNER.md](VULNERABILITY_SCANNER.md) for API and catalog details, and [PROJECT_UPDATES_REPORT.en.md](PROJECT_UPDATES_REPORT.en.md) for the full page inventory, setup instructions, cleanup notes and Chiral-FTP references.

## Chiral-FTP references

Chiral-FTP is a separate native homebrew application, not a PS5 browser feature or a Web Lab server. Its upstream documentation lists a jailbroken PS5, ShadowMountPlus and an ELF loader as requirements for full storage access; it reports testing on firmware 13.60 and does not confirm compatibility with firmware 14.10.

- [Chiral-FTP PS5 installation instructions](https://github.com/Herbrax/Chiral-FTP#ps5)
- [Chiral-FTP releases](https://github.com/Herbrax/Chiral-FTP/releases)

## Status

The JavaScript probes pass syntax checks and have been exercised with simulated Canvas APIs for JSON output handling. They have not been run on a PS5 as part of that verification. Confirm target-browser behavior on the actual device and record the environment with each result.

The project root currently has no Git history. Review `.gitignore` and the repository contents before publishing. The optional Chiral-FTP checkout and local cleanup archive are kept outside this project directory.
