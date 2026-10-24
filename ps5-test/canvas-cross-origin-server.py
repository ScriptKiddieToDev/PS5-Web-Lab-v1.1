#!/usr/bin/env python3
"""Serve one synthetic PNG on a second origin for the Canvas taint check.

By default this helper emits no Access-Control-Allow-Origin header. An
optional exact-origin allowlist enables the positive CORS control. It serves
no project files other than data/canvas-cross-origin.png.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
FIXTURE = (ROOT / "data" / "canvas-cross-origin.png").resolve()
EXPECTED_FIXTURE = (ROOT / "data" / "canvas-cross-origin.png").resolve()


def validate_allowed_origin(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path or parsed.query or parsed.fragment
            or parsed.username or parsed.password or parsed.netloc == "*"):
        raise ValueError("allow-origin must be one exact http(s) origin without path, credentials, query, or wildcard")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("allow-origin has an invalid port") from exc
    return value


def make_handler():
    class PixelHandler(BaseHTTPRequestHandler):
        server_version = "PS5CanvasOrigin/1.0"
        BLOB_PROBE = ("<!doctype html><meta charset=utf-8>"
                      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
                      "script-src 'unsafe-inline'; connect-src blob:; object-src 'none'; base-uri 'none'\">"
                      "<title>Local Blob URL origin probe</title><script>"
                      "onmessage=async function(e){if(!e.data||typeof e.data.url!=='string'||"
                      "e.data.url.length>2048||e.data.url.indexOf('blob:')!==0||"
                      "typeof e.data.researchProbe!=='string')return;let result;try{const r=await fetch(e.data.url);"
                      "result={fetch:'allowed',status:r.status,body:(await r.text()).slice(0,128)}}"
                      "catch(x){result={fetch:'blocked',error:x.name||'Error'}}"
                      "parent.postMessage({researchProbe:e.data.researchProbe,result:result},e.origin)};</script>").encode("utf-8")

        def log_message(self, _format: str, *_args: object) -> None:
            # Do not log query strings or arbitrary header values.
            return

        def _serve(self, include_body: bool) -> None:
            path = urlsplit(self.path).path
            if path == "/blob-url-probe.html" and include_body:
                body = self.BLOB_PROBE
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; connect-src blob:; object-src 'none'; base-uri 'none'")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            if path != "/canvas-cross-origin.png":
                self.send_error(404, "Not Found")
                return
            fixture = Path(self.server.fixture_path).resolve()
            if fixture != EXPECTED_FIXTURE or not fixture.is_file() or fixture.is_symlink():
                self.send_error(404, "Fixture unavailable")
                return
            body = fixture.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            allowed_origin = getattr(self.server, "allow_origin", None)
            request_origin = self.headers.get("Origin")
            cors_allowed = bool(allowed_origin and request_origin == allowed_origin)
            if cors_allowed:
                self.send_header("Access-Control-Allow-Origin", allowed_origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            if include_body:
                self.wfile.write(body)
            print(
                "canvas-origin request: "
                f"peer={self.client_address[0]} path={path}; "
                "response=200 Content-Type:image/png "
                f"Access-Control-Allow-Origin:{'exact-match' if cors_allowed else 'absent'}",
                flush=True,
            )

        def do_GET(self) -> None:
            self._serve(True)

        def do_HEAD(self) -> None:
            self._serve(False)

        def do_POST(self) -> None:
            self.send_error(405, "Method Not Allowed", "Only GET and HEAD are supported")

        def do_OPTIONS(self) -> None:
            self.send_error(405, "Method Not Allowed", "No CORS preflight is supported")

    return PixelHandler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0 for LAN access)")
    parser.add_argument("--port", type=int, default=8001, help="TCP port (default: 8001; must differ from dashboard origin)")
    parser.add_argument("--allow-origin", help="optional exact origin allowed for CORS, e.g. http://192.168.1.4:8000")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        args.allow_origin = validate_allowed_origin(args.allow_origin)
    except ValueError as exc:
        parser.error(str(exc))
    if not FIXTURE.is_file():
        parser.error(f"synthetic fixture is missing: {FIXTURE}")
    server = ThreadingHTTPServer((args.host, args.port), make_handler())
    server.fixture_path = FIXTURE
    server.allow_origin = args.allow_origin
    print(f"Serving only {FIXTURE.name} on http://{args.host}:{args.port}", flush=True)
    policy = f"exact CORS origin {args.allow_origin}" if args.allow_origin else "no Access-Control-Allow-Origin"
    print(f"Response policy: image/png; {policy}; no filesystem browsing or write endpoint.", flush=True)
    print("Stop with Ctrl+C. Ensure this port differs from the dashboard origin and is reachable from the PS5.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Canvas cross-origin helper stopped.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
