#!/usr/bin/env python3
"""Small token-protected HTTP file transfer server, scoped to one directory."""

from __future__ import annotations

import argparse
import http.client
import hmac
import ipaddress
import json
import mimetypes
import os
import secrets
import shutil
import socket
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MAX_UPLOAD_BYTES = 128 * 1024 * 1024
PAGE = Path(__file__).resolve().parent.parent / "pages" / "local-transfer.html"


def private_ipv4_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = result[4][0]
            if not ipaddress.ip_address(address).is_loopback:
                addresses.add(address)
    except OSError:
        pass
    return sorted(addresses)


def make_handler(root: Path, token: str, read_only: bool):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LocalTransfer/1.0"

        def _proxy_to_dashboard(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            upstream_path = "/dashboard.html" + ("?" + parsed.query if parsed.query else "") if parsed.path == "/dashboard" else self.path
            connection = http.client.HTTPConnection(self.server.dashboard_host, self.server.dashboard_port, timeout=20)
            try:
                body = None
                if self.command in {"POST", "PUT", "PATCH"}:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > 8 * 1024 * 1024:
                        self._send_json(413, {"error": "Richiesta al dashboard oltre il limite di 8 MiB"})
                        return
                    body = self.rfile.read(length) if length else b""
                connection.putrequest(self.command, upstream_path, skip_host=True, skip_accept_encoding=True)
                for key, value in self.headers.items():
                    if key.lower() not in {"host", "connection", "x-transfer-token"}:
                        connection.putheader(key, value)
                connection.putheader("Host", f"{self.server.dashboard_host}:{self.server.dashboard_port}")
                connection.putheader("Connection", "close")
                connection.endheaders(body)
                response = connection.getresponse()
                body = response.read()
                self.send_response(response.status, response.reason)
                for key, value in response.getheaders():
                    if key.lower() not in {"connection", "content-length", "transfer-encoding", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if body:
                    self.wfile.write(body)
            except (OSError, http.client.HTTPException, ValueError):
                self._send_json(502, {"error": "Dashboard non raggiungibile sul server principale"})
            finally:
                connection.close()

        def log_message(self, fmt: str, *args) -> None:
            # Never include request headers, where the bearer token is sent.
            super().log_message(fmt, *args)

        def _send_json(self, status: int, value: object) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            supplied = self.headers.get("X-Transfer-Token", "")
            if not hmac.compare_digest(supplied, token):
                self._send_json(401, {"error": "Token non valido"})
                return False
            return True

        def _query(self) -> dict[str, list[str]]:
            return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)

        def _safe_path(self, value: str) -> Path:
            if "\x00" in value:
                raise ValueError("Percorso non valido")
            candidate = (root / value).resolve(strict=False)
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise ValueError("Percorso fuori dalla cartella condivisa") from exc
            return candidate

        def do_GET(self) -> None:
            route = urllib.parse.urlsplit(self.path).path
            if route in {"/", "/pages/local-transfer.html"}:
                try:
                    body = PAGE.read_bytes()
                except OSError:
                    self.send_error(500, "Pagina trasferimento non disponibile")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            if route in {"/dashboard", "/dashboard.html"} or route.startswith(("/pages/", "/data/")):
                self._proxy_to_dashboard()
                return
            if route.startswith("/api/") and route not in {"/api/list", "/api/file", "/api/config"}:
                self._proxy_to_dashboard()
                return
            if not route.startswith("/api/"):
                self._proxy_to_dashboard()
                return
            if not self._authorized():
                return
            query = self._query()
            try:
                if route == "/api/list":
                    path = self._safe_path(query.get("path", [""])[0])
                    if not path.is_dir():
                        raise ValueError("La destinazione non è una cartella")
                    entries = []
                    for item in path.iterdir():
                        if item.is_symlink():
                            continue
                        stat = item.stat()
                        entries.append({"name": item.name, "directory": item.is_dir(), "size": None if item.is_dir() else stat.st_size, "modified": stat.st_mtime})
                    entries.sort(key=lambda item: (not item["directory"], item["name"].casefold()))
                    self._send_json(200, {"path": path.relative_to(root).as_posix() if path != root else "", "entries": entries})
                    return
                if route == "/api/config":
                    self._send_json(200, {"readOnly": read_only, "root": str(root)})
                    return
                if route == "/api/file":
                    path = self._safe_path(query.get("path", [""])[0])
                    if not path.is_file():
                        raise ValueError("Il file non esiste")
                    self.send_response(200)
                    self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
                    self.send_header("Content-Length", str(path.stat().st_size))
                    self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(path.name, safe=""))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    with path.open("rb") as stream:
                        shutil.copyfileobj(stream, self.wfile, length=64 * 1024)
                    return
                self.send_error(404)
            except (OSError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})

        def do_POST(self) -> None:
            if urllib.parse.urlsplit(self.path).path != "/api/mkdir":
                self._proxy_to_dashboard()
                return
            if not self._authorized():
                return
            if read_only:
                self._send_json(403, {"error": "Server in sola lettura"})
                return
            query = self._query()
            try:
                parent = self._safe_path(query.get("path", [""])[0])
                name = query.get("name", [""])[0]
                if not parent.is_dir() or not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
                    raise ValueError("Nome cartella non valido")
                (parent / name).mkdir(exist_ok=False)
                self._send_json(201, {"ok": True})
            except FileExistsError:
                self._send_json(409, {"error": "Esiste già un elemento con questo nome"})
            except (OSError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})

        def do_PUT(self) -> None:
            if urllib.parse.urlsplit(self.path).path != "/api/upload":
                self._proxy_to_dashboard()
                return
            if not self._authorized():
                return
            if read_only:
                self._send_json(403, {"error": "Server in sola lettura"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if length < 0 or length > MAX_UPLOAD_BYTES:
                    raise ValueError("Upload limitato a 128 MiB per file")
                query = self._query()
                parent = self._safe_path(query.get("path", [""])[0])
                name = query.get("name", [""])[0]
                if not parent.is_dir() or not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
                    raise ValueError("Nome file o cartella non valido")
                destination = parent / name
                fd, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=parent)
                try:
                    with os.fdopen(fd, "wb") as temporary:
                        remaining = length
                        while remaining:
                            chunk = self.rfile.read(min(64 * 1024, remaining))
                            if not chunk:
                                raise ValueError("Upload interrotto")
                            temporary.write(chunk)
                            remaining -= len(chunk)
                        temporary.flush()
                        os.fsync(temporary.fileno())
                    # Hard-link creation is atomic and fails if a file already exists.
                    os.link(temporary_name, destination)
                finally:
                    try:
                        os.unlink(temporary_name)
                    except FileNotFoundError:
                        pass
                self._send_json(201, {"ok": True, "name": name, "bytes": length})
            except FileExistsError:
                self._send_json(409, {"error": "Esiste già un elemento con questo nome; non viene sovrascritto"})
            except (OSError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Pagina HTTP per trasferire file da/verso una cartella scelta")
    parser.add_argument("--root", default=str(Path.home() / "PS5-Transfer"), help="unica cartella esposta (default: ~/PS5-Transfer)")
    parser.add_argument("--bind", default="127.0.0.1", help="127.0.0.1 per questo computer; 0.0.0.0 per la rete locale")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--read-only", action="store_true", help="disabilita upload e creazione cartelle")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    if root == Path("/") and not args.read_only:
        parser.error("per esporre / è obbligatorio --read-only")
    root.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(6)  # 8 URL-safe characters
    server = ThreadingHTTPServer((args.bind, args.port), make_handler(root, token, args.read_only))
    server.dashboard_host = "127.0.0.1"
    server.dashboard_port = int(os.environ.get("PS5_WEB_LAB_PORT", "8000"))
    print(f"Cartella condivisa: {root}")
    print("Modalità: sola lettura" if args.read_only else "Modalità: trasferimento in lettura e scrittura")
    print(f"Pagina: http://127.0.0.1:{args.port}/")
    if args.bind == "0.0.0.0":
        for address in private_ipv4_addresses():
            print(f"Rete locale: http://{address}:{args.port}/")
    print(f"Token (non condividerlo fuori dalla rete fidata): {token}")
    print("Interrompi con Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer arrestato.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
