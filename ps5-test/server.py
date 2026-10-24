#!/usr/bin/env python3
"""Small same-origin HTTP server for the PS5 Web Lab.

It serves the dashboard, accepts validated scan events, and stores logs only in
the logs/ directory beside this script. No command, file-read, or path API is
provided.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_VERSION = "1.0.0"
API_VERSION = 1
MAX_EVENT_BYTES = 256 * 1024
MAX_CATALOG_BYTES = 1024 * 1024
MAX_ANALYSIS_EVENTS = 5000
MAX_ANALYSIS_RESPONSE_BYTES = 5 * 1024 * 1024
EVENT_TYPES = {
    "scan_start",
    "test_result",
    "connectivity_check",
    "transmission_error",
    "scan_interrupted",
    "scan_complete",
    "session_summary",
}
RESULT_STATES = {"PASS", "FAIL", "ERROR", "SKIPPED", "INCONCLUSIVE"}
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
EVENT_RE = re.compile(r"^[A-Za-z0-9_-]{8,96}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class PayloadTooLarge(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def validate_catalog(catalog: Any) -> tuple[bool, str]:
    if not isinstance(catalog, dict) or catalog.get("schemaVersion") != 1:
        return False, "schemaVersion 1 richiesto"
    if not isinstance(catalog.get("entries"), list) or len(catalog["entries"]) > 200:
        return False, "entries deve essere una lista di massimo 200 voci"
    if not isinstance(catalog.get("updatedAt"), str) or not isinstance(catalog.get("provenance"), str):
        return False, "updatedAt e provenance sono obbligatori"
    seen: set[str] = set()
    for index, entry in enumerate(catalog["entries"]):
        prefix = f"Voce {index + 1}: "
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not CVE_RE.fullmatch(entry["id"]):
            return False, prefix + "id CVE non valido"
        cve_id = entry["id"].upper()
        if cve_id in seen:
            return False, prefix + "id CVE duplicato"
        seen.add(cve_id)
        for key in ("title", "component", "description"):
            if not isinstance(entry.get(key), str) or not entry[key].strip() or len(entry[key]) > 20000:
                return False, prefix + f"{key} non valido"
        for key in ("affectedProducts", "affectedVersions", "knownFixedReleases", "prerequisites", "diagnosticTestIds", "sources"):
            if not isinstance(entry.get(key), list) or len(entry[key]) > 100:
                return False, prefix + f"{key} deve essere una lista"
        if entry.get("applicability") not in {"unknown", "supported", "not-applicable"}:
            return False, prefix + "applicability non valida"
        if len(entry["diagnosticTestIds"]) > 100 or any(not isinstance(item, str) for item in entry["diagnosticTestIds"]):
            return False, prefix + "diagnosticTestIds non valida"
        for source in entry["sources"]:
            if not isinstance(source, dict) or not isinstance(source.get("name"), str) or not isinstance(source.get("url"), str):
                return False, prefix + "fonte non valida"
            parsed = urllib.parse.urlsplit(source["url"])
            if parsed.scheme != "https" or not parsed.netloc or len(source["url"]) > 2048:
                return False, prefix + "URL fonte deve usare HTTPS"
        for key in ("affectedProducts", "affectedVersions", "knownFixedReleases", "prerequisites"):
            if any(not isinstance(item, str) or len(item) > 2000 for item in entry[key]):
                return False, prefix + f"{key} contiene valori non validi"
    return True, "ok"


def validate_result(result: Any, session_id: str) -> tuple[bool, str]:
    if not isinstance(result, dict):
        return False, "payload.result deve essere un oggetto"
    if not isinstance(result.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,79}", result["id"]):
        return False, "id test non valido"
    for key in ("category", "description"):
        if not isinstance(result.get(key), str) or not result[key].strip() or len(result[key]) > 4000:
            return False, f"{key} non valido"
    if result.get("state") not in RESULT_STATES:
        return False, "state non valido"
    if not isinstance(result.get("observed"), dict) or not isinstance(result.get("limitations"), list):
        return False, "observed o limitations non validi"
    if any(not isinstance(item, str) or len(item) > 4000 for item in result["limitations"]):
        return False, "limitations contiene valori non validi"
    if result.get("error") is not None and not isinstance(result.get("error"), dict):
        return False, "error deve essere un oggetto o null"
    duration = result.get("durationMs")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration < 0 or duration > 3600000:
        return False, "durationMs non valida"
    if result.get("sessionId") != session_id:
        return False, "sessionId del test non corrisponde all'evento"
    return True, "ok"


def safe_markdown(dossier: dict[str, Any]) -> str:
    def val(value: Any) -> str:
        return str(value if value is not None else "").replace("<", "&lt;").replace(">", "&gt;")

    lines = [
        "# PS5 Vulnerability Research & Evidence Dossier",
        "",
        f"- Sessione: `{val(dossier.get('sessionId'))}`",
        f"- Firmware dichiarato: {val(dossier.get('declaredFirmware') or 'non dichiarato')}",
        f"- Stato: **{val(dossier.get('overallState'))}**",
        f"- Inizio: {val(dossier.get('startedAt'))}",
        f"- Fine: {val(dossier.get('completedAt'))}",
        "",
        "> I controlli sono diagnostici. PASS/FAIL descrivono solo il test indicato e non dimostrano sicurezza o vulnerabilità.",
        "",
        "## Ambiente osservato",
        "",
        "```json",
        json.dumps(dossier.get("environment", {}), ensure_ascii=False, indent=2),
        "```",
        "",
        "## Risultati",
        "",
    ]
    for result in dossier.get("results", []):
        lines.extend([
            f"### {val(result.get('id'))} — {val(result.get('state'))}",
            "",
            val(result.get("description")),
            "",
            f"- Categoria: {val(result.get('category'))}",
            f"- Durata: {val(result.get('durationMs'))} ms",
            f"- Osservato: `{json.dumps(result.get('observed', {}), ensure_ascii=False)}`",
        ])
        if result.get("error"):
            lines.append(f"- Errore: {val(result['error'].get('message', result['error']))}")
        for limitation in result.get("limitations", []):
            lines.append(f"- Limite: {val(limitation)}")
        lines.append("")
    conclusions = dossier.get("conclusions", {})
    for title, key in (("Fatti osservati", "factsObserved"), ("Ipotesi", "hypotheses"), ("Risultati inconcludenti", "inconclusiveResults"), ("Dati mancanti", None), ("Verifiche ulteriori consigliate", "recommendedChecks")):
        lines.extend([f"## {title}", ""])
        items = dossier.get("missingData", []) if key is None else conclusions.get(key, [])
        if title == "Ipotesi" and not items:
            lines.append("Nessuna ipotesi è promossa a fatto da questo dossier.")
        for item in items:
            lines.append("- " + val(item))
        lines.append("")
    lines.extend(["## Correlazioni con vulnerabilità note", ""])
    for item in conclusions.get("vulnerabilityCorrelations", []):
        lines.append(f"- **{val(item.get('cve'))} — {val(item.get('title'))}**: applicabilità **{val(item.get('applicability'))}**. {val(item.get('reason'))}")
        if item.get("affectedProducts"):
            lines.append("  - Prodotti nella fonte: " + "; ".join(val(value) for value in item["affectedProducts"]))
        if item.get("knownFixedReleases"):
            lines.append("  - Release correttive indicate: " + "; ".join(val(value) for value in item["knownFixedReleases"]))
        for source in item.get("sources", []):
            lines.append(f"  - Fonte: [{val(source.get('name'))}](<{val(source.get('url'))}>)")
        if item.get("tests"):
            lines.append("  - Controlli correlati: " + ", ".join(val(test.get("id")) + " (" + val(test.get("state")) + ")" for test in item["tests"]))
    lines.extend(["", "## Limitazioni", ""])
    for item in dossier.get("limitations", []):
        lines.append("- " + val(item))
    return "\n".join(lines) + "\n"


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], project_root: Path):
        self.project_root = project_root.resolve()
        self.logs_dir = (self.project_root / "logs").resolve()
        self.server_instance = secrets.token_hex(8)
        self.session_files: dict[str, str] = {}
        self.seen_event_ids: set[tuple[str, str]] = set()
        self.data_lock = threading.RLock()
        super().__init__(address, make_handler(), bind_and_activate=True)


def make_handler() -> type[BaseHTTPRequestHandler]:
    class LabHandler(BaseHTTPRequestHandler):
        server_version = f"PS5WebLab/{BACKEND_VERSION}"

        def log_message(self, fmt: str, *args: Any) -> None:
            # Keep default access logging concise and avoid echoing request bodies.
            super().log_message(fmt, *args)

        def _send_json(self, status: int, value: Any, extra_headers: dict[str, str] | None = None) -> None:
            body = json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-PS5-Web-Lab-Version", BACKEND_VERSION)
            for name, header_value in (extra_headers or {}).items():
                self.send_header(name, header_value)
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def _read_json(self, max_bytes: int) -> Any:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ValueError("Content-Type application/json richiesto")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Content-Length non valido") from exc
            if length > max_bytes:
                raise PayloadTooLarge(f"Richiesta oltre il limite di {max_bytes} byte")
            if length <= 0:
                raise ValueError("Corpo richiesta vuoto")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Corpo richiesta incompleto")
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("JSON non valido") from exc

        def _catalog_path(self) -> Path:
            active = self.server.project_root / "data" / "active-catalog.json"
            seed = self.server.project_root / "data" / "cve-catalog.json"
            return active if active.is_file() else seed

        def _load_catalog(self) -> dict[str, Any]:
            path = self._catalog_path()
            with path.open("r", encoding="utf-8") as stream:
                catalog = json.load(stream)
            valid, message = validate_catalog(catalog)
            if not valid:
                raise ValueError("Catalogo locale non valido: " + message)
            return catalog

        def do_GET(self) -> None:
            path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
            if path in {"/api/scan-log", "/api/catalog/import", "/api/catalog/update"}:
                self._send_json(405, {"ok": False, "error": "Metodo POST richiesto", "method": "GET", "path": path}, {"Allow": "POST"})
                return
            if path == "/api/analysis-events":
                self._get_analysis_events()
                return
            if path == "/api/health":
                try:
                    catalog = self._load_catalog()
                    catalog_date = catalog.get("updatedAt")
                except (OSError, ValueError, json.JSONDecodeError):
                    catalog_date = None
                self._send_json(200, {
                    "ok": True,
                    "service": "PS5-Web-Lab",
                    "apiVersion": API_VERSION,
                    "backendVersion": BACKEND_VERSION,
                    "serverTime": utc_now(),
                    "serverInstance": self.server.server_instance,
                    "logging": True,
                    "logsDirectory": str(self.server.logs_dir),
                    "catalogUpdatedAt": catalog_date,
                    "postEndpoint": "/api/scan-log",
                })
                return
            if path == "/api/catalog":
                try:
                    self._send_json(200, self._load_catalog())
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    self._send_json(500, {"ok": False, "error": str(exc)})
                return
            if path == "/pages/":
                names = sorted(
                    item.name for item in (self.server.project_root / "pages").iterdir()
                    if item.is_file() and item.suffix.lower() == ".html" and not item.name.startswith(".")
                ) if (self.server.project_root / "pages").is_dir() else []
                links = "".join(f'<li><a href="{urllib.parse.quote(name)}">{name}</a></li>' for name in names)
                self._send_text(200, "<!doctype html><meta charset=utf-8><title>Pagine</title><ul>" + links + "</ul>", "text/html; charset=utf-8")
                return
            if path in {"/", "/dashboard.html"}:
                target = self.server.project_root / "dashboard.html"
            else:
                pure = PurePosixPath(path.lstrip("/"))
                parts = pure.parts
                if not parts or any(part in {".", ".."} or part.startswith(".") for part in parts):
                    self._send_json(404, {"ok": False, "error": "Risorsa non trovata"})
                    return
                if parts[0] == "pages":
                    allowed = {".html", ".js", ".css", ".json"}
                elif len(parts) == 1:
                    allowed = {".html", ".js", ".css", ".txt"}
                else:
                    allowed = set()
                if pure.suffix.lower() not in allowed:
                    self._send_json(404, {"ok": False, "error": "Risorsa non trovata"})
                    return
                target = (self.server.project_root / Path(*parts)).resolve()
                try:
                    target.relative_to(self.server.project_root)
                except ValueError:
                    self._send_json(404, {"ok": False, "error": "Risorsa non trovata"})
                    return
            if not target.is_file():
                self._send_json(404, {"ok": False, "error": "Risorsa non trovata"})
                return
            try:
                body = target.read_bytes()
            except OSError:
                self._send_json(404, {"ok": False, "error": "Risorsa non disponibile"})
                return
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
                content_type += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _get_analysis_events(self) -> None:
            """Read a bounded view of generated JSONL records without modifying them."""
            logs_dir = self.server.logs_dir
            if logs_dir.is_symlink():
                self._send_json(500, {"ok": False, "error": "Directory log non disponibile"})
                return
            records: list[dict[str, Any]] = []
            total = 0
            try:
                with self.server.data_lock:
                    paths = sorted(
                        (item for item in logs_dir.glob("scan-*.jsonl") if item.is_file() and not item.is_symlink()),
                        key=lambda item: item.stat().st_mtime_ns,
                    ) if logs_dir.is_dir() else []
                    for file_path in paths:
                        with file_path.open("r", encoding="utf-8") as stream:
                            for line in stream:
                                try:
                                    record = json.loads(line)
                                except (json.JSONDecodeError, UnicodeDecodeError):
                                    continue
                                if not isinstance(record, dict):
                                    continue
                                event_id = record.get("eventId")
                                event_type = record.get("eventType")
                                session_id = record.get("sessionId")
                                client_time = record.get("clientTime")
                                payload = record.get("payload")
                                if not (isinstance(event_id, str) and isinstance(event_type, str)
                                        and isinstance(session_id, str) and isinstance(client_time, str)
                                        and isinstance(payload, dict)):
                                    continue
                                total += 1
                                records.append({
                                    "eventId": event_id,
                                    "eventType": event_type,
                                    "sessionId": session_id,
                                    "clientTime": client_time,
                                    "payload": payload,
                                })
            except OSError:
                self._send_json(500, {"ok": False, "error": "Lettura dello storico non disponibile"})
                return

            records.sort(key=lambda item: item["clientTime"])
            truncated = total > MAX_ANALYSIS_EVENTS
            records = records[-MAX_ANALYSIS_EVENTS:]
            # Keep the response bounded even if a valid historical event is unusually large.
            while records and len(json_bytes({"ok": True, "events": records, "eventCount": len(records), "truncated": truncated, "totalAvailable": total})) > MAX_ANALYSIS_RESPONSE_BYTES:
                records.pop(0)
                truncated = True
            self._send_json(200, {
                "ok": True,
                "events": records,
                "eventCount": len(records),
                "truncated": truncated,
                "totalAvailable": total,
            })

        def do_POST(self) -> None:
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/scan-log":
                self._post_scan_log()
            elif path == "/api/catalog/import":
                self._post_catalog_import()
            elif path == "/api/catalog/update":
                self._post_catalog_update()
            elif path in {"/api/health", "/api/catalog"}:
                self._send_json(405, {"ok": False, "error": "Metodo GET richiesto", "method": "POST", "path": path}, {"Allow": "GET"})
            else:
                self._send_json(404, {"ok": False, "error": "Endpoint non disponibile", "method": "POST", "path": path})

        def _recover_session_files(self, session_id: str, logs_dir: Path) -> None:
            """Restore session routing and event idempotency after a server restart."""
            if session_id in self.server.session_files:
                return
            try:
                candidates = sorted(
                    (path for path in logs_dir.glob("scan-*.jsonl") if path.is_file() and not path.is_symlink()),
                    key=lambda path: path.stat().st_mtime_ns,
                )
            except OSError:
                return
            matching_tokens: list[str] = []
            recovered_ids: set[tuple[str, str]] = set()
            for path in candidates:
                found_session = False
                try:
                    with path.open("r", encoding="utf-8") as stream:
                        for line in stream:
                            try:
                                record = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if record.get("sessionId") != session_id:
                                continue
                            found_session = True
                            old_event_id = record.get("eventId")
                            if isinstance(old_event_id, str) and EVENT_RE.fullmatch(old_event_id):
                                recovered_ids.add((session_id, old_event_id))
                except (OSError, UnicodeDecodeError):
                    continue
                if found_session:
                    matching_tokens.append(path.stem)
            if matching_tokens:
                self.server.session_files[session_id] = matching_tokens[-1]
                self.server.seen_event_ids.update(recovered_ids)

        def _post_scan_log(self) -> None:
            try:
                event = self._read_json(MAX_EVENT_BYTES)
            except PayloadTooLarge as exc:
                self._send_json(413, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            if not isinstance(event, dict):
                self._send_json(400, {"ok": False, "error": "L'evento deve essere un oggetto JSON"})
                return
            event_type = event.get("eventType")
            session_id = event.get("sessionId")
            event_id = event.get("eventId")
            payload = event.get("payload")
            if event_type not in EVENT_TYPES or not isinstance(session_id, str) or not SESSION_RE.fullmatch(session_id):
                self._send_json(400, {"ok": False, "error": "Tipo evento o sessionId non valido"})
                return
            if not isinstance(event_id, str) or not EVENT_RE.fullmatch(event_id) or not isinstance(payload, dict):
                self._send_json(400, {"ok": False, "error": "eventId o payload non valido"})
                return
            if event_type == "test_result":
                valid, message = validate_result(payload.get("result"), session_id)
                if not valid:
                    self._send_json(400, {"ok": False, "error": message})
                    return
            if event_type == "session_summary":
                dossier = payload.get("dossier")
                if not isinstance(dossier, dict) or dossier.get("sessionId") != session_id or not isinstance(dossier.get("results"), list):
                    self._send_json(400, {"ok": False, "error": "Dossier finale non valido"})
                    return
                for result in dossier["results"]:
                    valid, message = validate_result(result, session_id)
                    if not valid:
                        self._send_json(400, {"ok": False, "error": "Risultato del dossier non valido: " + message})
                        return
            if len(json_bytes(event)) > MAX_EVENT_BYTES:
                self._send_json(413, {"ok": False, "error": "Evento troppo grande"})
                return

            logs_dir = self.server.logs_dir
            try:
                logs_dir.mkdir(parents=True, exist_ok=True)
                if logs_dir.is_symlink():
                    raise OSError("La directory log non può essere un link simbolico")
                with self.server.data_lock:
                    self._recover_session_files(session_id, logs_dir)
                    dedupe_key = (session_id, event_id)
                    if dedupe_key in self.server.seen_event_ids:
                        token = self.server.session_files.get(session_id)
                        if event_type == "session_summary" and token:
                            summary_path = logs_dir / f"{token}-summary.json"
                            if not summary_path.is_file():
                                dossier = payload["dossier"]
                                summary = {"serverMetadata": {"receivedAt": utc_now(), "serverInstance": self.server.server_instance}, "dossier": dossier}
                                self._write_json_atomic(summary_path, summary)
                                self._write_bytes_atomic(logs_dir / f"{token}-report.md", safe_markdown(dossier).encode("utf-8"))
                        self._send_json(200, {"ok": True, "duplicate": True, "saved": True, "eventType": event_type, "sessionFile": f"logs/{token}.jsonl" if token else None, "logsDirectory": str(logs_dir)})
                        return
                    token = self.server.session_files.get(session_id)
                    if token is None:
                        token = "scan-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(6)
                        self.server.session_files[session_id] = token
                    record = dict(event)
                    record["serverMetadata"] = {
                        "receivedAt": utc_now(),
                        "serverInstance": self.server.server_instance,
                        "remoteAddress": self.client_address[0],
                    }
                    line = json_bytes(record) + b"\n"
                    log_path = logs_dir / f"{token}.jsonl"
                    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(log_path, flags, 0o600)
                    try:
                        with os.fdopen(descriptor, "ab", closefd=True) as stream:
                            stream.write(line)
                            stream.flush()
                            os.fsync(stream.fileno())
                    except Exception:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                        raise
                    self.server.seen_event_ids.add(dedupe_key)
                    if event_type == "session_summary":
                        dossier = payload["dossier"]
                        summary = {"serverMetadata": record["serverMetadata"], "dossier": dossier}
                        self._write_json_atomic(logs_dir / f"{token}-summary.json", summary)
                        markdown = safe_markdown(dossier).encode("utf-8")
                        self._write_bytes_atomic(logs_dir / f"{token}-report.md", markdown)
                self._send_json(201, {
                    "ok": True,
                    "saved": True,
                    "eventType": event_type,
                    "sessionFile": f"logs/{token}.jsonl",
                    "logsDirectory": str(logs_dir),
                    "summaryFile": f"logs/{token}-summary.json" if event_type == "session_summary" else None,
                    "markdownFile": f"logs/{token}-report.md" if event_type == "session_summary" else None,
                })
            except (OSError, ValueError) as exc:
                self._send_json(500, {"ok": False, "error": "Salvataggio non riuscito: " + str(exc)})

        def _write_json_atomic(self, path: Path, value: Any) -> None:
            self._write_bytes_atomic(path, json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")

        def _write_bytes_atomic(self, path: Path, body: bytes) -> None:
            temp_path = path.with_name(path.name + "." + secrets.token_hex(5) + ".tmp")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            descriptor = os.open(temp_path, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_path, path)
            finally:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

        def _post_catalog_import(self) -> None:
            try:
                catalog = self._read_json(MAX_CATALOG_BYTES)
            except PayloadTooLarge as exc:
                self._send_json(413, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            valid, message = validate_catalog(catalog)
            if not valid:
                self._send_json(400, {"ok": False, "error": "Catalogo rifiutato: " + message})
                return
            catalog = dict(catalog)
            catalog["offline"] = True
            catalog["provenance"] = str(catalog.get("provenance", "catalogo locale")) + " (importazione locale)"
            path = self.server.project_root / "data" / "active-catalog.json"
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                self._write_json_atomic(path, catalog)
            except OSError as exc:
                self._send_json(500, {"ok": False, "error": "Importazione non riuscita: " + str(exc)})
                return
            self._send_json(201, {"ok": True, "catalog": catalog, "saved": True})

        def _post_catalog_update(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 1024:
                    raise PayloadTooLarge("Richiesta troppo grande")
                if length:
                    body = self._read_json(1024)
                    if body not in ({}, None):
                        raise ValueError("L'aggiornamento non accetta URL o parametri client")
                catalog = self._load_catalog()
            except PayloadTooLarge as exc:
                self._send_json(413, {"ok": False, "error": str(exc)})
                return
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            checked_at = utc_now()
            updated = 0
            errors: list[dict[str, str]] = []
            # URLs are fixed to NVD's public API; no URL or CVE list comes from the browser.
            for entry in catalog["entries"][:20]:
                cve_id = entry["id"].upper()
                if not CVE_RE.fullmatch(cve_id):
                    continue
                query = urllib.parse.urlencode({"cveId": cve_id})
                request = urllib.request.Request(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0?" + query,
                    headers={"Accept": "application/json", "User-Agent": "PS5-Web-Lab local research catalog/1.0"},
                )
                try:
                    with urllib.request.urlopen(request, timeout=8) as response:
                        if response.status != 200:
                            raise urllib.error.HTTPError(request.full_url, response.status, "NVD HTTP error", response.headers, None)
                        data = json.loads(response.read(MAX_CATALOG_BYTES + 1).decode("utf-8"))
                    if len(json_bytes(data)) > MAX_CATALOG_BYTES:
                        raise ValueError("Risposta NVD oltre il limite")
                    vulnerabilities = data.get("vulnerabilities", [])
                    cve = vulnerabilities[0].get("cve", {}) if vulnerabilities else {}
                    if not cve or str(cve.get("id", "")).upper() != cve_id:
                        errors.append({"cve": cve_id, "error": "NVD non ha restituito una voce corrispondente"})
                        continue
                    descriptions = cve.get("descriptions", [])
                    english = next((item.get("value") for item in descriptions if item.get("lang") == "en"), None)
                    entry["nvdEnrichment"] = {
                        "source": "NVD API 2.0",
                        "sourceUrl": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                        "checkedAt": checked_at,
                        "published": cve.get("published"),
                        "lastModified": cve.get("lastModified"),
                        "description": english,
                    }
                    updated += 1
                except (OSError, ValueError, KeyError, IndexError, urllib.error.URLError) as exc:
                    errors.append({"cve": cve_id, "error": str(exc)[:500]})
            result_catalog = dict(catalog)
            result_catalog["lastUpdateAttempt"] = checked_at
            result_catalog["updateStatus"] = "updated" if updated else "offline"
            if updated:
                result_catalog["updatedAt"] = checked_at
                result_catalog["offline"] = False
                result_catalog["provenance"] = "Catalogo locale con arricchimento NVD API 2.0; avvisi Apple mantenuti come fonti di applicabilità prodotto."
                path = self.server.project_root / "data" / "active-catalog.json"
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    self._write_json_atomic(path, result_catalog)
                except OSError as exc:
                    errors.append({"cve": "catalog", "error": "Salvataggio non riuscito: " + str(exc)})
                    result_catalog["updateStatus"] = "offline"
            self._send_json(200, {"ok": True, "catalog": result_catalog, "updated": updated, "offline": updated == 0, "errors": errors})

        def do_OPTIONS(self) -> None:
            # Same-origin browser requests do not require CORS preflight.
            self._send_json(405, {"ok": False, "error": "Metodo non disponibile"})

    return LabHandler


def create_server(host: str = "0.0.0.0", port: int = 8000, project_root: Path = PROJECT_ROOT) -> LabHTTPServer:
    return LabHTTPServer((host, port), Path(project_root))


def main() -> None:
    host = os.environ.get("PS5_WEB_LAB_HOST", "0.0.0.0")
    port = int(os.environ.get("PS5_WEB_LAB_PORT", "8000"))
    server = create_server(host, port)
    print(f"PS5 Web Lab: http://{host if host != '0.0.0.0' else '<IP-LAN-PC>'}:{port}/dashboard.html")
    print(f"Log campagna: {server.logs_dir}")
    print("Imposta l'URL nel browser PS5 usando l'indirizzo LAN del PC; Ctrl+C per arrestare.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArresto server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
