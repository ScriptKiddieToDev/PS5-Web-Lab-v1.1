import json
import io
import shutil
import sys
import tempfile
import threading
import uuid
import unittest
import urllib.error
import urllib.parse
from email.message import Message
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import server  # noqa: E402


class Response:
    def __init__(self, body):
        self.status = 200
        self.headers = {}
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size=-1):
        return self.body


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ps5-web-lab-test-")
        self.root = Path(self.temp.name)
        (self.root / "pages").mkdir()
        (self.root / "data").mkdir()
        shutil.copy(ROOT / "dashboard.html", self.root / "dashboard.html")
        shutil.copy(ROOT / "hardware-check.html", self.root / "hardware-check.html")
        (self.root / "pages" / "test-page.html").write_text("<!doctype html><title>Test</title>", encoding="utf-8")
        for name in (
            "vulnerability-scanner.html", "vulnerability-scanner.js", "vulnerability-scanner-core.js",
            "canvas-security-impact.html", "canvas-security-impact.js", "canvas-security-impact-core.js",
        ):
            shutil.copy(ROOT / "pages" / name, self.root / "pages" / name)
        shutil.copy(ROOT / "data" / "cve-catalog.json", self.root / "data" / "cve-catalog.json")
        self.fake_server = type("TestHTTPServer", (), {})()
        self.fake_server.project_root = self.root.resolve()
        self.fake_server.logs_dir = (self.root / "logs").resolve()
        self.fake_server.server_instance = "test-server-instance"
        self.fake_server.session_files = {}
        self.fake_server.seen_event_ids = set()
        self.fake_server.data_lock = threading.RLock()
        self.handler_class = server.make_handler()

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, method, path, value=None, content_type="application/json"):
        if value is None:
            raw = b""
        elif isinstance(value, bytes):
            raw = value
        else:
            raw = json.dumps(value).encode("utf-8")
        headers = Message()
        if content_type:
            headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(raw))
        handler = object.__new__(self.handler_class)
        handler.server = self.fake_server
        handler.client_address = ("127.0.0.1", 54321)
        handler.path = path
        handler.headers = headers
        handler.rfile = io.BytesIO(raw)
        handler.wfile = io.BytesIO()
        status = []
        response_headers = {}
        handler.send_response = lambda code, message=None: status.append(code)
        handler.send_header = lambda key, header_value: response_headers.__setitem__(key, header_value)
        handler.end_headers = lambda: None
        getattr(handler, "do_" + method)()
        response_body = handler.wfile.getvalue()
        try:
            parsed = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = response_body
        return status[0], response_headers, parsed

    def post(self, path, value, content_type="application/json"):
        status, _headers, body = self.invoke("POST", path, value, content_type)
        return status, body

    def get(self, path):
        status, headers, body = self.invoke("GET", path)
        if isinstance(body, bytes):
            return status, headers, body
        return status, headers, json.dumps(body).encode("utf-8")

    def event(self, kind, payload, event_id="event-result-0001"):
        return {"eventId": event_id, "eventType": kind, "sessionId": "test-session-0001", "clientTime": "2026-10-24T00:00:00Z", "payload": payload}

    def result(self):
        return {
            "id": "canvas.context", "category": "Canvas e grafica", "description": "Tiny controlled canvas test.",
            "state": "PASS", "observed": {"contextCreated": True}, "error": None,
            "durationMs": 1, "limitations": ["Not an exploitability check."], "sessionId": "test-session-0001",
        }

    def test_serves_dashboard_pages_and_health_without_exposing_files(self):
        status, _, body = self.get("/dashboard.html")
        self.assertEqual(status, 200)
        self.assertIn(b"fetch('/pages/", body)
        self.assertIn(b"Elenco pagine caricato", (ROOT / "dashboard.html").read_bytes())
        self.assertNotIn(b"Server locale: raggiungibile", (ROOT / "dashboard.html").read_bytes())
        status, _, body = self.get("/pages/")
        self.assertEqual(status, 200)
        self.assertIn(b"test-page.html", body)
        self.assertIn(b"vulnerability-scanner.html", body)
        self.assertIn(b"canvas-security-impact.html", body)
        status, _, body = self.get("/pages/vulnerability-scanner.html")
        self.assertEqual(status, 200)
        self.assertIn(b"Vulnerability Research &amp; Evidence Analyzer", body)
        self.assertIn(b"vulnerability-scanner-core.js", body)
        status, js_headers, body = self.get("/pages/vulnerability-scanner.js")
        self.assertEqual(status, 200)
        self.assertIn(js_headers["Content-Type"].split(";", 1)[0], {"text/javascript", "application/javascript"})
        self.assertIn(b"network.same-origin-post", body)
        status, _, body = self.get("/pages/vulnerability-scanner-core.js")
        self.assertEqual(status, 200)
        self.assertIn(b"buildDossier", body)
        status, _, body = self.get("/pages/canvas-security-impact.html")
        self.assertEqual(status, 200)
        self.assertIn(b"Canvas Security Impact", body)
        self.assertIn(b"canvas-security-impact-core.js", body)
        status, js_headers, body = self.get("/pages/canvas-security-impact.js")
        self.assertEqual(status, 200)
        self.assertIn(js_headers["Content-Type"].split(";", 1)[0], {"text/javascript", "application/javascript"})
        self.assertIn(b"canvas-security-impact.F-cross-origin", body)
        status, js_headers, body = self.get("/pages/canvas-security-impact-core.js")
        self.assertEqual(status, 200)
        self.assertIn(js_headers["Content-Type"].split(";", 1)[0], {"text/javascript", "application/javascript"})
        self.assertIn(b"aggregateCase", body)
        status, _, body = self.get("/hardware-check.html")
        self.assertEqual(status, 200)
        self.assertIn(b"PS5 Browser Diagnostics", body)
        status, headers, body = self.get("/api/health")
        health = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(health["logging"])
        self.assertEqual(health["service"], "PS5-Web-Lab")
        self.assertEqual(health["apiVersion"], 1)
        self.assertEqual(health["backendVersion"], server.BACKEND_VERSION)
        self.assertEqual(headers["X-PS5-Web-Lab-Version"], server.BACKEND_VERSION)
        self.assertEqual(health["postEndpoint"], "/api/scan-log")
        self.assertEqual(health["logsDirectory"], str((self.root / "logs").resolve()))
        for hidden in ("/server.py", "/logs/anything.jsonl", "/data/active-catalog.json"):
            hidden_status, _, _ = self.invoke("GET", hidden)
            self.assertEqual(hidden_status, 404)
        status, headers, body = self.invoke("GET", "/api/scan-log")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "POST")
        self.assertEqual(body["method"], "GET")
        status, _, body = self.invoke("GET", "/api/health/")
        self.assertEqual(status, 404, "API paths are exact; a trailing slash is not silently treated as health")
        self.assertTrue(body["ok"] is False)
        status, _, body = self.invoke("POST", "/api/scan-log/", {})
        self.assertEqual(status, 404, "POST logging route has no trailing slash")
        self.assertEqual(body["path"], "/api/scan-log/")
        status, headers, body = self.invoke("POST", "/api/health", {})
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(body["method"], "POST")

    def test_analysis_events_reads_only_valid_jsonl_without_mutating_logs(self):
        logs = self.root / "logs"
        logs.mkdir()
        first = self.event("scan_start", {"tool": "Canvas"}, "event-start-0001")
        second = self.event("test_result", {"result": self.result()}, "event-result-0001")
        second["clientTime"] = "2026-10-24T00:00:01Z"
        log_path = logs / "scan-test.jsonl"
        log_path.write_text(json.dumps(first) + "\nnot-json\n" + json.dumps(second) + "\n", encoding="utf-8")
        (logs / "scan-test-summary.json").write_text('{"private":"not a JSONL event"}', encoding="utf-8")
        before = log_path.read_bytes()

        status, headers, response = self.invoke("GET", "/api/analysis-events")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertTrue(response["ok"])
        self.assertEqual(response["eventCount"], 2)
        self.assertEqual([item["eventId"] for item in response["events"]], [first["eventId"], second["eventId"]])
        self.assertNotIn("serverMetadata", response["events"][0])
        self.assertEqual(log_path.read_bytes(), before, "GET must leave historical JSONL bytes unchanged")
        status, _, _ = self.invoke("POST", "/api/analysis-events", {})
        self.assertEqual(status, 404)

    def test_events_are_jsonl_and_summary_is_saved_as_json_and_markdown(self):
        start = self.event("scan_start", {"startedAt": "2026-10-24T00:00:00Z"}, "event-start-0001")
        self.assertEqual(self.post("/api/scan-log", start)[0], 201)
        connection = self.event("connectivity_check", {"origin": "http://127.0.0.1:8000"}, "event-connect-0001")
        self.assertEqual(self.post("/api/scan-log", connection)[0], 201)
        result = self.result()
        result_event = self.event("test_result", {"result": result})
        status, reply = self.post("/api/scan-log", result_event)
        self.assertEqual(status, 201)
        self.assertTrue(reply["saved"])
        self.assertTrue(reply["sessionFile"].startswith("logs/scan-"))
        self.assertNotIn("test-session-0001", reply["sessionFile"])
        self.assertEqual(self.post("/api/scan-log", result_event)[1]["duplicate"], True)

        dossier = {
            "schemaVersion": 1, "sessionId": "test-session-0001", "startedAt": "2026-10-24T00:00:00Z",
            "completedAt": "2026-10-24T00:00:01Z", "declaredFirmware": "14.10", "environment": {"userAgent": "test"},
            "overallState": "COMPLETED", "results": [result], "transmissionErrors": [],
            "conclusions": {"factsObserved": ["tiny test passed"], "hypotheses": [], "vulnerabilityCorrelations": [], "inconclusiveResults": [], "recommendedChecks": []},
            "missingData": [], "limitations": ["No security conclusion."],
        }
        status, final = self.post("/api/scan-log", self.event("session_summary", {"dossier": dossier}, "event-summary-0001"))
        self.assertEqual(status, 201)
        self.assertTrue(final["summaryFile"])
        log_path = self.root / reply["sessionFile"]
        records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["eventType"] for record in records], ["scan_start", "connectivity_check", "test_result", "session_summary"])
        self.assertTrue(records[0]["serverMetadata"]["receivedAt"].endswith("Z"))
        summary_path = self.root / final["summaryFile"]
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["dossier"]["sessionId"], "test-session-0001")
        markdown_path = self.root / final["markdownFile"]
        self.assertIn("# PS5 Vulnerability Research", markdown_path.read_text(encoding="utf-8"))

        # Simulate a server restart: recover the session mapping and event IDs from JSONL.
        self.fake_server.session_files = {}
        self.fake_server.seen_event_ids = set()
        status, duplicate = self.post("/api/scan-log", result_event)
        self.assertEqual(status, 200)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["sessionFile"], reply["sessionFile"])
        self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 4, "replayed event is not appended twice after restart")

    def test_canvas_impact_record_uses_existing_validated_event_protocol(self):
        session_id = "csi-test-session-0001"
        record = {
            "id": "canvas-security-impact.A4-alpha-false-getter",
            "category": "Canvas Security Impact",
            "description": "Diagnostic execution only; not a security conclusion.",
            "state": "PASS",
            "observed": {
                "raw": {"getterReads": 1, "alpha": False},
                "interpretation": {"classification": "EXPECTED"},
            },
            "error": None,
            "durationMs": 1,
            "limitations": ["A diagnostic PASS is not proof of browser security."],
            "sessionId": session_id,
        }
        event = {
            "eventId": "csi-event-test-0001",
            "eventType": "test_result",
            "sessionId": session_id,
            "clientTime": "2026-10-24T00:00:00Z",
            "payload": {"result": record, "canvasSecurityImpactRecord": {"raw": {"getterReads": 1}, "interpretation": {"classification": "EXPECTED"}}},
        }
        status, reply = self.post("/api/scan-log", event)
        self.assertEqual(status, 201)
        self.assertTrue(reply["saved"])
        self.assertEqual(reply["eventType"], event["eventType"])
        path = self.root / reply["sessionFile"]
        saved = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(saved["payload"]["canvasSecurityImpactRecord"]["interpretation"]["classification"], "EXPECTED")
        duplicate_status, duplicate_reply = self.post("/api/scan-log", event)
        self.assertEqual(duplicate_status, 200, "the existing server protocol deduplicates retries by stable event ID")
        self.assertTrue(duplicate_reply["saved"])
        self.assertTrue(duplicate_reply["duplicate"])
        self.assertEqual(duplicate_reply["eventType"], event["eventType"])

    def test_workspace_log_path_is_written_physically_and_client_cannot_choose_path(self):
        original_files = self.fake_server.session_files
        original_seen = self.fake_server.seen_event_ids
        session_id = "workspace-test-" + uuid.uuid4().hex[:12]
        event_id = "event-workspace-" + uuid.uuid4().hex[:12]
        self.fake_server.session_files = {}
        self.fake_server.seen_event_ids = set()
        try:
            event = {"eventId": event_id, "eventType": "scan_start", "sessionId": session_id, "clientTime": "2026-10-24T00:00:00Z", "payload": {"requestedPath": "/tmp/should-not-be-used"}}
            status, reply = self.post("/api/scan-log", event)
            self.assertEqual(status, 201)
            self.assertEqual(reply["logsDirectory"], str(self.fake_server.logs_dir))
            saved_path = self.root / reply["sessionFile"]
            self.assertTrue(saved_path.is_file())
            self.assertNotIn("should-not-be-used", str(saved_path))
            record = json.loads(saved_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertNotIn("requestedPath", record["serverMetadata"])
        finally:
            self.fake_server.session_files = original_files
            self.fake_server.seen_event_ids = original_seen

    def test_rejects_bad_content_type_json_and_result_shape(self):
        status, body = self.post("/api/scan-log", b"{}", "text/plain")
        self.assertEqual(status, 400)
        self.assertIn("Content-Type", body["error"])
        status, body = self.post("/api/scan-log", b"{")
        self.assertEqual(status, 400)
        self.assertIn("JSON", body["error"])
        bad = self.event("test_result", {"result": dict(self.result(), state="VULNERABLE")})
        status, body = self.post("/api/scan-log", bad)
        self.assertEqual(status, 400)
        self.assertIn("state", body["error"])
        self.assertFalse((self.root / "logs").exists())

    def test_rejects_oversized_events(self):
        event = self.event("scan_start", {"extra": "x" * (server.MAX_EVENT_BYTES + 1024)})
        status, body = self.post("/api/scan-log", event)
        self.assertEqual(status, 413)
        self.assertFalse(body["ok"])

    def test_catalog_import_validates_schema_and_persists_to_fixed_location(self):
        catalog = json.loads((ROOT / "data" / "cve-catalog.json").read_text(encoding="utf-8"))
        status, response = self.post("/api/catalog/import", catalog)
        self.assertEqual(status, 201)
        self.assertTrue((self.root / "data" / "active-catalog.json").is_file())
        status, _, body = self.get("/api/catalog")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["entries"]), 2)
        invalid = dict(catalog, entries=[dict(catalog["entries"][0], id="not-a-cve")])
        status, response = self.post("/api/catalog/import", invalid)
        self.assertEqual(status, 400)
        self.assertIn("CV", response["error"])

    def test_nvd_update_uses_fixed_authoritative_endpoint_and_keeps_cve_unknown(self):
        answer = {"vulnerabilities": [{"cve": {"published": "2024-06-10T00:00:00.000", "lastModified": "2026-04-02T00:00:00.000", "descriptions": [{"lang": "en", "value": "NVD test description"}]}}]}
        requests = []

        def fake_urlopen(request, timeout):
            requests.append((request.full_url, timeout))
            cve_id = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)["cveId"][0]
            response_data = json.loads(json.dumps(answer))
            response_data["vulnerabilities"][0]["cve"]["id"] = cve_id
            return Response(json.dumps(response_data).encode("utf-8"))

        with mock.patch.object(server.urllib.request, "urlopen", side_effect=fake_urlopen):
            status, response = self.post("/api/catalog/update", {})
        self.assertEqual(status, 200)
        self.assertEqual(response["updated"], 2)
        self.assertFalse(response["offline"])
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(urllib.parse.urlsplit(url).hostname == "services.nvd.nist.gov" for url, _ in requests))
        self.assertTrue(all(timeout == 8 for _, timeout in requests))
        self.assertTrue(all(entry["applicability"] == "unknown" for entry in response["catalog"]["entries"]))
        self.assertTrue((self.root / "data" / "active-catalog.json").exists())

    def test_nvd_offline_keeps_the_local_snapshot_available(self):
        with mock.patch.object(server.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline test")):
            status, response = self.post("/api/catalog/update", {})
        self.assertEqual(status, 200)
        self.assertTrue(response["offline"])
        self.assertEqual(response["updated"], 0)
        self.assertEqual(len(response["catalog"]["entries"]), 2)
        self.assertEqual(response["catalog"]["updateStatus"], "offline")
        self.assertFalse((self.root / "data" / "active-catalog.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
