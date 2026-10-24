import json
import hashlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import server


class ActiveLabPersistenceTests(unittest.TestCase):
    def setUp(self):
        project_logs = Path(__file__).resolve().parents[1] / "logs"
        self.historical_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in project_logs.iterdir() if path.is_file()}
        self.temp = tempfile.TemporaryDirectory(prefix="active-lab-test-")
        self.root = Path(self.temp.name)
        (self.root / "pages").mkdir()
        source_pages = Path(__file__).resolve().parents[1] / "pages"
        for name in ("active-vulnerability-research-lab.html", "active-vulnerability-research-lab.js",
                     "active-vulnerability-research-lab-core.js"):
            (self.root / "pages" / name).write_bytes((source_pages / name).read_bytes())
        self.httpd = server.create_server("127.0.0.1", 0, self.root)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.httpd.server_address
        self.endpoint = f"http://{host}:{port}/api/scan-log"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def post(self, event):
        request = urllib.request.Request(self.endpoint, data=json.dumps(event).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as exc:
            self.fail(f"event rejected: {exc.code} {exc.read().decode()}")
        with response:
            return response.status, json.loads(response.read())

    def test_active_lab_events_persist_to_isolated_temp_logs(self):
        sid = "active-lab-test-0001"
        result = {
            "id": "A2-alpha-false-01", "category": "canvas-webidl",
            "description": "test alpha option", "state": "PASS",
            "observed": {"expected": {"alpha": False}, "actual": {"alpha": False},
                         "classification": "EXPECTED", "implementation": "active-vulnerability-research-lab/1.0.0"},
            "error": None, "limitations": ["temporary localhost test"],
            "durationMs": 1.25, "sessionId": sid
        }
        start = {"eventId":"evt-start-0001", "eventType":"scan_start", "sessionId":sid,
                 "clientTime":"2026-10-24T00:00:00Z", "payload":{"tool":"Active Vulnerability Research Lab"}}
        row = {"eventId":"evt-result-0001", "eventType":"test_result", "sessionId":sid,
               "clientTime":"2026-10-24T00:00:01Z", "payload":{"result":result}}
        dossier = {"schemaVersion":1,"tool":"Active Vulnerability Research Lab","sessionId":sid,
                   "startedAt":"2026-10-24T00:00:00Z","completedAt":"2026-10-24T00:00:02Z",
                   "declaredFirmware":"14.10","overallState":"completed","environment":{"userAgent":"test"},
                   "results":[result],"limitations":["isolated test"]}
        summary = {"eventId":"evt-summary-0001", "eventType":"session_summary", "sessionId":sid,
                   "clientTime":"2026-10-24T00:00:02Z", "payload":{"dossier":dossier}}
        self.assertEqual(self.post(start)[0], 201)
        self.assertEqual(self.post(row)[0], 201)
        status, response = self.post(summary)
        self.assertEqual(status, 201)
        self.assertTrue(response["saved"])
        logs = self.root / "logs"
        records = [json.loads(line) for line in (logs / Path(response["sessionFile"]).name).read_text().splitlines()]
        self.assertEqual([item["eventType"] for item in records], ["scan_start", "test_result", "session_summary"])
        self.assertEqual(json.loads((logs / Path(response["summaryFile"]).name).read_text())["dossier"]["results"][0]["id"], result["id"])
        self.assertIn("test alpha option", (logs / Path(response["markdownFile"]).name).read_text())
        project_logs = Path(__file__).resolve().parents[1] / "logs"
        after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in project_logs.iterdir() if path.is_file()}
        self.assertEqual(after, self.historical_hashes, "project historical logs stayed byte-identical")

    def test_server_serves_lab_page_and_runner_from_pages_directory(self):
        host, port = self.httpd.server_address
        with urllib.request.urlopen(f"http://{host}:{port}/pages/active-vulnerability-research-lab.html", timeout=3) as response:
            page = response.read().decode()
        self.assertIn("Active Vulnerability Research Lab", page)
        self.assertIn("active-vulnerability-research-lab-core.js", page)
        with urllib.request.urlopen(f"http://{host}:{port}/pages/active-vulnerability-research-lab.js", timeout=3) as response:
            runner = response.read().decode()
        self.assertIn("/api/scan-log", runner)


if __name__ == "__main__":
    unittest.main()
