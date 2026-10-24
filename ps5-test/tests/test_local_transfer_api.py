import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_transfer_server", ROOT / "tools" / "local-transfer-server.py")
TRANSFER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFER)


class LocalTransferApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="local-transfer-api-test-")
        self.root = Path(self.temp.name).resolve()
        (self.root / "nested").mkdir()
        (self.root / "nested" / "alpha.js").write_bytes(b"return {ok:true};")
        self.token = "unit-test-token"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), TRANSFER.make_handler(self.root, self.token, False))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, token=None):
        headers = {}
        if token is not None:
            headers["X-Transfer-Token"] = token
        if body is not None:
            headers["Content-Type"] = "application/octet-stream"
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers
        with response:
            return response.status, response.read(), response.headers

    def test_import_requires_auth_and_preserves_file_integrity(self):
        path = "/api/list?path=" + urllib.parse.quote("nested", safe="")
        self.assertEqual(self.request("GET", path)[0], 401)
        self.assertEqual(self.request("GET", path, token="wrong")[0], 401)
        status, body, _ = self.request("GET", path, token=self.token)
        self.assertEqual(status, 200)
        entries = json.loads(body)["entries"]
        self.assertEqual([item["name"] for item in entries], ["alpha.js"])
        file_path = "/api/file?path=" + urllib.parse.quote("nested/alpha.js", safe="")
        status, source, _ = self.request("GET", file_path, token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(source).hexdigest(), hashlib.sha256(b"return {ok:true};").hexdigest())

    def test_upload_is_authenticated_bounded_and_non_overwriting(self):
        payload = b'{"sessionId":"s1","results":[]}'
        path = "/api/upload?path=&name=research-s1.json"
        self.assertEqual(self.request("PUT", path, payload)[0], 401)
        status, body, _ = self.request("PUT", path, payload, self.token)
        self.assertEqual(status, 201)
        result = json.loads(body)
        self.assertEqual(result["bytes"], len(payload))
        saved = self.root / "research-s1.json"
        self.assertEqual(hashlib.sha256(saved.read_bytes()).digest(), hashlib.sha256(payload).digest())
        self.assertEqual(self.request("PUT", path, b"replacement", self.token)[0], 409)
        self.assertEqual(saved.read_bytes(), payload)

    def test_upload_rejects_declared_oversize_before_reading_body(self):
        req = urllib.request.Request(self.base + "/api/upload?path=&name=too-large.js", headers={
            "X-Transfer-Token": self.token,
            "Content-Length": str(TRANSFER.MAX_UPLOAD_BYTES + 1),
            "Content-Type": "application/octet-stream",
        }, method="PUT")
        try:
            response = urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            self.assertIn("128 MiB", json.loads(exc.read())["error"])
        else:
            response.close()
            self.fail("oversized body was accepted")
        self.assertFalse((self.root / "too-large.js").exists())

    def test_errors_and_path_escape_are_reported(self):
        bad = "/api/list?path=" + urllib.parse.quote("../", safe="")
        status, body, _ = self.request("GET", bad, token=self.token)
        self.assertEqual(status, 400)
        self.assertIn("fuori", json.loads(body)["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
