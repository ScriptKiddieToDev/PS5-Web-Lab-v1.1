import contextlib
import errno
import importlib.util
import io
import sys
import threading
import unittest
import urllib.request
from email.message import Message
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("canvas_origin_server", ROOT / "canvas-cross-origin-server.py")
canvas_origin_server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = canvas_origin_server
SPEC.loader.exec_module(canvas_origin_server)


class CanvasOriginServerTests(unittest.TestCase):
    def setUp(self):
        self.handler_class = canvas_origin_server.make_handler()

    def invoke(self, method, path="/canvas-cross-origin.png?probe=unit", allow_origin=None):
        handler = object.__new__(self.handler_class)
        handler.server = type("FakeServer", (), {"fixture_path": canvas_origin_server.FIXTURE, "allow_origin": allow_origin})()
        handler.client_address = ("192.0.2.15", 12345)
        handler.path = path
        handler.headers = Message()
        handler.headers["Host"] = "192.0.2.1:8001"
        handler.headers["Origin"] = "http://192.0.2.1:8000"
        handler.wfile = io.BytesIO()
        codes = []
        response_headers = {}
        errors = []
        handler.send_response = lambda code, message=None: codes.append(code)
        handler.send_header = lambda key, value: response_headers.__setitem__(key, value)
        handler.end_headers = lambda: None
        handler.send_error = lambda code, message=None, explain=None: errors.append((code, message, explain))
        return handler, codes, response_headers, errors

    def test_serves_only_synthetic_png_without_cors_header(self):
        handler, codes, headers, errors = self.invoke("GET")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            handler.do_GET()
        self.assertEqual(codes, [200])
        self.assertEqual(headers["Content-Type"], "image/png")
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        body = handler.wfile.getvalue()
        self.assertTrue(body.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertNotIn("host=", output.getvalue())
        self.assertNotIn("origin=", output.getvalue())
        self.assertIn("Access-Control-Allow-Origin:absent", output.getvalue())
        self.assertEqual(errors, [])

    def test_head_has_headers_but_no_body_and_other_paths_are_not_served(self):
        handler, codes, headers, _errors = self.invoke("HEAD")
        handler.do_HEAD()
        self.assertEqual(codes, [200])
        self.assertEqual(handler.wfile.getvalue(), b"")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

        handler, _codes, _headers, errors = self.invoke("GET", "/server.py")
        handler.do_GET()
        self.assertEqual(errors[0][0], 404)

    def test_blob_url_probe_is_an_exact_local_fixture_with_restricted_policy(self):
        handler, codes, headers, errors = self.invoke("GET", "/blob-url-probe.html")
        handler.do_GET()
        body = handler.wfile.getvalue().decode("utf-8")
        self.assertEqual(codes, [200])
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn("connect-src blob:", headers["Content-Security-Policy"])
        self.assertIn("researchProbe", body)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(int(headers["Content-Length"]), len(body.encode("utf-8")))
        self.assertEqual(errors, [])

    def test_post_is_not_an_available_operation(self):
        handler, _codes, _headers, errors = self.invoke("POST")
        handler.do_POST()
        self.assertEqual(errors[0][0], 405)

    def test_cors_allows_only_the_configured_exact_origin(self):
        handler, codes, headers, errors = self.invoke("GET", allow_origin="http://192.0.2.1:8000")
        with contextlib.redirect_stdout(io.StringIO()):
            handler.do_GET()
        self.assertEqual(codes, [200])
        self.assertEqual(headers["Access-Control-Allow-Origin"], "http://192.0.2.1:8000")
        self.assertEqual(headers["Vary"], "Origin")
        self.assertEqual(errors, [])

        handler, _codes, headers, _errors = self.invoke("GET", allow_origin="http://192.0.2.1:8000")
        handler.headers.replace_header("Origin", "http://192.0.2.1:9000")
        with contextlib.redirect_stdout(io.StringIO()):
            handler.do_GET()
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_cors_option_rejects_non_origin_values(self):
        for value in ("*", "https://example.test/path", "file:///tmp", "http://user@example.test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canvas_origin_server.validate_allowed_origin(value)

    def test_real_loopback_http_response_has_no_cors_permission_header(self):
        try:
            httpd = canvas_origin_server.ThreadingHTTPServer(("127.0.0.1", 0), self.handler_class)
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES):
                self.skipTest(f"Sandbox denies local TCP bind: {error}")
            raise
        httpd.fixture_path = canvas_origin_server.FIXTURE
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = httpd.server_address
            request = urllib.request.Request(
                f"http://{host}:{port}/canvas-cross-origin.png?probe=tcp-test",
                headers={"Origin": "http://127.0.0.1:8000"},
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                body = response.read()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get_content_type(), "image/png")
                self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
                self.assertTrue(body.startswith(b"\x89PNG\r\n\x1a\n"))
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
