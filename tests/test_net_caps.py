"""online.RealNet's caps on what a server sends (the DA apps' one security standard, 2026-11-14): an error's answer
is read only as far as MAX_ERROR_BODY, and a download that names no limit of its own still has one (MAX_DOWNLOAD).
Against a server on this computer (plain http is allowed there; conftest refuses anything else)."""

from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager

from daprivacyscanner import online


@contextmanager
def serving(status: int, size: int, length: bool = True):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            if length:
                self.send_header("Content-Length", str(size))
            self.end_headers()
            try:
                for _ in range(0, size, 65536):
                    self.wfile.write(b"x" * 65536)
            except OSError:                       # the app stopped reading: what this test is about
                pass

        def log_message(self, *a):
            pass

    class Server(http.server.HTTPServer):
        def handle_error(self, request, client_address):
            pass

    srv = Server(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}/"
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_error_s_answer_is_read_only_as_far_as_its_cap():
    with serving(500, 8 * 65536) as url:
        r = online.RealNet().http_get(url, timeout=5)
    assert r.status == 500 and 0 < len(r.body) <= online.MAX_ERROR_BODY == 64 * 1024


def test_a_download_that_names_no_limit_still_has_one(tmp_path, monkeypatch):
    monkeypatch.setattr(online, "MAX_DOWNLOAD", 100_000)
    for length in (True, False):
        with serving(200, 4 * 65536, length=length) as url:
            r = online.RealNet().download(url, tmp_path / "file", timeout=5)
        assert r.status is None and "larger than expected" in r.error
