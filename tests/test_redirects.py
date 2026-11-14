"""online.ConfinedRedirects: a redirect is followed only to the host asked or to one the call named,
never from https to http (rule 10: every host contacted is one the page named first)."""

from __future__ import annotations

import io
import urllib.request
from email.message import Message

import pytest

from daprivacyscanner import online


def follow(url: str, to: str, hosts=()):
    req = urllib.request.Request(url)
    req.allowed_hosts = tuple(hosts)
    return online.ConfinedRedirects().redirect_request(req, io.BytesIO(), 302, "Found", Message(), to)


def test_the_same_host_and_an_upgrade_to_https_are_followed():
    assert follow("https://dist.torproject.org/a", "https://dist.torproject.org/b").full_url.endswith("/b")
    assert follow("http://example.org/a", "https://example.org/a") is not None


@pytest.mark.parametrize("to", ["https://elsewhere.example/a", "http://dist.torproject.org/a",
                                "ftp://dist.torproject.org/a"])
def test_another_host_or_a_downgrade_is_stopped(to):
    with pytest.raises(online.Redirected, match="isn't one of the hosts named"):
        follow("https://dist.torproject.org/a", to)


def test_a_host_the_call_named_is_followed_and_stays_allowed_on_the_next_hop():
    hosts = ("aus1.torproject.org", "dist.torproject.org")
    nxt = follow("https://aus1.torproject.org/i.json", "https://dist.torproject.org/i.json", hosts)
    assert nxt.allowed_hosts == hosts
    with pytest.raises(online.Redirected):
        follow("https://aus1.torproject.org/i.json", "https://cdn.mullvad.net/i.json", hosts)


def test_the_real_opener_uses_it():
    net = online.RealNet()
    assert any(isinstance(h, online.ConfinedRedirects) for h in net._opener.handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in net._opener.handlers)


def test_a_request_that_sends_something_follows_no_redirect():
    """urllib turned a redirected POST (a UPnP router's SOAP request) into a GET of the new address."""
    req = urllib.request.Request("http://192.168.1.1:5000/ctl", data=b"<s:Envelope/>", method="POST")
    req.allowed_hosts = ()
    with pytest.raises(online.Redirected, match="sends something"):
        online.ConfinedRedirects().redirect_request(req, io.BytesIO(), 302, "Found", Message(),
                                                    "http://192.168.1.1:5000/other")


def test_a_redirect_from_the_internet_into_the_local_network_is_stopped_even_to_a_host_named():
    for to in ("https://192.168.1.1/x", "https://127.0.0.1/x", "https://[fd00::1]/x", "https://router.local/x"):
        with pytest.raises(online.Redirected, match="from the internet to this computer"):
            follow("https://example.org/a", to, hosts=(online.urllib.parse.urlsplit(to).hostname,))
    assert follow("http://192.168.1.1/a", "https://192.168.1.1/a") is not None      # the router's own upgrade


def test_a_post_redirected_by_a_real_server_is_not_sent_again(tmp_path):
    import http.server
    import threading

    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(("POST", self.path))
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302)
            self.send_header("Location", "/again")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            seen.append(("GET", self.path))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        r = online.RealNet().http_post(f"http://127.0.0.1:{srv.server_port}/ctl", b"<x/>", {"Content-Type": "text/xml"},
                                       timeout=5)
    finally:
        srv.shutdown()
        srv.server_close()
    assert r.status is None and "sends something" in r.error
    assert seen == [("POST", "/ctl")]
