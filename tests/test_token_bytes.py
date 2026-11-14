"""The server's tokens are compared as bytes, in constant time (the DA apps' one security standard, 2026-11-14): the
session token in X-Token and the launch token in the link. Anything beyond ASCII is a wrong token, never an error."""

from __future__ import annotations

import hmac

from test_server import TOKEN, client

from daprivacyscanner import server


def test_tokens_are_compared_as_bytes(cat, tmp_path, monkeypatch):
    seen, real = [], hmac.compare_digest

    def spy(a, b):
        seen.append((type(a), type(b)))
        return real(a, b)

    monkeypatch.setattr(server.hmac, "compare_digest", spy)
    c = client(cat, tmp_path, launch_token="l4unch")
    assert c.get("/api/state", headers={"X-Token": TOKEN}).status_code == 200
    c.get("/?t=l4unch")
    assert seen and all(kinds == (bytes, bytes) for kinds in seen)


def test_a_token_beyond_ascii_is_just_wrong(cat, tmp_path):
    c = client(cat, tmp_path, launch_token="l4unch")
    assert c.get("/api/state", headers={"X-Token": "t0kén".encode("latin-1")}).status_code == 403
    assert "data-token" not in c.get("/?t=l4unché").text
    assert server.same_token("t0ken", "t0ken") and not server.same_token(None, "t0ken")
    assert not server.same_token("\udcff", "t0ken")
