"""JSON from outside the app nests at most 200 levels, and a parser that gives up (RecursionError) is a refusal,
never a crash (the DA apps' one security standard, 2026-11-14): untrusted.loads for online answers, GitHub's, a
browser's download index, online.json and the page's requests; helper._loads for the helper's requests."""

from __future__ import annotations

import json

import pytest
from test_helper_hardening import ask, serve_in_thread
from test_server import TOKEN, client

from daprivacyscanner import helper, online, untrusted, update
from daprivacyscanner.checks import online as checks_online
from daprivacyscanner.online import FakeNet, HttpResult

DEEP = "[" * 200_000                          # json.loads raised RecursionError on it
NESTED = lambda n: "[" * n + "]" * n           # noqa: E731


def test_loads_refuses_what_nests_too_deep_as_a_value_error():
    for text in (DEEP, NESTED(201), json.dumps({"a": json.loads(NESTED(200))})):
        with pytest.raises(untrusted.TooDeep):
            untrusted.loads(text)
        with pytest.raises(ValueError):
            untrusted.loads(text)
    assert untrusted.loads(NESTED(200)) is not None and untrusted.loads(b'{"open": true}') == {"open": True}


def test_an_online_answer_nested_too_deep_is_just_unreadable():
    assert checks_online._json(HttpResult(200, DEEP.encode())) == {}


def test_githubs_answer_nested_too_deep_is_refused_in_words():
    net = FakeNet(http={update.LATEST: HttpResult(200, DEEP.encode())})
    with pytest.raises(update.UpdateError, match="couldn't be read"):
        update.latest(net)


def test_online_json_nested_too_deep_is_a_settings_error(tmp_path):
    f = online.settings_path(tmp_path)
    f.parent.mkdir(parents=True)
    f.write_text(DEEP)
    with pytest.raises(online.SettingsError):
        online.load_settings(tmp_path)


def test_a_request_to_the_server_nested_too_deep_is_read_as_empty(cat, tmp_path):
    c = client(cat, tmp_path)
    r = c.post("/api/welcome", headers={"X-Token": TOKEN, "Content-Type": "application/json"}, content=DEEP)
    assert r.status_code == 200 and r.json() == {"show": True}


def test_a_helper_request_nested_too_deep_is_a_bad_request(monkeypatch):
    assert helper.handle(DEEP) == {"id": None, "ok": False, "error": "bad request"}
    assert helper.handle(json.dumps({"id": 1, "action": "hello", "args": {"x": json.loads(NESTED(250))}})) \
        == {"id": None, "ok": False, "error": "bad request"}


def test_a_deep_line_with_cancel_in_it_doesnt_end_the_helper_s_session(monkeypatch):
    """_cancel_of read such a line before handle did, and caught only ValueError: the session ended."""
    mine, theirs, t = serve_in_thread(monkeypatch)
    try:
        reply = ask(mine, ('{"action": "cancel", "x": ' + DEEP + "\n").encode())
        assert reply == {"id": None, "ok": False, "error": "bad request"}
        assert ask(mine, {"id": 2, "action": "hello"})["result"]["version"] == helper.PROTOCOL
    finally:
        mine.close()
        t.join(5)
        theirs.close()
