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
