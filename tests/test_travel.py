"""Before you travel (tools/travel.py): its list is made of real checks, and the endpoint gives it
with the RAM disk's state."""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import make_host
from daprivacyscanner.checks import load_all
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import travel

H = {"X-Token": "t0ken"}


def test_every_item_is_an_implemented_check_listed_once(cat):
    ids = [i for i, _ in travel.ITEMS]
    assert len(ids) == len(set(ids))
    assert set(ids) <= set(cat.checks) and set(ids) <= set(load_all())
    assert all(cat[i].scope.value != "online" for i in ids)     # a scan's results, never an online test's
    assert all(w.endswith(".") for _, w in travel.ITEMS)


def test_endpoint(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/mounts": "/dev/sda2 / ext4 rw 0 0\n"})
    d = TestClient(create_app("t0ken", cat, make_host=lambda: host)).get("/api/tools/travel", headers=H).json()
    assert d["items"][0]["id"] == "enc.fde_missing"
    assert d["ramdisk"] == {"name": "RAMDisk", "path": "~/RAMDisk", "open": False, "files": 0}
    assert [r["name"] for r in d["ramdisks"]] == ["RAMDisk", "TempBrowser"]
    assert d["intro"] and d["advice"]
