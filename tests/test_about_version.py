"""A copy says which build it is: a dev build's version carries +dev.<commit>, as its file name does."""

import sys
import types

from daprivacyscanner import __version__, about


def _built(monkeypatch, **values):
    mod = types.ModuleType("daprivacyscanner._built")
    for k, v in values.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, "daprivacyscanner._built", mod)


def test_a_dev_build_says_it_is_one(monkeypatch):
    _built(monkeypatch, BUILT="2026-11-12", VERSION=f"{__version__}+dev.0123456789ab")
    assert about.version() == f"{__version__}+dev.0123456789ab" and about.dev_build()
    assert about.age()["version"] == f"{__version__}+dev.0123456789ab"


def test_a_release_and_an_older_build_file_give_the_packages_version(monkeypatch):
    _built(monkeypatch, BUILT="2026-11-12", VERSION=__version__)
    assert about.version() == __version__ and not about.dev_build()
    _built(monkeypatch, BUILT="2026-11-12")                      # written before the version was recorded
    assert about.version() == __version__
    _built(monkeypatch, BUILT="2026-11-12", VERSION="9.9")      # not this package's: never shown as its version
    assert about.version() == __version__
