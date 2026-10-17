"""What does this app keep?: what the tools review of 2026-10-17 found (D1 to D13 and the suspicions it confirmed),
each with the test that keeps it fixed. The watch itself needs root and the real kernel: what it does there was
tried on the lab machines; here, its parts."""

from __future__ import annotations

from daprivacyscanner.tools import activity as A


# ------------------------------------------------------------------ D1: the user's own files are never named

def test_the_users_own_documents_saved_often_are_counted_not_named(tmp_path):
    home = tmp_path / "home"
    w = A.Where(str(home), 1000)
    recs = [[str(home / "Documents/Legal/letter-to-my-lawyer.odt"), A.OPENED | A.WRITTEN, 3, 5, 4, ""],
            ["/media/alice/USB/Diary/2026-10-17.txt", A.OPENED | A.WRITTEN, 1, 30, 1, ""],
            [str(home / ".config/xed/state"), A.WRITTEN, 0, 9, 3, ""]]
    for seconds in (600, 100):                       # in different minutes, or (a short watch) often
        s = A.summarise(recs, w, seconds, size_of=lambda p: 10)
        assert [r["path"] for r in s["regular"]] == ["~/.config/xed/state"]
        assert "letter-to-my-lawyer" not in repr(s) and "2026-10-17.txt" not in repr(s)     # folders are named, files not
    assert A.summarise(recs, w, 600, size_of=lambda p: 10)["regular_yours"] == 1
    assert A.summarise(recs, w, 100, size_of=lambda p: 10)["regular_yours"] == 2
    # a trial's home is made up: its "documents" may be named
    s = A.summarise(recs[:1], w, 600, names=True, size_of=lambda p: 10)
    assert [r["path"] for r in s["regular"]] == ["~/Documents/Legal/letter-to-my-lawyer.odt"] and not s["regular_yours"]
