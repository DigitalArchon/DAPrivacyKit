"""auth.startup_files_writable: login files, PATH folders under home and their programs that other
accounts can change; the auto fix takes the write bits away and reverts."""

from __future__ import annotations

import os

from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from test_fixes import redetect, revert, run_fix

CHECK = "auth.startup_files_writable"


def accounts_host(tmp_path, group_members="", **kw):
    uid, gid = os.getuid(), os.getgid()
    files = {"/etc/passwd": f"root:x:0:0::/root:/bin/bash\nalice:x:{uid}:{gid}::/home/alice:/bin/bash\n"
                            "bob:x:1001:1001::/home/bob:/bin/bash\n",
             "/etc/group": f"root:x:0:\nalice:x:{gid}:{group_members}\nbob:x:1001:\n"}
    host = make_host(tmp_path, files=files, **kw)
    host.uid = uid
    os.chmod(host.home, 0o750)
    return host


def test_private_files_pass(cat, tmp_path):
    host = accounts_host(tmp_path, home_files={".bashrc": "x", ".profile": "y"})
    os.chmod(host.home / ".bashrc", 0o664)                 # group write, but the group is alice's own
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.PASS and ev(o)["Files and folders checked"] >= 3


def test_world_writable_file_and_path_folder(cat, tmp_path):
    host = accounts_host(tmp_path, home_files={".bashrc": "x", ".local/bin/tool": "#!/bin/sh\n"})
    host.environ = {**host.environ, "PATH": f"{host.home}/.local/bin:/usr/bin"}
    os.chmod(host.home / ".bashrc", 0o666)
    os.chmod(host.home / ".local/bin", 0o777)
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.FAIL
    e = ev(o)
    assert e["~/.bashrc"] == "mode 666: every account can change it"
    assert e["~/.local/bin"] == "mode 777: every account can change it"
    assert e["Folders on PATH under your home"] == "~/.local/bin"
    assert effective_severity(cat[CHECK], {"multi_user": False}).value == 2


def test_shared_group_counts(cat, tmp_path):
    host = accounts_host(tmp_path, group_members="bob", home_files={".zshrc": "x"})
    os.chmod(host.home / ".zshrc", 0o664)
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.FAIL and "(1 other account) can change it" in ev(o)["~/.zshrc"]


def test_fix_follows_a_link_and_reverts(cat, tmp_path):
    host = accounts_host(tmp_path, home_files={"dotfiles/zshrc": "x", ".profile": "y"})
    os.symlink(host.home / "dotfiles/zshrc", host.home / ".zshrc")
    os.chmod(host.home / "dotfiles/zshrc", 0o646)
    os.chmod(host.home / ".profile", 0o4766)                 # an odd setuid bit stays as it was
    plan, res, log = run_fix(cat, host, CHECK)
    assert res.ok, res.error
    assert [a.display for a in plan.actions] == ["~/.profile", "~/.zshrc (→ ~/dotfiles/zshrc)"]
    assert os.stat(host.home / "dotfiles/zshrc").st_mode & 0o7777 == 0o644
    assert os.stat(host.home / ".profile").st_mode & 0o7777 == 0o4764
    assert os.path.islink(host.home / ".zshrc")
    assert redetect(cat, host, CHECK).status is Status.PASS
    assert all(r.ok for r in revert(host, log, res))
    assert os.stat(host.home / "dotfiles/zshrc").st_mode & 0o7777 == 0o646
    assert os.stat(host.home / ".profile").st_mode & 0o7777 == 0o4766
