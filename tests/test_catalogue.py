import copy
import re
from pathlib import Path

import pytest
import yaml

from daprivacyscanner import catalogue
from daprivacyscanner.catalogue import CONTEXT_KEYS, CatalogueError, Scope, Tier, effective_severity, modifier_states


def test_real_catalogue_loads(cat):
    assert len(cat) > 80
    assert cat.schema_version == 1
    for spec in cat:
        assert spec.id.startswith(catalogue.CATEGORY_PREFIX[spec.category] + ".")
        assert isinstance(spec.scope, Scope) and isinstance(spec.tier, Tier)


# what full-disk encryption protects while the computer is off: one lower when it is on an encrypted disk
ENCRYPTED_AT_REST = {"desk.thumbnails", "desk.clipboard_history", "desk.zeitgeist", "enc.snapshots_retain_deleted",
                     "app.cups_spool", "auth.ssh_known_hosts_plain", "sbx.leftover_data", "enc.tmp_on_disk",
                     "auth.keyring_blank", "auth.chromium_basic_store", "auth.ssh_key_no_passphrase",
                     "auth.plaintext_credentials", "auth.shell_history_secrets", "auth.firefox_no_primary_password",
                     "auth.gpg_no_passphrase"}


def test_every_modifier_uses_context_keys_or_the_checks_own_findings(cat):
    findings = {s.id: s.finding_names - {"data_on_encrypted_disk"} for s in cat}
    findings = {k: v for k, v in findings.items() if v}
    assert {s.id for s in cat if "data_on_encrypted_disk" in s.finding_names} == ENCRYPTED_AT_REST
    # the catalogue header names these; any new finding name should be a deliberate addition
    updates = {"security_updates_pending", "kernel_update_pending", "kernel_restart_pending"}
    vpn = {"vpn_avoid", "vpn_closed_client", "vpn_ownership_concerns"}
    assert findings == {"desk.thumbnails": {"thumbnails_reference_removable_or_container", "thumbnails_on_disk_none_leaking",
                                            "thumbnails_expire"},
                        "enc.fde_missing": {"home_ecryptfs"},
                        "desk.indexers": {"indexes_outside_home", "index_on_unencrypted_disk"},
                        "net.exposed_services": {"firewall_blocks_exposed"},
                        "kern.updates": updates, "kern.updates_refreshed": updates,
                        "kern.package_signatures": {"signature_checks_off", "unsigned_over_http"},
                        "net.vpn_trust": vpn, "br.vpn_extensions": vpn,
                        "br.surveillance_browsers": {"chrome_or_edge_installed", "surveillance_default",
                                                     "chrome_or_edge_default"},
                        "br.default_browser": {"default_closed_ui"},
                        "auth.ssh_client_settings": {"agent_forwarded_everywhere", "host_keys_unchecked",
                                                     "agent_keys_unlimited"},
                        "auth.ssh_authorized_keys": {"sshd_reachable", "weak_authorized_keys"},
                        "auth.gpg_keys": {"gpg_weak_key"},
                        "br.site_permissions": {"site_default_allow"}}
    # each is named in words, for the reason a severity was chosen
    assert set().union(*findings.values(), {"data_on_encrypted_disk"}) <= set(catalogue.CONTEXT_LABEL)


@pytest.mark.parametrize("check_id", sorted(ENCRYPTED_AT_REST))
def test_on_an_encrypted_disk_severity_is_one_lower(cat, check_id):
    """Whatever else the check found, the same severity less one (never below 1), decided by a modifier on
    data_on_encrypted_disk (the runner's note says so) exactly when it was lowered."""
    import itertools
    spec = cat[check_id]
    others = sorted(spec.finding_names - {"data_on_encrypted_disk"})
    for combo in itertools.product((False, True), repeat=len(others)):
        values = dict(zip(others, combo))
        plain = effective_severity(spec, {**values, "data_on_encrypted_disk": False})
        enc = effective_severity(spec, {**values, "data_on_encrypted_disk": True})
        assert enc.value == max(1, plain.value - 1), values
        lowered = enc.value < plain.value
        assert lowered == ("data_on_encrypted_disk" in (enc.modifier or "")), values


def test_every_finding_a_check_sets_is_used_by_its_modifiers(cat):
    """The runner turns a check that sets a finding no modifier uses into an error (a scan showed
    enc.trim_off as "The check failed" on every SSD): a static look at what the check modules set."""
    import re
    from pathlib import Path
    import daprivacyscanner.checks as checks
    used = set().union(*(s.finding_names for s in cat))
    set_by_code = set()
    for f in Path(checks.__file__).parent.glob("*.py"):
        text = f.read_text()
        for m in re.finditer(r"findings\s*=\s*\{([^}]*)\}", text, re.S):
            set_by_code |= set(re.findall(r"[\"']([a-z_]+)[\"']\s*:", m.group(1)))
        set_by_code |= set(re.findall(r"findings\[[\"']([a-z_]+)[\"']\]\s*=", text))
    assert set_by_code and set_by_code <= used, sorted(set_by_code - used)


def test_folded_text_is_one_line(cat):
    assert "\n" not in cat["enc.fde_missing"].why


@pytest.mark.parametrize("check_id, values, expected", [
    # an unencrypted fixed disk is critical on every kind of machine (decided, keep it)
    ("enc.fde_missing", {"device": "laptop", "fde": "none"}, 10),
    ("enc.fde_missing", {"device": "desktop", "fde": "none"}, 10),
    ("enc.fde_missing", {"device": None, "fde": "none"}, 10),
    # only the home folder encrypted: still high; fscrypt or a LUKS /home less serious than nothing, eCryptfs in between
    ("enc.fde_missing", {"device": "laptop", "fde": "home", "home_ecryptfs": False}, 7),
    ("enc.fde_missing", {"device": "desktop", "fde": "home", "home_ecryptfs": True}, 8),
    ("enc.swap_unencrypted", {"hibernation": False, "fde": "home"}, 8),          # swap holds the home folder's files
    ("enc.swap_unencrypted", {"hibernation": True, "fde": "full"}, 9),
    # without disk encryption, swap still holds passwords and keys no file has: zram keeps them off the disk
    ("enc.swap_unencrypted", {"hibernation": False, "fde": "none"}, 8),
    ("enc.hibernate_unencrypted", {"fde": "none"}, 9),
    # thumbnails on disk: deleted within 30 days the lowest, kept longer higher, leaking highest. Nothing
    # leaking yet is a warning, warn_lower (2) below these: 1 and 3 on the page
    ("desk.thumbnails", {"thumbnails_on_disk_none_leaking": True, "thumbnails_expire": True,
                         "thumbnails_reference_removable_or_container": False,
                         "data_on_encrypted_disk": False}, 3),
    ("desk.thumbnails", {"thumbnails_on_disk_none_leaking": True, "thumbnails_expire": False,
                         "thumbnails_reference_removable_or_container": False,
                         "data_on_encrypted_disk": False}, 5),
    ("desk.thumbnails", {"thumbnails_on_disk_none_leaking": False, "thumbnails_expire": True,
                         "thumbnails_reference_removable_or_container": False,
                         "data_on_encrypted_disk": False}, 4),       # thumbnails of deleted files
    ("desk.thumbnails", {"thumbnails_on_disk_none_leaking": False, "thumbnails_expire": True,
                         "thumbnails_reference_removable_or_container": True,
                         "data_on_encrypted_disk": False}, 7),
    # an index that covers removable drives or other volumes: a problem, worse on an unencrypted disk
    ("desk.indexers", {"indexes_outside_home": True, "index_on_unencrypted_disk": False}, 6),
    ("desk.indexers", {"indexes_outside_home": True, "index_on_unencrypted_disk": True}, 8),
    ("auth.screen_lock", {"device": "desktop", "multi_user": False}, 5),
    ("auth.screen_lock", {"device": "desktop", "multi_user": True}, 7),
    ("kern.suspend_keys_in_ram", {"device": "desktop", "fde": "full"}, 1),
    ("kern.suspend_keys_in_ram", {"device": "desktop", "fde": "none"}, 0),
    ("sbx.x11_session", {"session": "wayland"}, 0),
    ("sbx.x11_session", {"session": "x11"}, 4),
    # off where nearly every distribution has it on, at almost no cost: worth a look (decided, keep it)
    ("kern.init_on_alloc", {}, 4),
])
def test_effective_severity(cat, check_id, values, expected):
    sev = effective_severity(cat[check_id], values)
    assert sev.value == expected
    assert not sev.uncertain_on


def test_unknown_context_keeps_known_severity_and_says_so(cat):
    sev = effective_severity(cat["auth.autologin"], {"tpm_unlock_no_pin": None})
    assert sev.value == 6 and sev.uncertain_on == ("tpm_unlock_no_pin",)
    assert not sev.not_applicable


def test_unknown_before_a_match_does_not_make_it_uncertain(cat):
    # device unknown, but fde == 'none' comes later and decides it
    sev = effective_severity(cat["kern.suspend_keys_in_ram"], {"device": None, "fde": "none"})
    assert sev.value == 0 and sev.not_applicable and sev.modifier == "fde == 'none'"


def test_unknown_after_a_match_is_uncertain(cat):
    sev = effective_severity(cat["kern.suspend_keys_in_ram"], {"device": "desktop", "fde": None})
    assert sev.value == 1 and sev.uncertain_on == ("fde",)


def test_modifier_states(cat):
    assert modifier_states(cat["kern.suspend_keys_in_ram"], {"device": "laptop", "fde": None}) == [False, None]


# ------------------------------------------------------------------ validation

@pytest.fixture(scope="module")
def raw():
    return yaml.safe_load((Path(__file__).resolve().parents[1] / catalogue.CATALOGUE_NAME).read_text())


def _with(raw, index, **changes):
    data = copy.deepcopy(raw)
    data["checks"][index].update(changes)
    return data


@pytest.mark.parametrize("changes, message", [
    ({"id": "network.fde_missing"}, "does not match category"),
    ({"id": "enc.FDE"}, "is not '<prefix>.<name>'"),
    ({"category": "storage"}, "unknown category"),
    ({"severity": 11}, "integer 0-10"),
    ({"severity": True}, "integer 0-10"),
    ({"tier": "magic"}, "magic"),
    ({"scope": "root"}, "root"),
    ({"colour": "red"}, "unknown field"),
    ({"related": ["enc.nope"]}, "not in the catalogue"),
    ({"modifiers": [{"when": "device == 'desktp'", "severity": 8}]}, "can never be"),
    ({"modifiers": [{"when": "autologin == 'yes'", "severity": 8}]}, "can never be"),
    ({"modifiers": [{"when": "device ==", "severity": 8}]}, "modifiers[0].when"),
    ({"modifiers": [{"when": "hibernation"}]}, "exactly `when` and `severity`"),
    ({"warn_lower": 1}, "warn_lower must be a whole number from 2 to 10"),
    ({"warn_lower": 11}, "warn_lower must be a whole number from 2 to 10"),
    ({"warn_lower": "3"}, "warn_lower must be a whole number from 2 to 10"),
    ({"warn_lower": True}, "warn_lower must be a whole number from 2 to 10"),
])
def test_rejects_invalid_entries(raw, changes, message):
    with pytest.raises(CatalogueError, match=re.escape(message)):
        catalogue.parse(_with(raw, 0, **changes))


def test_rejects_missing_fields(raw):
    data = copy.deepcopy(raw)
    del data["checks"][0]["fix"]
    with pytest.raises(CatalogueError, match="missing fix"):
        catalogue.parse(data)


def test_rejects_duplicate_ids(raw):
    data = copy.deepcopy(raw)
    data["checks"].append(copy.deepcopy(data["checks"][0]))
    with pytest.raises(CatalogueError, match="duplicate id enc.fde_missing"):
        catalogue.parse(data)


def test_rejects_other_schema_versions(raw):
    with pytest.raises(CatalogueError, match="schema_version"):
        catalogue.parse({**raw, "schema_version": 2})


def test_context_keys_match_the_catalogue_header():
    header = (catalogue.default_path()).read_text().split("schema_version")[0]
    for key in CONTEXT_KEYS:
        assert f"#   {key}" in header


def test_remedies_name_checks_by_title(cat):
    """Remedies are read by users: another check is named by its title, never its id."""
    from daprivacyscanner.guide import CHECK_ID
    assert not [(s.id, m) for s in cat for m in CHECK_ID.findall(s.remedy) if m in cat.checks]


def test_user_facing_text_never_names_a_check_by_id(cat):
    """What the user reads (title, why, remedy, an Easy fix's cost, meanwhile) says "disk encryption",
    never "enc.fde_missing" or "data_on_encrypted_disk": ids and finding names are for the code and developer mode. `fix` and `detect` are developer notes."""
    import re
    ids = {s.id for s in cat}
    word = re.compile(r"\b[a-z]+\.[a-z0-9_]+\b")
    for spec in cat:
        texts = {"title": spec.title, "why": spec.why, "remedy": spec.remedy,
                 "easy.cost": spec.easy.cost if spec.easy else "",
                 "meanwhile.text": spec.meanwhile.text if spec.meanwhile else ""}
        names = {n for n in catalogue.CONTEXT_LABEL if "_" in n} | {n for n in spec.finding_names if "_" in n}
        for field, text in texts.items():
            named = [m for m in word.findall(text or "") if m in ids]
            assert not named, f"{spec.id}: {field} names {named} by id; use its title or plain words"
            internal = sorted(n for n in names if re.search(rf"\b{n}\b", text or ""))
            assert not internal, f"{spec.id}: {field} uses the internal names {internal}; say it in words"


def test_modifiers_are_sent_to_the_page_in_words(cat):
    """The page shows each modifier's condition in words (describe_when), the expression only in developer mode."""
    d = cat["desk.thumbnails"].to_dict()
    assert all(m["when_text"] and m["when_text"] != m["when"] for m in d["modifiers"])
    words = lambda cid: {m["when"]: m["when_text"] for m in cat[cid].to_dict()["modifiers"]}  # noqa: E731
    assert words("net.mac_permanent")["device == 'desktop'"] == "device type is desktop"
    assert words("sbx.x11_session")["session == 'wayland'"] == "display session is Wayland"
    assert words("enc.fde_missing")["fde == 'home' and home_ecryptfs"] == \
        "disk encryption is home folder only and the home folder is encrypted with eCryptfs"


def _checks_that_can_warn() -> set[str]:
    """Every check whose class reaches warned() (or Status.WARN), directly or through a function
    of the checks package that does: found by reading the source, by name (an over-approximation)."""
    import ast
    from pathlib import Path

    import daprivacyscanner.checks as pkg
    calls, classes = {}, {}

    def called(node):
        out = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                fn = n.func
                out.add(fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None)
            if isinstance(n, ast.Attribute) and n.attr == "WARN":
                out.add("warned")
        return out - {None}

    for f in Path(pkg.__file__).parent.rglob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name not in ("detect", "detect_online"):
                calls.setdefault(node.name, set()).update(called(node))
            if isinstance(node, ast.ClassDef):
                cid = next((s.value.value for s in node.body if isinstance(s, ast.Assign)
                            and any(getattr(t, "id", None) == "id" for t in s.targets)
                            and isinstance(s.value, ast.Constant)), None)
                if cid:
                    classes[cid] = called(node)
    warns, grew = {"warned"}, True
    while grew:
        grew = False
        for fn, cs in calls.items():
            if fn not in warns and cs & warns:
                warns.add(fn)
                grew = True
    return {cid for cid, cs in classes.items() if cs & warns}


def test_every_check_that_can_warn_says_how_much_lower_a_warning_is():
    """A warning (a Risk) is rated below the same check failing (a Problem): each check that can warn
    states by how much (`warn_lower`, at least 2), so the value was chosen, not left to the default."""
    raw = {e["id"]: e for e in yaml.safe_load(catalogue.default_path().read_text())["checks"]}
    can_warn = _checks_that_can_warn()
    assert len(can_warn) > 30                        # the scan of the source found them
    # desk.session_restore never warns: the source scan finds it through a helper's name, and declaring it is harmless
    missing = sorted(c for c in can_warn - {"desk.session_restore"} if "warn_lower" not in raw[c])
    assert not missing, f"checks that can warn without warn_lower: {missing}"


def test_a_warning_is_at_least_two_lower_than_a_failure_in_every_context(cat):
    """For every check, in every combination of the names its modifiers use: a warning's severity is
    the failure's less warn_lower (at least 2), never below 1; not applicable stays not applicable."""
    import itertools
    from daprivacyscanner.catalogue import CONTEXT_KEYS, as_warning
    for spec in cat:
        names = sorted({n for m in spec.modifiers for n in m.when.names})
        domains = [(None, *(CONTEXT_KEYS[n] or (False, True))) if n in CONTEXT_KEYS and CONTEXT_KEYS[n] is not None
                   else (None, False, True) for n in names]
        for combo in itertools.product(*domains):
            values = dict(zip(names, combo))
            fail = effective_severity(spec, values)
            warn = as_warning(spec, fail)
            assert spec.warn_lower >= 2
            if fail.value == 0:
                assert warn.value == 0, (spec.id, values)
            else:
                assert warn.value == max(1, fail.value - spec.warn_lower) and warn.value <= max(1, fail.value - 2), \
                    (spec.id, values)
                assert warn.as_warning and not fail.as_warning

