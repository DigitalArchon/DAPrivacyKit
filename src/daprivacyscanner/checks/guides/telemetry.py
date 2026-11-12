"""Guided fixes: telemetry (see the package docstring)."""

from __future__ import annotations

from ...fix import RootChange
from ...guide import Guide, Step
from .._util import mozilla_profiles
from ..fixes import gset
from . import guide, option, service_off, ff_prefs, chromium_policy_options, chromium_step


@guide("tel.crash_reporters", keys=("turn_off",))
def crash_reporters(check, scan, outcome):
    on = {e.label: e.value for e in outcome.evidence}
    steps = []
    if on.get("apport") == "on":
        steps.append(Step("apport", options=[option(check, "Turn off apport", [
            RootChange("edit_config", {"target": "apport"}, "Set enabled=0 in /etc/default/apport"),
            *service_off(scan, "apport.service")], key="turn_off")]))
    if "whoopsie" in on:
        steps.append(Step("whoopsie (sends Ubuntu crash reports)",
                          options=[option(check, "Turn off whoopsie", service_off(scan, "whoopsie.service", "whoopsie.path"), key="turn_off")]))
    if "ABRT" in on:
        steps.append(Step("ABRT", options=[option(check, "Turn off ABRT", service_off(
            scan, "abrtd.service", "abrt-journal-core.service", "abrt-oops.service", "abrt-xorg.service",
            "abrt-vmcore.service"), key="turn_off")], side_effects=["Crashes are no longer collected for reporting."]))
    if "popularity-contest" in on:
        steps.append(Step("popularity-contest", "It sends the list of packages you use, weekly.",
                          options=[option(check, "Stop participating", [RootChange(
                              "edit_config", {"target": "popcon"}, 'Set PARTICIPATE="no" in /etc/popularity-contest.conf')],
                              key="turn_off")]))
    if "pkgstats" in on:
        steps.append(Step("pkgstats", "Arch's pkgstats sends the list of the packages you have installed, and your "
                          "mirror, every week. Its timer can't be turned off, only masked; or remove pkgstats.",
                          commands=["sudo systemctl mask --now pkgstats.timer     # undo: sudo systemctl unmask pkgstats.timer",
                                    "sudo pacman -Rns pkgstats                   # or remove it"]))
    if "motd-news" in on:
        steps.append(Step("motd-news", "Ubuntu fetches news for the login message from motd.ubuntu.com, sending the "
                          "release, kernel, processor, uptime and cloud in its request.",
                          options=[option(check, "Turn off motd-news", [
                              RootChange("edit_config", {"target": "motd-news"}, "Set ENABLED=0 in /etc/default/motd-news"),
                              *service_off(scan, "motd-news.timer")], key="turn_off",
                              side_effects=["The login message in a terminal no longer shows Ubuntu's news."])]))
    if scan.context.desktop.is_gnome:
        acts = gset(scan, "org.gnome.desktop.privacy", "report-technical-problems", "false")
        acts += gset(scan, "org.gnome.desktop.privacy", "send-software-usage-stats", "false")
        if acts:
            steps.append(Step("GNOME's problem reporting", options=[option(check, "Turn it off", acts, key="turn_off")]))
    if scan.context.desktop.is_kde:
        steps.append(Step("KDE", "System Settings → Security & Privacy → User Feedback: set it to Disabled. DrKonqi "
                          "asks before sending a crash report."))
    return Guide(check.id, "Turn off crash reporting and usage surveys", "", steps)


@guide("tel.browser_telemetry", keys=("profile",))
def browser_telemetry(check, scan, outcome):
    from .._util import chromium_dirs, firefox_policies, firefox_prefs
    from ..telemetry import mozilla_telemetry_on
    steps = []
    policies = firefox_policies(scan.host)
    # per profile, only what the check counts as on there (Thunderbird: telemetry alone; what the policy turns
    # off is left), so an option is never one that changes nothing the check sees
    from ..browser import ff_policies
    off = lambda p, prefs: {k: False for k in mozilla_telemetry_on(p.app, prefs, ff_policies(scan, p))}  # noqa: E731
    ff = ff_prefs(check, scan, "Turn off telemetry and studies", off, key="profile")
    tb = ff_prefs(check, scan, "Turn off telemetry", off, only=("Thunderbird",), key="profile")
    native_on = [p for p in mozilla_profiles(scan.host, scan.paths, ("Firefox",)) if p.install == "native"
                 and mozilla_telemetry_on(p.app, firefox_prefs(scan.host, p.path), policies)]
    settings = {k: True for k in ("DisableTelemetry", "DisableFirefoxStudies") if policies.get(k) is not True}
    if native_on and settings:
        ff.append(option(check, "Firefox, for every user (policy)", [RootChange(
            "browser_policy", {"browser": "firefox", "settings": settings},
            f"Set {' and '.join(settings)} in /etc/firefox/policies/policies.json"
            + (" (DisableTelemetry also turns off the daily usage ping)" if "DisableTelemetry" in settings else ""))],
            side_effects=["Firefox shows \"Your browser is being managed by your organization\"."]))
    if ff:
        steps.append(Step("Firefox", options=ff))
    if tb:
        steps.append(Step("Thunderbird", "Settings → Privacy & Security → \"Allow Thunderbird to send technical and "
                          "interaction data to Mozilla\" does the same from inside Thunderbird.", options=tb))
    on = {e.label for e in outcome.evidence if str(e.value).endswith(" on")}
    flagged = {d.label for d in chromium_dirs(scan.paths)} & on
    chromium = chromium_policy_options(check, scan, {"MetricsReportingEnabled": False, "BraveP3AEnabled": False,
                                                      "BraveStatsPingEnabled": False}, "Turn off usage statistics",
                                       skip=lambda d: d.label not in flagged)
    steps.append(chromium_step(scan, "Per profile: Settings → Privacy → \"Help improve…\" / \"Send usage statistics\" "
                               "off (in Brave also \"Privacy-preserving product analytics\" and \"Automatically send "
                               "daily usage ping\").", chromium, not flagged))
    return Guide(check.id, "Turn off browser telemetry", "", steps)


COUNTME_OVERRIDE = "/etc/dnf/repos.override.d/60-daprivacyscanner-countme.repo"
RPMNEW_COST = ("DNF4 has no override folder, so the repository files themselves are changed. rpm then counts them as "
               "edited: when a package brings a new version of one (fedora-repos at an upgrade, epel-release), rpm keeps "
               "yours and saves its new one beside it as .rpmnew, so changes to that repository's settings don't arrive "
               "until you merge them (sudo rpmconf -a, or by hand).")


@guide("tel.countme", keys=("off",))
def countme(check, scan, outcome):
    """DNF5: one override file of the app's own ([*] countme=0, the helper's dnf-countme drop-in), read after the
    repository files, which stay as their packages installed them, and covering repositories added later. DNF4 has no
    overrides: the repository files are edited, at the cost of .rpmnew files at their packages' updates, so it is no
    Easy fix there (its option has no key)."""
    from ...helper import dropin_content
    from .._util import read_text
    from ..kernel import is_dnf5
    counting = [str(e.value) for e in outcome.evidence if e.label == "countme=1"]
    effects = ["Fedora's anonymous count of active systems no longer includes this machine."]
    title = "Turn off DNF's countme"
    if not counting:
        return Guide(check.id, title, "", [Step("Turn off countme", "countme is off for every repository.", done=True)])
    if is_dnf5(scan.host):
        mine = read_text(scan.host, scan.host.sys_path(COUNTME_OVERRIDE)) == dropin_content(
            "dnf-countme", {"countme": "0"}).decode()
        if mine:
            # an override file read later wins over the app's (dnf config-manager setopt writes 99-config_manager.repo)
            step = Step("Turn off countme", f"The app's override file, {COUNTME_OVERRIDE}, turns countme off for every "
                        "repository, but an override file DNF5 reads after it turns it on again for "
                        f"{', '.join(counting)}: dnf config-manager's own (99-config_manager.repo) takes it out.",
                        commands=["sudo dnf config-manager unsetopt " + " ".join(f"{r}.countme" for r in counting)])
        else:
            step = Step("Turn off countme", "DNF5 adjusts the repositories' settings with the files in "
                        "/etc/dnf/repos.override.d after reading the repository files: one file of the app's own turns "
                        "countme off for every repository.", options=[option(
                            check, "Turn off countme for every repository",
                            [RootChange("write_dropin", {"name": "dnf-countme", "settings": {"countme": "0"}},
                                        f"Write {COUNTME_OVERRIDE} with [*] countme=0")], recommended=True, key="off",
                            side_effects=effects + ["The repository files stay as their packages installed them, so "
                                                    "their updates arrive as usual; repositories added later are covered "
                                                    "too. Reverting removes the file."])])
    else:
        step = Step("Turn off countme", "DNF4 reads countme from each repository's file.", options=[option(
            check, "Set countme=0 in the repository files",
            [RootChange("edit_config", {"target": "countme"}, "Set countme=0 wherever a repository file in "
                                                              "/etc/yum.repos.d or /etc/dnf/dnf.conf has countme=1")],
            side_effects=effects + [RPMNEW_COST])])
    return Guide(check.id, title, "DNF adds a counter to one request a week for each repository that has countme on, "
                 "so Fedora can count the systems in use without identifying them.", [step])
