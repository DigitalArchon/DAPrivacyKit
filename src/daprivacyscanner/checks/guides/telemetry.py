"""Guided fixes: telemetry (see the package docstring)."""

from __future__ import annotations

from ...fix import RootChange
from ...guide import Guide, Step
from .._util import mozilla_profiles
from ..fixes import gset
from . import guide, option, service_off, ff_prefs, chromium_policy_options


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
        steps.append(Step("KDE", "System Settings → Privacy → User Feedback: set it to Disabled. DrKonqi asks before "
                          "sending a crash report."))
    return Guide(check.id, "Turn off crash reporting and usage surveys", "", steps)


@guide("tel.browser_telemetry", keys=("profile",))
def browser_telemetry(check, scan, outcome):
    steps = []
    ff = ff_prefs(check, scan, "Turn off telemetry and studies",
                  {"datareporting.healthreport.uploadEnabled": False, "app.shield.optoutstudies.enabled": False,
                   "datareporting.usage.uploadEnabled": False},
                  only=("Firefox", "Thunderbird"), key="profile")
    native_ff = any(p.install == "native" for p in mozilla_profiles(scan.host, scan.paths, ("Firefox",)))
    if native_ff:
        ff.append(option(check, "Firefox, for every user (policy)", [RootChange(
            "browser_policy", {"browser": "firefox", "settings": {"DisableTelemetry": True, "DisableFirefoxStudies": True}},
            "Set DisableTelemetry and DisableFirefoxStudies in /etc/firefox/policies/policies.json (DisableTelemetry also "
            "turns off the daily usage ping)")],
            side_effects=["Firefox shows \"Your browser is being managed by your organization\"."]))
    if ff:
        steps.append(Step("Firefox", options=ff))
    chromium = chromium_policy_options(check, scan, {"MetricsReportingEnabled": False, "BraveP3AEnabled": False,
                                                      "BraveStatsPingEnabled": False}, "Turn off usage statistics")
    steps.append(Step("Chromium-based browsers",
                      "Per profile: Settings → Privacy → \"Help improve…\" / \"Send usage statistics\" off (in Brave also "
                      "\"Privacy-preserving product analytics\" and \"Automatically send daily usage ping\").",
                      options=chromium))
    return Guide(check.id, "Turn off browser telemetry", "", steps)
