"use strict";
/* DA Privacy Kit frontend: the machine's context, then every check's result with its severity
   on this machine. A scan only reads; fixes and guided fixes change the system only after the
   user has seen exactly what they do and confirmed it.

   Access: the launch link's one-time token is exchanged by the server for the session token, which this page
   gets in its body (data-token, taken off at once) and keeps in its session storage: this tab's, for this origin
   alone, port included (a cookie would reach every other local server on 127.0.0.1 the user visits in --browser
   mode, whatever its port). Every request carries it in the X-Token header, which a page on another site can't
   add. No token lives in the page's source or its address. */

// ------------------------------------------------------------------ helpers

const S = {
  token: "",          // the session token (sessionToken), sent with every request
  state: null,        // /api/state
  report: null,       // the last scan
  open: new Set(),    // expanded check ids
  scanning: false,
  adminActive: false, // the root helper is running (one polkit prompt covers what follows)
  band: null,         // show only findings of one severity band ("critical", "high", ...)
  show: "all",        // which checks to list: "findings", "hygiene", "info", "accepted" or "all"
  source: "all",      // which results to list: "all", "scan" or "online"
  job: null,          // the online tests' job, as /api/online/status last said
  jobClock: 0,        // local time minus the server's, for the job's timers
  jobLost: 0,         // status requests that failed in a row
  jobHidden: false,   // the user closed the finished job's strip
  presentation: null, // {on, since}: Presentation mode, shown in the top bar while it is on
};

const isOnline = (spec) => spec.scope === "online";
const isFeature = (spec) => spec.tier === "feature";                                 // listed under Tools
const hasGuide = (spec) => spec.tier === "guided" || spec.tier === "feature";      // the rest have one plan

const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;      // through CSSOM: the page's CSP refuses style attributes
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// replaceChildren, skipping empty entries and flattening lists as h() does
function fill(el, ...children) {
  el.replaceChildren(...children.flat(Infinity).filter(c => c !== null && c !== undefined && c !== false));
  return el;
}

const TOKEN_KEY = "daps-token";

/* The session token: handed over in the body when the launch link was opened (and kept in this tab's session
   storage, so a reload keeps working), else from that storage. "" when this tab was opened without the link. */
function sessionToken() {
  const given = document.body.dataset.token || "";
  if (given) {
    delete document.body.dataset.token;
    try { sessionStorage.setItem(TOKEN_KEY, given); } catch { /* no storage: this load alone */ }
    history.replaceState(null, "", "/");      // the used link out of the address bar and this tab's history
    return given;
  }
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
}

async function api(method, path, body, raw = false) {
  const res = await fetch(path, {
    method, credentials: "omit",
    headers: { "X-Token": S.token, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (raw) {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.text();
  }
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    const err = new Error(data.error || data.detail || `${res.status} ${res.statusText}`);
    err.declined = !!data.declined;
    err.status = res.status;
    err.data = data;                  // a failed fix still reports what was re-checked after the rollback
    throw err;
  }
  return data;
}

function toast(text, kind = "info", ms = 6000, action = null) {
  // read out by a screen reader as it appears: an error at once, the rest when it has finished speaking
  const el = h("div", { class: `toast ${kind}`, role: kind === "error" ? "alert" : "status" }, text,
    action ? h("button", { class: "small", onclick: () => { el.remove(); action.onclick(); } }, action.label) : null);
  $("#toasts").append(el);
  setTimeout(() => el.remove(), ms);
}

function setStatus(text, kind = "idle") {
  $("#status").className = kind;
  $("#status-text").textContent = text;
}

const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

// ------------------------------------------------------------------ vocabulary

const CONTEXT_LABEL = {
  fde: "Disk encryption",
  virtualization: "Virtual machine or container",
  device: "Device type",
  multi_user: "Several user accounts",
  session: "Display session",
  hibernation: "Hibernation possible",
  tpm_unlock_no_pin: "TPM unlock without a PIN",
  autologin: "Automatic login",
  exposed_services: "Services exposed to the network",
  vpn_active: "VPN connected",
  ipv6_global: "Public IPv6 address",
};
const ENUM_LABEL = { none: "None", home: "Home folder only", partial: "Partial", full: "Full", laptop: "Laptop", desktop: "Desktop",
                     wayland: "Wayland", x11: "X11", vm: "VM", container: "Container" };
const NOTE_KIND = { risk: "Worth knowing", info: "Note", limitation: "Scan limit" };
// A failure is a Problem, a warning a Risk (possible, partial, or not happened yet; rated below the problem
// it could become). The words say what kind of result it is, never how serious: that is the severity's
// number and colour alone, so the words are drawn in the text colour (model.STATUS_WORD says the same).
const STATUS_LABEL = { pass: "Pass", fail: "Problem", warn: "Risk", unknown: "Couldn't check", not_applicable: "N/A",
                       error: "Error", pending: "Not checked yet", unscanned: "Not scanned",
                       online_pending: "Online test, not run" };
// the status above the severity number, short enough for the row's left column
const STATUS_SHORT = { pass: "Pass", fail: "Problem", warn: "Risk", unknown: "Unknown", not_applicable: "N/A",
                       error: "Error", pending: "Pending", unscanned: "Not run", online_pending: "Not run" };
const BAND_LABEL = { critical: "critical", high: "high", medium: "medium", low: "low" };
const TIER_TITLE = {
  auto: "Can be fixed after one confirmation, and undone",
  guided: "Fixed step by step, with each side effect explained",
  advice: "Explained only; the app never makes this change",
  feature: "An optional tool, not a pass/fail check",
};
const SCOPE_TITLE = {
  user: "Runs as you",
  system: "Needs administrator access for full detection or to fix",
  online: "Contacts other machines: runs only from Online tests, never in a scan",
};
const KIND_TITLE = {
  hygiene: "Hygiene: residue of normal use (caches, histories). Listed and cleaned, not counted as a finding",
  info: "Information: an inventory worth knowing about, neither a pass nor a fail",
};

function band(sev) {
  if (sev <= 0) return "na";
  if (sev >= 9) return "critical";
  if (sev >= 6) return "high";
  if (sev >= 3) return "medium";
  return "low";
}

// a row's severity: in its colour only when there is a problem (fail or warning); grey when it
// passed, however high; outlined when it couldn't be checked or hasn't run (what is at stake)
function rowPill(v, title) {
  if (v.status === "not_applicable" || v.sev <= 0) return h("span", { class: "sev sev-na", title }, "–");
  if (v.found) return sevPill(v.sev, title);
  if (v.status === "pass") return h("span", { class: "sev sev-off", title: `${title}: passed` }, v.sev);
  return h("span", { class: `sev sev-${band(v.sev)} sev-stake`, title: `${title} if there is a problem` }, v.sev);
}

function sevPill(sev, title) {
  return h("span", { class: `sev sev-${band(sev)}`, title }, sev > 0 ? sev : "–");
}

function contextValue(v) {
  if (v === null || v === undefined) return h("span", { class: "badge v-unknown" }, "unknown");
  if (v === true) return h("span", { class: "badge v-yes" }, "yes");
  if (v === false) return h("span", { class: "badge v-no" }, "no");
  return h("span", { class: "badge v-enum" }, ENUM_LABEL[v] || v);
}

function evidenceLine(e, fresh = null) {
  if (e.kind === "note") return h("li", {}, e.label);
  const tag = fresh instanceof Set && fresh.has(e.label) ? h("span", { class: "newtag", title: "Not there at the last scan" }, "new") : null;
  if (e.value === null || e.value === undefined || e.value === "") return h("li", {}, tag, e.label);
  return h("li", {}, tag, `${e.label}: `, h("b", {}, String(e.value)));
}

// an inventory's entries that weren't there at the last scan (what starts at login), by check
function newItems(id) {
  return S.report?.changes?.new_items?.[id] || [];
}

// informational notes: risks that would apply if something changed, and limits of the scan
// The user sees checks by their titles everywhere; their ids (enc.fde_missing) appear only in developer
// mode (--dev), where the catalogue is the reference.
const isDev = () => !!S.state?.dev;
const checkTitle = (id) => S.state?.catalogue?.find(sp => sp.id === id)?.title || id;
// chips naming checks, each opening its row (a set-up's opens the Tools panel)
const relatedChips = (ids) => ids.map(id => h("span", { class: "chip", title: "Show it in the list", onclick: () => reveal(id) },
  checkTitle(id)));

function noteBox(n) {
  return h("div", { class: `notebox ${n.kind}` },
    h("div", { class: "nhead" }, h("span", { class: "nkind" }, NOTE_KIND[n.kind] || n.kind), h("b", {}, n.title)),
    h("div", {}, n.text),
    n.related.length ? h("div", { class: "related" }, relatedChips(n.related)) : null);
}

// ------------------------------------------------------------------ context pane

function renderContext() {
  const list = $("#context-list");
  list.replaceChildren();
  const ctx = S.report?.context;
  if (!ctx) {
    list.append(h("div", { class: "empty" }, "Scan to see this machine's context."));
    return;
  }
  for (const key of S.state.context_keys) {
    const c = ctx.values[key];
    if (!c) continue;
    const unknown = c.value === null;
    list.append(h("div", { class: `ctx${unknown ? " unknown" : ""}` },
      h("div", { class: "head" }, h("span", { class: "name" }, CONTEXT_LABEL[key] || key), contextValue(c.value)),
      isDev() ? h("span", { class: "key" }, key) : null,
      c.note ? h("span", { class: "note" }, c.note) : null,
      c.partial ? h("span", { class: "note" }, "Partial: some sources need administrator access.") : null,
      c.evidence.length ? h("ul", {}, c.evidence.map(evidenceLine)) : null,
      (c.notes || []).map(noteBox),
    ));
  }
  list.append(h("div", { class: "desk" }, `Desktop: ${ctx.desktop.label}`));
}

// ------------------------------------------------------------------ checks pane

// An accepted finding is hidden (listed only under Accepted, not counted) until its severity rises
// above the one it was accepted at; then it is shown again, saying why. history.py has the same rule.
const acceptedRecord = (id) => S.state?.accepted?.[id] || null;
const risen = (rec, sev) => !!rec && Number.isInteger(rec.severity) && sev > rec.severity;
// accepted, and its severity hasn't risen since (the server's history.hidden): left out of what changed since
// the last scan, new, resolved or otherwise, and never "to do" in Before you travel
const acceptedHidden = (id) => !!acceptedRecord(id) && !risen(acceptedRecord(id), S.report?.results?.[id]?.effective_severity ?? 0);

// new since the last scan, leaving out what the user accepted and is still hidden, and what has been
// fixed since (the scan's diff isn't recomputed after a fix: the chips follow the results as they are now)
const foundNow = (id) => {
  const spec = S.state.catalogue.find(s => s.id === id);
  return !spec || !!view(spec).found;
};
// a problem when last checked that this scan couldn't check (no administrator access this time): it isn't
// resolved, which only a scan that checked it can say. history.py's `unchecked`, by check
const uncheckedNow = (id) => {
  const spec = S.state.catalogue.find(s => s.id === id);
  return !!spec && isUnchecked(view(spec));
};
const lastChecked = (id) => (S.report?.changes?.unchecked || []).find(u => u.id === id && uncheckedNow(id)) || null;
const lastCheckedText = (u) => `${STATUS_LABEL[u.status] || "A problem"}, severity ${u.severity}, when it was last checked`
  + (u.checked ? ` (${new Date(u.checked * 1000).toLocaleDateString([], { dateStyle: "medium" })})` : "")
  + ". This scan couldn't check it, so it isn't resolved.";
const newShown = (ids) => ids.filter(id => {
  const spec = S.state.catalogue.find(s => s.id === id);
  return !spec || (!isFeature(spec) && view(spec).found && !acceptedHidden(id));
});
// the scan's `new` holds whatever fails or warns now and didn't before, of any kind: only findings are "new
// findings" (the headline counts those alone); hygiene and information are new under their own names
const newOfKind = (ids, kind) => ids.filter(id => (S.state.catalogue.find(s => s.id === id)?.kind || "finding") === kind);

function whyShownAgain(rec, result) {
  const when = new Date((rec.when || 0) * 1000).toLocaleDateString([], { dateStyle: "medium" });
  const then = rec.severity_reason || "", now = result.severity_reason || "";
  const text = `Shown again automatically: its severity rose from ${rec.severity} to ${result.effective_severity} `
    + `since you accepted it on ${when}`;
  return text + (then !== now ? ` (then: ${then || "its base severity"}; now: ${now || "its base severity"}).`
    : " (the app rates it higher now than when you accepted it).");
}

// one row's view of a check: catalogue spec + this machine's result, if any
function view(spec) {
  const r = S.report;
  const result = r?.results?.[spec.id];
  if (result) {
    return { status: result.status, sev: result.effective_severity, uncertain: result.uncertain_on,
             summary: result.summary, evidence: result.evidence, partial: result.partial, error: result.error,
             notes: result.notes, fixable: result.fixable, modifiers: r.modifiers?.[spec.id], kind: spec.kind,
             found: (result.status === "fail" || result.status === "warn") && result.effective_severity > 0,
             ms: result.duration_ms, accepted: !!acceptedRecord(spec.id),
             resurfaced: risen(acceptedRecord(spec.id), result.effective_severity), needsAdmin: !!result.needs_admin,
             result };
  }
  if (spec.scope === "online") {
    return { status: r ? "online_pending" : "unscanned", sev: spec.severity, uncertain: [], modifiers: null, kind: spec.kind };
  }
  const pending = r?.not_implemented?.[spec.id];
  if (pending) {
    const na = pending.effective_severity === 0 && !pending.uncertain_on.length;
    return { status: na ? "not_applicable" : "pending", sev: pending.effective_severity,
             uncertain: pending.uncertain_on, modifiers: r.modifiers?.[spec.id], kind: spec.kind };
  }
  return { status: "unscanned", sev: spec.severity, uncertain: [], modifiers: null, kind: spec.kind };
}

// the online tests' findings among a job's results, by the same rule: not what the user accepted
const jobFindings = (job) => Object.entries(job.results).filter(([id, x]) => (x.status === "fail" || x.status === "warn")
  && x.effective_severity > 0 && (x.kind || "finding") === "finding"
  && !(acceptedRecord(id) && !risen(acceptedRecord(id), x.effective_severity))).length;   // the job's own severity

// the same rule as the server's CheckResult.is_finding, minus what the user accepted (unless it rose)
const isFinding = (v) => !!v.found && v.kind === "finding" && (!v.accepted || v.resurfaced);
const isHygiene = (v) => !!v.found && v.kind === "hygiene";
const isInfo = (v) => !!v.found && v.kind === "info";
const isAccepted = (v) => !!v.found && v.kind === "finding" && v.accepted && !v.resurfaced;    // hidden
// couldn't be checked (or the check failed to run): a problem there wouldn't show as a finding
const isUnchecked = (v) => v.status === "unknown" || v.status === "error";
// an Easy fix (the catalogue's `easy`) for a problem on this machine, not accepted: offered by Easy fixes…
const isEasy = (v) => !!v.result?.easy && !!v.found && !isAccepted(v);

// what a check's own findings (not context keys) mean, for the uncertain-severity line: the server's
// labels (the catalogue's, one per name), else the name in words
const findingLabel = (n) => S.state?.labels?.[n] || n.replace(/_/g, " ");

function uncertainText(spec, v) {
  const names = v.uncertain || [];
  const ctx = names.filter(n => S.state.context_keys.includes(n));
  const own = names.filter(n => !S.state.context_keys.includes(n));
  const parts = [];
  if (ctx.length) parts.push(`depends on ${ctx.map(n => CONTEXT_LABEL[n] || n).join(", ").toLowerCase()}, which couldn't be determined`);
  if (own.length) parts.push(`depends on ${own.map(n => `whether ${findingLabel(n)}`).join(", ")}, which couldn't be checked`);
  if (!parts.length) return null;
  // the severities the unknown modifiers would give, had they matched
  const states = v.modifiers || [];
  // a risk is lowered the same way whichever modifier would decide it (catalogue.as_warning)
  const asRisk = (n) => v.result?.as_warning && n > 0 ? Math.max(1, n - spec.warn_lower) : n;
  const could = spec.modifiers.filter((m, i) => states[i] === null || states[i] === undefined).map(m => asRisk(m.severity));
  const hi = Math.max(v.sev, ...could), lo = Math.min(v.sev, ...could);
  const range = hi > v.sev && lo < v.sev ? `anywhere from ${lo} to ${hi}` : hi > v.sev ? `as high as ${hi}` : `as low as ${lo}`;
  return `Severity ${parts.join("; ")}: it could be ${range}${lo === 0 ? " (0: not applicable)" : ""}.`;
}

function matches(spec, q) {
  if (!q) return true;
  q = q.toLowerCase();
  return [spec.id, spec.title, spec.why, spec.category].some(s => (s || "").toLowerCase().includes(q));
}

function shown(v) {
  switch (S.show) {
    case "findings": return isFinding(v);
    case "hygiene": return isHygiene(v);
    case "info": return isInfo(v);
    case "accepted": return isAccepted(v);
    default: return !isAccepted(v);                 // accepted findings are hidden everywhere else
  }
}

// the report's headline: findings by severity band, what else there is, and what changed
// A fix the user applied whose problem is back (UndoLog.undone): the loudest thing on the page,
// above everything else, until it is fixed again, reverted from History or accepted.
// started with --browser: what the user's own browser can do with this page, at the top until it is acknowledged
// (for this page only: it is said again at the next start)
function browserBanner() {
  return h("div", { class: "notebox danger" }, h("b", {}, "Running in your web browser, not the app's window"),
    "This page shows your findings, file names and whatever the tools show you. Here, any browser extension allowed on all "
    + "sites can read it and act on it, the browser may send what you type to an online spell checker, and it can keep "
    + "what is typed in its session files or sync its history. Use the app's window where you can: it needs WebKitGTK 4.1, "
    + "and the app says how to install it when it starts without --browser. Quit when you are done.",
    h("div", { class: "orow" }, h("button", { class: "small", onclick: () => { S.browserNoted = true; renderChecks(); } }, "I understand")));
}

// The app never looks for a newer version of itself: once its own copy is a few months old it says so here.
function oldCopyBanner(app) {
  const url = S.state?.welcome?.links?.releases || "";
  return h("div", { class: "notebox" }, h("b", {}, "This copy of the app is getting old"),
    `It was built on ${app.built_text}, about ${Math.floor(app.days / 30)} months ago. A newer one probably fixes bugs and `
    + "knows newer versions of your apps. The app never looks for updates by itself: the latest is on its releases page, ",
    welcomeLink("releases"), url ? "." : "",
    h("div", { class: "orow" }, h("button", { class: "small", onclick: () => { S.oldCopyNoted = true; renderChecks(); } }, "Not now")));
}

function undoneBanner(items) {
  const day = (t) => new Date(t * 1000).toLocaleDateString([], { dateStyle: "medium" });
  return h("section", { class: "undone", role: "alert" },
    h("h2", {}, items.length === 1 ? "⚠ A fix you made has been undone"
      : `⚠ ${items.length} fixes you made have been undone`),
    h("p", {}, "Something changed these back: an update, another program, a sync, or someone using this computer. "
      + "Fix them again, and if it keeps happening, find what does it. If you changed one back on purpose, accept the finding."),
    h("ul", {}, items.map(u => {
      const spec = S.state.catalogue.find(s => s.id === u.check_id);
      const result = S.report.results[u.check_id] || {};
      return h("li", {},
        h("div", { class: "uhead" },
          h("span", { class: "sev-num" }, u.severity),
          h("a", { href: "#", onclick: (e) => { e.preventDefault(); reveal(u.check_id); } }, spec ? spec.title : u.check_id),
          h("span", { class: "spacer" }),
          spec && result.fixable ? h("button", { class: "small primary", onclick: () => hasGuide(spec) ? openGuide(spec) : openFix(spec) },
            "Fix again…") : null,
          spec ? h("button", { class: "small ghost", title: "You changed it back on purpose: hide it until its severity rises",
            onclick: () => setAccepted(spec, true, "Changed back on purpose") }, "Accept") : null),
        h("div", { class: "small muted" }, `Fixed on ${day(u.applied)} (${u.title}); found undone on ${day(u.undone_since)}.`),
        u.changed_back?.length ? h("ul", { class: "small" }, u.changed_back.map(t => h("li", {}, `Changed back: ${t}`))) : null);
    })));
}

function summaryBar(views) {
  const bands = { critical: 0, high: 0, medium: 0, low: 0 };
  let unknown = 0, stake = 0, hygiene = 0, info = 0, acc = 0;
  for (const v of views) {
    if (isFinding(v)) bands[band(v.sev)]++;
    if (isHygiene(v)) hygiene++;
    if (isInfo(v)) info++;
    if (isAccepted(v)) acc++;
    if (isUnchecked(v)) { unknown++; stake = Math.max(stake, v.sev); }
  }
  const total = Object.values(bands).reduce((a, b) => a + b, 0);
  const easy = views.filter(isEasy).length;
  const counter = (n, label, show, title) => n ? h("button", { class: `band${S.show === show ? " on" : ""}`, title,
    onclick: () => setShow(S.show === show ? "all" : show) }, `${n} ${label}`) : null;
  const ch = S.report.changes;
  const fresh = ch ? newShown(ch.new) : [];
  // a finding whose severity changed and that has been fixed since is resolved now; one resolved at the
  // scan and found again (a fix reverted from History) isn't
  const changed = ch ? ch.changed.filter(c => foundNow(c.id) && !acceptedHidden(c.id)) : [];
  const resolved = ch ? [...ch.resolved, ...ch.changed.filter(c => !foundNow(c.id)).map(c => c.id)]
    .filter(id => !foundNow(id) && !uncheckedNow(id) && !acceptedHidden(id)).sort() : [];
  const notChecked = ch ? (ch.unchecked || []).filter(u => uncheckedNow(u.id) && !acceptedHidden(u.id)) : [];
  const titleOf = (id) => S.state.catalogue.find(sp => sp.id === id)?.title || id;
  const chips = (ids, cls) => ids.map(id => h("span", { class: `chip ${cls}`, title: "Show it in the list", onclick: () => reveal(id) }, titleOf(id)));
  return h("div", { class: "report" },
    h("span", { class: "headline" }, total ? plural(total, "finding") : "No findings"),
    Object.entries(bands).filter(([, n]) => n).map(([b, n]) =>
      h("button", { class: `band${S.band === b ? " on" : ""}`, title: S.band === b ? "Show every severity again"
          : `Show only the ${BAND_LABEL[b]} findings`, onclick: () => setBand(b) },
        h("span", { class: `sev sev-${b}` }, n), ` ${BAND_LABEL[b]}`)),
    S.band ? h("button", { class: "small ghost", onclick: () => setBand(null) }, "Show all") : null,
    counter(hygiene, "hygiene", "hygiene", KIND_TITLE.hygiene),
    counter(info, "to know about", "info", KIND_TITLE.info),
    counter(acc, "accepted (hidden)", "accepted", "Findings you've accepted: hidden and not counted unless their severity rises"),
    easy ? h("button", { class: "small primary easy-btn", title: "Fixes that cost you nothing, or next to nothing: "
        + "see them all, choose, and apply them together", onclick: () => openEasy() }, `Easy fixes (${easy})…`) : null,
    unknown ? h("button", { class: "band unchecked-count", title: "A problem in these wouldn't show as a finding: see the list at the top",
        onclick: showUnchecked }, `${unknown} couldn't be checked` + (stake ? ` · highest severity ${stake}` : "")) : null,
    ch ? h("div", { class: "changes" },
      `Since ${new Date(ch.previous * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}:`,
      // h() flattens one level: the chips are spread into their group
      ...[["finding", n => plural(n, "new finding")], ["hygiene", n => `${n} new hygiene`], ["info", n => `${n} new to know about`]]
        .map(([kind, label]) => [newOfKind(fresh, kind), label]).filter(([ids]) => ids.length)
        .map(([ids, label]) => [label(ids.length), ...chips(ids, "new")]),
      resolved.length ? [`${plural(resolved.length, "resolved")}`, ...chips(resolved, "resolved")] : null,
      notChecked.length ? [`${notChecked.length} not checked again`, ...notChecked.map(u => h("span", { class: "chip unchecked",
        title: lastCheckedText(u), onclick: () => reveal(u.id) }, titleOf(u.id)))] : null,
      changed.length ? [`${changed.length} changed severity`, ...changed.map(c => h("span", { class: "chip", title: c.id, onclick: () => reveal(c.id) },
        `${titleOf(c.id)}: severity ${c.from} → ${c.to}`))] : null,
      ...Object.entries(ch.new_items || {}).map(([id, items]) => h("span", { class: "chip new", onclick: () => reveal(id),
        title: items.join("\n") }, `${items.length} new in ${titleOf(id).toLowerCase()}`)),
      !fresh.length && !resolved.length && !notChecked.length && !changed.length && !Object.keys(ch.new_items || {}).length
        ? h("span", {}, "nothing changed") : null) : null);
}

// clicking a severity band shows only that band's findings; clicking it again shows everything
function setBand(b) {
  S.band = S.band === b ? null : b;
  if (S.band) S.show = "findings";
  renderChecks();
}

// the "Couldn't check" section is listed in the Findings and All views
function showUnchecked() {
  if (S.show !== "findings" && S.show !== "all") S.show = "findings";
  S.band = null;
  renderChecks();
  $("#unchecked")?.scrollIntoView({ block: "start" });
}

function setShow(mode) {
  S.show = mode;
  if (mode !== "findings") S.band = null;
  renderChecks();
}

function renderChecks() {
  const list = $("#checks-list");
  const keepScroll = list.scrollTop;
  list.replaceChildren();
  const q = $("#filter").value.trim();
  const showNA = $("#show-na").checked;
  const byCat = new Map(), online = [], unchecked = [];
  const views = [];
  let shownCount = 0, na = 0, findings = 0;
  for (const spec of S.state.catalogue) {
    if (isFeature(spec)) continue;              // set-ups that last are in the Tools panel
    const v = view(spec);
    views.push(v);
    if (v.status === "not_applicable") na++;        // counted for the whole report, as the headline's are
    if (isFinding(v)) findings++;
    if (S.source === "scan" && isOnline(spec)) continue;
    if (S.source === "online" && !isOnline(spec)) continue;
    if (v.status === "not_applicable" && !showNA) continue;
    if (isUnchecked(v)) {
      if ((S.show === "findings" || S.show === "all") && !S.band && matches(spec, q)) { unchecked.push([spec, v]); shownCount++; }
      continue;
    }
    if (!shown(v)) continue;
    if (S.band && !(isFinding(v) && band(v.sev) === S.band)) continue;
    if (!matches(spec, q)) continue;
    if (isOnline(spec)) online.push([spec, v]);
    else {
      if (!byCat.has(spec.category)) byCat.set(spec.category, []);
      byCat.get(spec.category).push([spec, v]);
    }
    shownCount++;
  }
  const weight = (v) => isFinding(v) ? 3 : isHygiene(v) || isInfo(v) ? 2 : isAccepted(v) ? 1 : 0;
  const risk = (v) => v.status === "warn" ? 1 : 0;
  const order = (a, b) => (weight(b[1]) - weight(a[1])) || (b[1].sev - a[1].sev) || (risk(a[1]) - risk(b[1]));
  if (S.state?.in_browser && !S.browserNoted) list.append(browserBanner());
  if (S.state?.app?.old && !S.oldCopyNoted) list.append(oldCopyBanner(S.state.app));
  if (S.report?.undone?.length) list.append(undoneBanner(S.report.undone));
  if (S.report) list.append(summaryBar(views));
  if (unchecked.length) uncheckedSection(list, unchecked);
  // the online tests' results first, in a section of their own
  const ran = S.report?.online?.ran;
  const running = S.job && ["starting", "asking", "running"].includes(S.job.state);
  if (online.length || (S.source === "online" && S.report)) {
    online.sort(order);
    list.append(h("div", { class: "cat-head online" },
      h("span", { class: "title" }, "Online tests"),
      h("span", { class: "muted small" }, running ? "running now" : ran
        ? `ran at ${new Date(ran * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "not run yet"),
      h("span", { class: "muted small" }, `${online.length}`)));
    const block = h("div", { class: "online-block" });
    for (const [spec, v] of online) block.append(checkRow(spec, v));
    if (!online.length) block.append(h("div", { class: "empty" }, running ? "Results appear here as each test finishes."
      : "No online test results to show. Start them with Online tests…"));
    list.append(block);
    if (byCat.size) list.append(h("div", { class: "section-gap" }, h("span", {}, "Scan results")));
  }
  for (const [cat, rows] of byCat) {
    rows.sort(order);
    list.append(h("div", { class: "cat-head" },
      h("span", { class: "title" }, S.state.categories[cat] || cat),
      h("span", { class: "muted small" }, `${rows.length}`)));
    for (const [spec, v] of rows) list.append(checkRow(spec, v));
  }
  if (!shownCount && S.source !== "online") list.append(h("div", { class: "empty" }, q ? "No checks match the filter."
    : S.band ? `No ${BAND_LABEL[S.band]} findings left.` : S.show === "findings" ? "No findings to act on."
    : S.show === "accepted" ? "Nothing accepted. A finding's details have an “Accept this risk” control."
    : "Nothing to show."));

  const total = S.state.catalogue.filter(sp => !isFeature(sp)).length;
  const parts = [`${total} in the catalogue`];
  if (S.report) {
    parts.push(`${na} not applicable here`);
    parts.push(plural(findings, "finding"));
  }
  $("#checks-count").textContent = parts.join(" · ");
  document.querySelectorAll("#source button").forEach(b => b.classList.toggle("on", b.dataset.source === S.source));
  document.querySelectorAll("#show button").forEach(b => b.classList.toggle("on", b.dataset.show === S.show));
  list.scrollTop = keepScroll;
}

// at the top: what couldn't be checked, by the severity a problem would have, so nothing
// serious hides behind "unknown"; those that only need administrator access get one button
function uncheckedSection(list, rows) {
  rows.sort((a, b) => b[1].sev - a[1].sev);
  const admin = rows.filter(([, v]) => v.needsAdmin).length;
  list.append(h("div", { class: "cat-head unchecked", id: "unchecked" },
    h("span", { class: "title" }, "Couldn't check"),
    h("span", { class: "muted small" }, `${rows.length}`)));
  list.append(h("div", { class: "unchecked-why small" },
    h("span", {}, "A problem in any of these wouldn't show as a finding. The number is the severity it would have."),
    admin && !S.report?.privileged ? [h("span", {}, " " + (admin === rows.length
        ? (admin > 1 ? "They all need" : "It needs") : `${admin} of them ${admin > 1 ? "need" : "needs"}`)
        + " administrator access to check."),
      h("button", { class: "small", onclick: () => { $("#admin").checked = true; $("#scan-btn").click(); } },
        "Scan with administrator access")] : null));
  for (const [spec, v] of rows) list.append(checkRow(spec, v));
}

function setSource(src) {
  S.source = src;
  renderChecks();
}

function checkRow(spec, v) {
  const open = S.open.has(spec.id);
  const changed = S.report && v.sev !== spec.severity;
  const el = h("div", { class: `citem band-${v.found ? band(v.sev) : v.status === "not_applicable" ? "na" : "none"}`
    + `${v.status === "not_applicable" ? " dim" : ""}${isAccepted(v) ? " accepted" : ""}${v.status === "pass" ? " passed" : ""}`,
    id: `c-${spec.id}` });
  const unc = v.uncertain?.length ? uncertainText(spec, v) : null;
  el.append(h("div", { class: "row", onclick: () => toggle(spec.id) },
    h("div", { class: "sevcol" },
      h("span", { class: `status st-${v.status}`, title: STATUS_LABEL[v.status] || v.status }, STATUS_SHORT[v.status] || v.status),
      rowPill(v, (changed ? `Severity ${v.sev} on this machine (base ${spec.severity})` : `Severity ${v.sev}`)
        + (v.result?.as_warning ? `: a risk, rated ${spec.warn_lower} below the problem it could become` : "")),
      changed ? h("span", { class: "base" }, `base ${spec.severity}`) : null),
    // a pass leads with what was found ("/boot is on encrypted storage."), not the problem's name
    v.status === "pass" && v.summary ? h("div", { class: "titles" },
      h("div", { class: "t" }, v.summary),
      h("div", { class: "sub" }, spec.title, isDev() ? [" · ", h("span", { class: "id" }, spec.id)] : null),
      unc ? h("div", { class: "uncertain" }, unc) : null)
    : h("div", { class: "titles" },
      h("div", { class: "t" }, spec.title),
      isDev() ? h("div", { class: "id" }, spec.id) : null,
      v.summary ? h("div", { class: "sum" }, v.summary) : null,
      lastChecked(spec.id) ? h("div", { class: "sum was-problem" }, lastCheckedText(lastChecked(spec.id))) : null,
      unc ? h("div", { class: "uncertain" }, unc) : null),
    h("div", { class: "badges" },
      v.fixable ? h("button", { class: "small primary", title: hasGuide(spec) ? "Step by step, each change confirmed separately" : "Shows exactly what changes first",
        onclick: (e) => { e.stopPropagation(); hasGuide(spec) ? openGuide(spec) : openFix(spec); } },
        spec.tier === "feature" ? "Set up…" : spec.tier === "guided" ? "Guide…" : (spec.kind === "hygiene" ? "Clean…" : "Fix…")) : null,
      v.result?.how_to ? h("button", { class: "small", title: "What to do, step by step, for this machine: the app doesn't make this change itself",
        onclick: (e) => { e.stopPropagation(); openGuide(spec); } }, "How to…") : null,
      isEasy(v) ? h("button", { class: "badge easy", title: "An Easy fix: " + (spec.easy.cost || "it costs you nothing worth mentioning")
        + " Easy fixes… applies it with the others.", onclick: (e) => { e.stopPropagation(); openEasy(); } }, "easy") : null,
      isAccepted(v) ? [h("span", { class: "badge accepted", title: acceptedRecord(spec.id)?.note || "You accepted this risk" }, "accepted"),
        h("button", { class: "small ghost unaccept", title: "Show it and count it as a finding again",
          onclick: (e) => { e.stopPropagation(); setAccepted(spec, false); } }, "Un-accept")] : null,
      v.found && v.resurfaced ? h("span", { class: "badge resurfaced", title: whyShownAgain(acceptedRecord(spec.id), v.result) },
        "shown again") : null,
      (S.report?.undone || []).some(u => u.check_id === spec.id)
        ? h("span", { class: "badge undone", title: "You fixed this, and it has been undone since: see the top of the page" },
          "fix undone") : null,
      v.partial && v.status !== "unknown" ? h("span", { class: "badge partial", title: "Detection was incomplete" }, "partial") : null,
      spec.kind !== "finding" ? h("span", { class: `badge kind-${spec.kind}`, title: KIND_TITLE[spec.kind] }, spec.kind) : null,
      h("span", { class: `badge scope-${spec.scope}`, title: SCOPE_TITLE[spec.scope] },
        spec.scope === "system" ? "root" : spec.scope),
      v.result?.no_fix ? h("span", { class: "badge tier-none", title: `Not on this machine: ${v.result.no_fix}` }, "no fix here")
        : h("span", { class: `badge tier-${spec.tier}`, title: TIER_TITLE[spec.tier] }, spec.tier)),
  ));
  if (open) el.append(details(spec, v));
  return el;
}

// Accepting a finding hides it (it is listed only under Accepted) and stops counting and notifying
// about it, until its severity rises. Undone from the row's Un-accept button, its details or the toast.
async function setAccepted(spec, accept, note = "") {
  try {
    const r = await api("POST", "/api/accept", { check_id: spec.id, accept, note });
    S.state.accepted = r.accepted;
    if (S.report && r.undone) S.report.undone = r.undone;
    renderChecks();
    if (accept) {
      toast(`${spec.title}: accepted and hidden. It is listed under Accepted, and comes back by itself if its severity rises.`, "ok", 10000,
        { label: "Undo", onclick: () => setAccepted(spec, false) });
    }
  } catch (e) { toast(e.message, "error"); }
}

function acceptRow(spec, v) {
  const info = acceptedRecord(spec.id);
  if (v.accepted && v.resurfaced) {
    return h("div", { class: "accept-row" },
      h("div", { class: "warnbox" }, whyShownAgain(info, v.result) + (info.note ? ` Your reason then: ${info.note}` : "")),
      h("div", { class: "buttons" },
        h("button", { class: "small", title: `Hide it again; it comes back if its severity rises above ${v.sev}`,
          onclick: () => setAccepted(spec, true, info.note || "") }, `Accept it at severity ${v.sev}`),
        h("button", { class: "small ghost", title: "Keep it as a finding", onclick: () => setAccepted(spec, false) }, "Un-accept")));
  }
  if (v.accepted) {
    const when = info?.when ? ` on ${new Date(info.when * 1000).toLocaleDateString([], { dateStyle: "medium" })}` : "";
    const at = Number.isInteger(info?.severity) ? ` at severity ${info.severity}` : "";
    return h("div", { class: "accept-row" },
      h("span", { class: "small" }, `You accepted this risk${when}${at}${info?.note ? `: ${info.note}` : "."}`
        + (at ? ` It stays hidden unless its severity rises above ${info.severity}.` : "")),
      h("button", { class: "small", title: "Show it and count it as a finding again", onclick: () => setAccepted(spec, false) }, "Un-accept"));
  }
  const row = h("div", { class: "accept-row" });
  const closed = () => fill(row,
    h("span", { class: "muted small" }, v.fixable ? "Not going to fix this?" : "Decided to live with this?"),
    h("button", { class: "small ghost", onclick: open }, "Accept the risk…"));
  const open = () => {
    const note = h("input", { type: "text", maxlength: 300, placeholder: "e.g. test machine, needed for work", autocomplete: "off",
      spellcheck: "false" });
    fill(row,
      h("p", { class: "small" }, "An accepted finding is hidden: it is listed only under Accepted, and no longer counted "
        + `in the report or in the notifications of a scheduled scan. If its severity rises above ${v.sev} (the machine `
        + "changes, or the app rates it higher), it is shown again with the reason. You can un-accept it at any time."),
      h("label", { class: "small note" }, "Reason, for your own records (optional; kept with the report, and in its exports, redacted like the rest)", note),
      h("div", { class: "buttons" },
        h("button", { class: "small primary", onclick: () => setAccepted(spec, true, note.value) }, "Accept this risk"),
        h("button", { class: "small ghost", onclick: closed }, "Cancel")));
    note.focus();
  };
  closed();
  return row;
}

function details(spec, v) {
  const d = h("div", { class: "details" });
  const dev = S.state.dev;
  if (v.error) d.append(h("div", { class: "warnbox" }, v.error));
  const fresh = newItems(spec.id);
  if (fresh.length) d.append(noteBox({ kind: "risk", title: `New since the last scan (${fresh.length})`, related: [],
    text: `${fresh.join(", ")}. If you didn't add ${fresh.length > 1 ? "these" : "this"} yourself, find out what `
      + `${fresh.length > 1 ? "they are" : "it is"} before you leave ${fresh.length > 1 ? "them" : "it"} running.` }));
  if (v.evidence?.length) d.append(h("div", {}, h("h4", {}, "Evidence"), h("ul", { class: "evidence" },
    v.evidence.map(e => evidenceLine(e, new Set(fresh))))));
  for (const n of v.notes || []) d.append(noteBox(n));
  if (spec.why) d.append(h("div", {}, h("h4", {}, "Why it matters"), h("p", {}, spec.why)));
  if (spec.remedy || v.result?.no_fix) d.append(h("div", {}, h("h4", {}, "What to do"), spec.remedy ? h("p", {}, spec.remedy) : null,
    v.result?.no_fix ? h("p", { class: "no-fix" }, h("b", {}, "The app can't do this for you here: "), v.result.no_fix) : null));
  if (isEasy(v)) d.append(h("div", { class: "easy-note" }, h("h4", {}, "An Easy fix"),
    h("p", {}, spec.easy.cost ? `What it costs you: ${spec.easy.cost}` : "It costs you nothing worth mentioning.",
      " ", h("button", { class: "small", onclick: () => openEasy() }, "Easy fixes…"))));
  if (spec.meanwhile && v.found) d.append(meanwhileBox(spec));
  if (spec.modifiers.length) {
    const states = v.modifiers || [];
    d.append(h("div", {}, h("h4", {}, `Severity ${spec.severity}, adjusted by context (the last match wins)`),
      h("ul", { class: "mods" }, spec.modifiers.map((m, i) => {
        const s = states[i];
        const cls = s === true ? "hit" : s === false ? "miss" : S.report ? "unknown" : "";
        const mark = s === true ? "✓ " : s === false ? "" : S.report ? "? " : "";
        return h("li", { class: cls }, mark, dev ? h("code", {}, m.when) : (m.when_text || m.when),
          ` → ${m.severity}${m.severity === 0 ? " (not applicable)" : ""}`);
      }))));
  }
  if (v.result?.as_warning && v.found) d.append(h("div", {}, h("h4", {}, "A risk, not a confirmed problem"),
    h("p", {}, `What was found could lead to the problem, or is only part of it, so it is rated ${spec.warn_lower} lower `
      + `than the problem itself would be here (never below 1). Its severity is ${v.sev}.`)));
  if (spec.applies_to.length) d.append(h("div", {}, h("h4", {}, "Applies to"), h("p", {}, spec.applies_to.join(", "))));
  if (spec.contacts?.length) d.append(h("div", {}, h("h4", {}, "Contacts (when you run it)"),
    h("ul", {}, spec.contacts.map(c => h("li", {}, c)))));
  if (spec.related.length) {
    d.append(h("div", {}, h("h4", {}, "Related"), h("div", { class: "related" }, relatedChips(spec.related))));
  }
  if (v.found && spec.kind === "finding") d.append(acceptRow(spec, v));
  if (dev) {
    // developer notes: the catalogue's detection hints (not what the code does) and open verifications
    d.append(h("div", { class: "dev" }, h("h4", {}, "Detection hints (catalogue; developer view)"),
      h("ul", {}, spec.detect.map(x => h("li", {}, h("code", {}, x))))));
    d.append(h("div", { class: "dev" }, h("h4", {}, "How the fix works (catalogue; developer view)"), h("p", {}, spec.fix)));
    if (spec.verify) d.append(h("div", { class: "warnbox" }, h("b", {}, "Not yet confirmed on a real system: "), spec.verify));
    if (v.ms !== undefined) d.append(h("div", { class: "muted small dev" }, `Took ${v.ms} ms`));
  }
  return d;
}

function toggle(id) {
  if (S.open.has(id)) S.open.delete(id); else S.open.add(id);
  renderChecks();
}

function reveal(id) {
  const spec = S.state.catalogue.find(s => s.id === id);
  if (spec && isFeature(spec)) { openTools(); return; }
  S.open.add(id);
  const v = view(spec);
  if (v.status === "not_applicable") $("#show-na").checked = true;
  if (!shown(v)) S.show = isAccepted(v) ? "accepted" : "all";
  if (S.source !== "all" && (S.source === "online") !== isOnline(spec)) S.source = "all";
  S.band = null;
  $("#filter").value = "";
  renderChecks();
  const el = document.getElementById(`c-${id}`);
  if (el) {
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    el.classList.add("flash");
  }
}

// ------------------------------------------------------------------ modals (DAToolkit's)

// Every dialog of the page is drawn here, so that it is one for the keyboard and for a screen reader too: it is
// announced as a dialog named by its title (role, aria-modal, aria-labelledby); the focus moves into it and stays
// there (Tab and Shift+Tab go round inside it, and what is behind is inert: not reachable, not read out); Escape
// closes the one on top, as clicking beside it does, unless it is sticky; and closing it puts the focus back
// where it was.
const MODALS = [];                 // the open dialogs, the one on top last
let modalSeq = 0, modalWatch = null;
const FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), "
  + "textarea:not([disabled]), summary, [tabindex]:not([tabindex='-1'])";

function modalTop() {
  while (MODALS.length && !MODALS.at(-1).overlay.isConnected) MODALS.pop();      // one removed without its close
  return MODALS.at(-1) || null;
}

function modalFocusables(box) {
  return [...box.querySelectorAll(FOCUSABLE)].filter(el => !el.closest(".hidden, [hidden], [inert]")
    && !(el.tagName === "SUMMARY" ? el.parentElement.parentElement?.closest("details:not([open])")
                                  : el.closest("details:not([open])")));
}

// what is behind the dialog on top can't be reached or read out; the toasts stay (they say what just happened)
function modalBackground() {
  const top = modalTop();
  for (const el of document.body.children) {
    if (el.id !== "modal-root" && el.id !== "toasts" && el.tagName !== "SCRIPT") el.toggleAttribute("inert", !!top);
  }
  for (const m of MODALS) m.overlay.toggleAttribute("inert", m !== top);
}

// By its code and number as well as its name: WebKitGTK names Shift+Tab "Unidentified" (seen on CachyOS, KDE Plasma
// 6.7 on Wayland), and a handler that went by the name let the focus leave the dialog backwards.
const keyIs = (e, name, number) => e.key === name || e.code === name || e.keyCode === number;

document.addEventListener("keydown", (e) => {
  const top = modalTop();
  if (!top) return;
  if (keyIs(e, "Escape", 27)) {
    // a field's own use of Escape comes first (WebKit clears a search field with it)
    if (!top.sticky && !e.defaultPrevented) { e.preventDefault(); top.close(); }
    return;
  }
  if (!keyIs(e, "Tab", 9)) return;
  const items = modalFocusables(top.box);
  const first = items[0], last = items.at(-1), at = document.activeElement;
  if (!items.length) { e.preventDefault(); top.box.focus(); }
  else if (!top.box.contains(at) || at === top.box) { e.preventDefault(); (e.shiftKey ? last : first).focus(); }
  else if (e.shiftKey && at === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && at === last) { e.preventDefault(); first.focus(); }
});

function modal({ title, body, buttons = [], wide = false, cls = "", sticky = false, foot = null }) {
  const root = $("#modal-root");
  const heading = h("h2", { id: `modal-title-${++modalSeq}` }, title);
  const box = h("div", { class: `modal${wide ? " wide" : ""}${cls ? " " + cls : ""}`, role: "dialog", "aria-modal": "true",
                         "aria-labelledby": heading.id, tabindex: "-1" }, heading, h("div", { class: "content" }, body));
  const bar = h("div", { class: "buttons" });
  const opener = document.activeElement;
  const close = () => {
    if (!overlay.isConnected) return;
    overlay.remove();
    const i = MODALS.indexOf(entry);
    if (i >= 0) MODALS.splice(i, 1);
    modalBackground();
    const below = modalTop();
    // back to where the focus was: the button that opened it, else the dialog now on top
    if (opener && opener !== document.body && opener.isConnected && !opener.closest("[inert]")) opener.focus();
    else if (below) below.box.focus();
  };
  for (const b of buttons) {
    const el = h("button", { class: b.kind || "", disabled: b.disabled }, b.label);
    el.addEventListener("click", () => b.onclick ? b.onclick(close, el) : close());
    bar.append(el);
    if (b.ref) b.ref(el);
  }
  if (foot) bar.prepend(foot);
  box.append(bar);
  // sticky: only its own buttons close it (the welcome warning must be read, not clicked away)
  const overlay = h("div", { class: "overlay", onclick: (e) => { if (e.target === overlay && !sticky) close(); } }, box);
  const entry = { overlay, box, close, sticky };
  if (!modalWatch) {                 // a dialog taken off the page any other way must not leave the page behind it inert
    modalWatch = new MutationObserver(modalBackground);
    modalWatch.observe(root, { childList: true });
  }
  root.append(overlay);
  MODALS.push(entry);
  modalBackground();
  box.focus();                       // on the dialog itself: its title is read out, and Tab goes to its first control
  return { close, box };
}

// ------------------------------------------------------------------ after a fix or revert

// the server re-ran the context and every check whose severity depends on what changed
function takeRecheck(r) {
  if (!S.report || !r) return;
  if (r.result) S.report.results[r.result.id] = r.result;
  if (r.rechecked) Object.assign(S.report.results, r.rechecked);
  if (r.context) S.report.context = r.context;
  if (r.undone) S.report.undone = r.undone;
  renderContext();
  renderChecks();
}

// ------------------------------------------------------------------ fixes

const STEP_TAG = { true: ["undo", "can be undone"], false: ["fx", "side effect"] };

function stepLine(st) {
  const [cls, label] = st.irreversible ? ["gone", "can't be undone"] : STEP_TAG[st.reversible];
  return h("li", { class: `step ${cls}` }, h("span", { class: "tag" }, label),
    st.needs_root ? h("span", { class: "tag root", title: "Done by the administrator helper" }, "root") : null,
    h("div", { class: "stepbody" }, h("code", {}, st.text),
      st.commands?.length ? h("div", { class: "stepmore" }, h("span", { class: "muted small" },
        st.needs_root ? "Also runs, as root:" : "Also runs:"), st.commands.map(c => h("code", { class: "cmdline" }, c))) : null,
      st.lines?.length ? changedLines(st.lines) : null));
}

// the lines a step writes into a file: "+ added", "- removed"
function changedLines(lines) {
  return h("pre", { class: "changed" }, lines.map(l => h("span", { class: l.startsWith("+ ") ? "add" : l.startsWith("- ")
    ? "del" : "more" }, l + "\n")));
}

// what a step in History did, exactly: the commands it ran, the lines it wrote, the files the helper wrote,
// how to undo it by hand, and what putting it back ran
function historyStepDetail(st, open = false) {
  const parts = [
    st.commands?.length ? [h("div", { class: "muted small" }, st.as_root ? "Ran, as root:" : "Ran:"), commandBlock(st.commands)] : null,
    st.files?.length ? [h("div", { class: "muted small" }, "Files written, as root:"), h("ul", { class: "small files" },
      st.files.map(f => h("li", {}, h("code", {}, f))))] : null,
    st.dirs?.length ? [h("div", { class: "muted small" }, "Folders it made (reverting removes each while it holds nothing "
      + "else):"), h("ul", { class: "small files" }, st.dirs.map(f => h("li", {}, h("code", {}, f))))] : null,
    st.lines?.length ? [h("div", { class: "muted small" }, "Lines written:"), changedLines(st.lines)] : null,
    st.undo ? [h("div", { class: "muted small" }, "To undo it by hand:"), commandBlock([st.undo])] : null,
    st.revert_ran?.length ? [h("div", { class: "muted small" }, st.as_root ? "Putting it back ran, as root:" : "Putting it back did:"),
      commandBlock(st.revert_ran)] : null,
  ].filter(Boolean);
  return parts.length ? h("details", { class: "stepdetail", open }, h("summary", { class: "small" }, "Exactly what it did"), ...parts) : null;
}

// a backup kept only for a while (known_hosts' plain copy, the very list its fix hides): until when, and a button that
// deletes it now; once gone, that the step can't be put back
function backupLine(en, st, rerender) {
  const day = (t) => new Date(t * 1000).toLocaleDateString([], { dateStyle: "medium" });
  if (st.backup_dropped && !st.reverted) {
    return h("div", { class: "small muted" }, `Its plain copy was deleted ${day(st.backup_dropped)}: this step can't be put back.`);
  }
  if (!st.backup_until) return null;
  const drop = async (e) => {
    const btn = e.target;
    if (!await confirmModal("Delete the plain copy now?", h("p", {}, "This step can then no longer be reverted: the "
      + "names it hid can't be turned back."), "Delete it")) return;
    btn.disabled = true;
    try {
      await api("POST", `/api/undo/${en.id}/drop-backup`, {});
      if (rerender) rerender((await api("GET", "/api/undo")).entries);
      else btn.closest(".backupline")?.replaceChildren("The plain copy was deleted: this step can't be put back.");
    } catch (err) { toast(err.message, "error"); btn.disabled = false; }
  };
  return h("div", { class: "small backupline" }, `A plain copy of the file is kept until ${day(st.backup_until)}, so this can `
    + "be reverted, then deleted: it is the very list this step hides. ",
    h("button", { class: "small ghost", onclick: drop }, "Delete it now"));
}

// the steps of a History entry, each with what it did (open: the details shown at once)
function entrySteps(en, open = false, rerender = null) {
  return h("ul", { class: "steps" }, en.steps.map(st => h("li", { class: `step ${st.reverted ? "reverted" : st.reversible ? "undo" : "gone"}` },
    h("span", { class: "tag" }, st.reverted ? "reverted" : st.reversible ? "can be undone" : "permanent"),
    h("div", { class: "stepbody" }, h("span", { class: "steptext" }, st.text), backupLine(en, st, rerender),
      historyStepDetail(st, open)))));
}

// what a fix did, shown right after it was applied: the History entry as made, every step with the commands it
// ran and the lines it wrote, so what happened is seen now, not only found in History later. A failed attempt
// that had changed something shows what was put back.
function doneDialog(entries, failed = null) {
  entries = entries.filter(Boolean);
  if (!entries.length) return;
  const one = entries.length === 1;
  modal({ title: failed ? `Failed: ${entries[0].title}` : one ? `Done: ${entries[0].title}` : `Done: ${plural(entries.length, "fix", "fixes")} applied`,
    wide: true, body: [
      failed ? [h("div", { class: "warnbox bad" }, failed),
        h("p", { class: "small" }, entries[0].failed_step ? ["It failed at: ", h("code", {}, entries[0].failed_step), ". "] : null,
          "What had been changed before that was put back, as listed below; the attempt is kept in History.")] : null,
      failed ? null : h("p", { class: "small muted" }, "This is exactly what it did. It is kept in History, with "
        + (entries.some(en => en.steps.some(st => st.reversible)) ? "a Revert button" : "what it did") + "."),
      entries.map(en => h("div", { class: "entry" },
        one ? null : h("div", { class: "ehead" }, h("b", {}, en.title),
          h("span", { class: "muted small" }, checkTitle(en.check_id)),
          h("span", { class: `badge state-${en.state.replace(" ", "-")}` }, en.state)),
        en.via_text ? h("div", { class: "small muted" }, en.via_text) : null,
        en.state === "failed" && !failed ? h("div", { class: "small errmsg" }, `Failed: ${en.error}`
          + (en.failed_step ? ` (at: ${en.failed_step})` : "") + ". What had run was put back, as listed.") : null,
        entrySteps(en, true)))].flat(3),
    buttons: [{ label: "Open History", onclick: (close) => { close(); openHistory(); } }, { label: "Close", kind: "primary" }] });
}

const ROOT_NOTE = "Asks for administrator access (your password) when applied, unless it is already granted.";

function planBody(plan, confirm) {
  const irreversible = plan.steps.some(st => st.irreversible);
  const nothing = !plan.steps.length;
  return [
    plan.blockers.length ? h("div", { class: "warnbox bad" }, plan.blockers.join(" ")) : null,
    nothing && !plan.blockers.length ? h("p", {}, "Nothing needs changing any more.") : null,
    plan.steps.length ? h("ul", { class: "steps" }, plan.steps.map(stepLine)) : null,
    plan.side_effects.length ? h("div", {}, h("h4", {}, "Worth knowing"), h("ul", { class: "small" }, plan.side_effects.map(x => h("li", {}, x)))) : null,
    irreversible && confirm ? h("label", { class: "check confirm" }, confirm,
      "I understand that what the items marked “can't be undone” delete, or clear from a file, is gone for good.") : null,
    plan.steps.some(st => st.reversible && st.kind !== "command")
      ? h("p", { class: "muted small" }, "Settings changes can be reverted later from History.") : null,
    plan.needs_root && !S.adminActive ? h("p", { class: "muted small" }, ROOT_NOTE) : null,
  ];
}

// One option of a check's guide (by its key), confirmed with its dry run and applied like any fix (History reverts it):
// for a panel that offers the one change it needs, such as the browser's keeping file search out of ~/TempBrowser.
async function openGuideOption(id, key, after) {
  let opt;
  try {
    const data = await api("POST", `/api/fix/${encodeURIComponent(id)}/plan`);
    opt = (data.guide?.steps || []).flatMap(st => st.options || []).find(o => o.key === key);
  } catch (e) { toast(e.message, "error"); return; }
  if (!opt) { toast("Nothing needs changing any more.", "ok"); await after?.(); return; }
  const plan = opt.plan;
  modal({ title: opt.label, wide: true,
    body: [h("p", { class: "muted small" }, "Nothing has been changed yet. This is exactly what it will do:"),
           opt.detail ? h("p", { class: "small" }, opt.detail) : null, ...planBody(plan, null)],
    buttons: [{ label: "Cancel" }, { label: "Apply", kind: "primary", disabled: !plan.steps.length || plan.blockers.length > 0,
      onclick: async (close, el) => {
        el.disabled = true; el.textContent = "Applying…";
        try {
          const r = await applyPlan(plan, false);
          close();
          toast(`Done: ${opt.label}. Revert it from History if you need to.`, "ok");
          doneDialog([r.entry]);
          await after?.();
        } catch (e) {
          el.textContent = "Failed"; toast(`It failed and was rolled back: ${e.message}`, "error", 10000);
          if (e.data?.entry) doneDialog([e.data.entry], e.message);
        }
      } }] });
}

async function openFix(spec) {
  let data;
  try {
    data = await api("POST", `/api/fix/${encodeURIComponent(spec.id)}/plan`);
  } catch (e) {
    toast(e.message, "error");
    return;
  }
  const plan = data.plan;
  if (data.result) { S.report.results[spec.id] = data.result; renderChecks(); }
  const irreversible = plan.steps.some(st => st.irreversible);
  const nothing = !plan.steps.length;
  let applyBtn;
  const confirm = irreversible ? h("input", { type: "checkbox" }) : null;
  const body = [h("p", { class: "muted small" }, "Nothing has been changed yet. This is exactly what the fix will do:"),
                ...planBody(plan, confirm)];
  const m = modal({
    title: plan.title, wide: true, body,
    buttons: [
      { label: "Cancel" },
      { label: irreversible ? "Apply and delete" : "Apply", kind: irreversible ? "danger" : "primary",
        disabled: nothing || plan.blockers.length || irreversible, ref: (el) => { applyBtn = el; },
        onclick: (close, el) => applyFix(plan, !!confirm?.checked, close, el) },
    ],
  });
  if (confirm) confirm.addEventListener("change", () => { applyBtn.disabled = !confirm.checked; });
  return m;
}

async function applyPlan(plan, confirmed) {
  if (plan.needs_root && !S.adminActive) setStatus("Waiting for administrator authorization…", "busy");
  try {
    const r = await api("POST", "/api/fix/apply", { plan_id: plan.id, confirm_irreversible: confirmed });
    takeRecheck(r);
    if (plan.needs_root) S.adminActive = true;
    setStatus(`Applied: ${plan.title}.`, "done");
    return r;
  } catch (e) {
    takeRecheck(e.data);
    throw e;
  } finally {
    renderTop();
  }
}

async function applyFix(plan, confirmed, close, btn) {
  btn.disabled = true;
  btn.textContent = "Applying…";
  try {
    const r = await applyPlan(plan, confirmed);
    close();
    toast(`Done: ${plan.title}.` + (plan.steps.some(s => s.reversible && s.kind !== "command") ? " Revert it from History if you need to." : ""), "ok");
    renderChecks();
    doneDialog([r.entry]);
  } catch (e) {
    btn.textContent = "Failed";
    toast(e.declined ? e.message : `The fix failed and was rolled back: ${e.message}`, "error", 10000);
    setStatus(e.message, "failed");
    if (e.data?.entry) doneDialog([e.data.entry], e.message);
  }
}

// ------------------------------------------------------------------ Easy fixes
// The fixes that cost the user nothing, or next to nothing (the catalogue's `easy`), for problems found
// on this machine: listed together with what each costs, chosen with a tick, applied after one look at
// exactly what they do. Each is its own fix in History. Without disk encryption, the dialog starts with
// what is worth doing until it is encrypted (enc.fde_missing's `meanwhile`).

// what to do until a check the app can't fix is fixed: each check with its state and its own button
function meanwhileBox(spec, close = null) {
  const rows = spec.meanwhile.checks.map(id => {
    const sp = S.state.catalogue.find(s => s.id === id);
    if (!sp) return null;
    const r = S.report?.results?.[id];
    const st = travelState(r, id);
    return h("li", { class: `trow ${st}` },
      h("span", { class: `badge ${TRAVEL_STATE[st][0]}` }, TRAVEL_STATE[st][1]),
      h("div", { class: "titles" }, h("b", {}, sp.title), r?.summary ? h("div", { class: "small muted" }, r.summary) : null,
        st === "accepted" ? h("div", { class: "small muted" }, ACCEPTED_HERE) : null),
      h("div", { class: "orow" }, st === "todo" ? fixButtons(sp, r) : null,
        h("button", { class: "small ghost", onclick: () => { close?.(); reveal(id); } }, "In the list")));
  });
  return h("div", { class: "meanwhile" },
    h("h4", {}, "Until then"),
    h("p", {}, spec.meanwhile.text),
    h("ul", { class: "tlist" }, rows));
}

async function openEasy() {
  const body = h("div", { class: "easy" });
  let data, applyBtn, m;
  const picked = new Set();
  const confirm = h("input", { type: "checkbox" });
  const gone = h("ul", { class: "small" });                // what the chosen fixes delete, each named
  const first = S.state.catalogue.find(s => s.meanwhile && isFinding(view(s)));
  const chosen = () => data.items.filter(it => picked.has(it.check_id));
  const update = () => {
    if (!applyBtn) return;                       // the dialog isn't open yet
    const sel = chosen();
    const deletes = sel.flatMap(it => it.plans.flatMap(p => p.steps.filter(st => st.irreversible)
      .map(st => h("li", {}, h("b", {}, `${it.title}: `), st.text))));
    fill(gone, deletes);
    confirm.closest("label").classList.toggle("hidden", !deletes.length);
    if (!deletes.length) confirm.checked = false;
    applyBtn.disabled = !sel.length || (deletes.length > 0 && !confirm.checked);
    applyBtn.textContent = sel.length ? `Apply ${plural(sel.length, "fix", "fixes")}` : "Apply";
    applyBtn.className = deletes.length ? "danger" : "primary";
  };
  const item = (it) => {
    const box = h("input", { type: "checkbox", checked: picked.has(it.check_id), disabled: it.blockers.length > 0,
      onchange: () => { box.checked ? picked.add(it.check_id) : picked.delete(it.check_id); update(); } });
    return h("li", { class: `eitem${it.blockers.length ? " blocked" : ""}` },
      h("label", { class: "check" }, box, h("b", {}, it.title)),
      h("ul", { class: "small does" }, it.plans.map(p => h("li", {}, p.title))),
      it.covered_by ? h("p", { class: "small muted" }, `The same change as “${it.covered_by}”: applying that one deals with this too.`) : null,
      it.cost ? h("div", { class: "small cost" }, h("span", { class: "muted" }, "What it costs you: "), it.cost) : null,
      it.blockers.length ? h("div", { class: "warnbox bad small" }, it.blockers.join(" ")) : null,
      h("div", { class: "tags" },
        it.needs_root ? h("span", { class: "tag root", title: "Done by the administrator helper" }, "root") : null,
        it.irreversible ? h("span", { class: "tag gone", title: "Deletes files: can't be undone" }, "deletes files") : null,
        it.kind === "hygiene" ? h("span", { class: `badge kind-hygiene`, title: KIND_TITLE.hygiene }, "hygiene") : null),
      h("details", { class: "small" }, h("summary", {}, "Exactly what it does"),
        it.plans.flatMap(p => [h("ul", { class: "steps" }, p.steps.map(stepLine)),
          p.side_effects.length ? h("ul", { class: "small" }, p.side_effects.map(x => h("li", {}, x))) : null])));
  };
  const render = () => {
    const blocked = data.items.filter(it => it.blockers.length).length;
    fill(body,
      // a problem no Easy fix reaches comes first, with what is worth doing until it is fixed
      first ? h("div", { class: "warnbox first" }, h("div", { class: "orow" }, h("b", {}, first.title),
          h("span", { class: "spacer" }), fixButtons(first, view(first).result)),
        meanwhileBox(first, () => m?.close())) : null,
      h("p", {}, "These fixes cost you nothing, or next to nothing: what little they do cost is said beside each. Untick "
        + "any you don't want. Each one is applied on its own and can be reverted from History."),
      data.items.length ? h("ul", { class: "elist" }, data.items.map(item))
        : h("div", { class: "empty" }, "No Easy fixes are left to apply here."),
      blocked ? h("p", { class: "small muted" }, "Greyed out: can't be applied now, for the reason given. "
        + "Check again once it is dealt with.") : null,
      h("label", { class: "check confirm easy-confirm hidden" }, confirm,
        h("div", {}, "Some of the fixes you chose delete files, or clear history from a file, first. I understand that what "
          + "they delete or clear is gone for good:",
          gone)),
      data.items.some(it => it.needs_root) && !S.adminActive ? h("p", { class: "muted small" },
        "Those marked root ask for administrator access (your password) once, when applied.") : null);
    update();
  };
  const load = async () => {
    data = await api("POST", "/api/easy/plan");
    picked.clear();
    for (const it of data.items) if (!it.blockers.length) picked.add(it.check_id);
    render();
  };
  confirm.addEventListener("change", () => update());
  const apply = async (close, btn) => {
    const ids = chosen().flatMap(it => it.plans.map(p => p.id));
    btn.disabled = true;
    btn.textContent = "Applying…";
    if (chosen().some(it => it.needs_root) && !S.adminActive) setStatus("Waiting for administrator authorization…", "busy");
    try {
      const r = await api("POST", "/api/easy/apply", { plan_ids: ids, confirm_irreversible: confirm.checked });
      done(r, close);
    } catch (e) {
      if (e.data?.results) { done(e.data, close); return; }
      toast(e.message, "error", 10000);
      setStatus(e.message, "failed");
      btn.textContent = "Failed";
    }
  };
  const done = (r, close) => {
    takeRecheck(r);
    S.adminActive = !!r.admin_active;
    renderTop();
    const ok = r.results.filter(x => x.ok), bad = r.results.filter(x => !x.ok);
    close();
    setStatus(`Easy fixes: ${plural(ok.length, "fix", "fixes")} applied` + (bad.length ? `, ${bad.length} not` : "") + ".",
      bad.length ? "failed" : "done");
    if (bad.length) {
      modal({ title: "Some Easy fixes weren't applied", body: [
        ok.length ? h("p", {}, `${plural(ok.length, "fix was", "fixes were")} applied; revert any of them from History.`) : null,
        h("ul", {}, bad.map(x => h("li", {}, h("b", {}, x.title), ": ", x.error))),
        h("p", { class: "small muted" }, "A fix that failed was rolled back; nothing of it was left half done. "
          + "One that had changed something first is in History, with what was put back.")],
        buttons: [{ label: "What was done", onclick: (close) => { close(); doneDialog(r.results.map(x => x.entry)); } },
                  { label: "Close", kind: "primary" }] });
    } else {
      toast(`Done: ${plural(ok.length, "Easy fix", "Easy fixes")} applied. Revert any of them from History if you need to.`, "ok", 10000);
      doneDialog(r.results.map(x => x.entry));
    }
  };
  try { await load(); } catch (e) { toast(e.message, "error"); return; }
  m = modal({ title: "Easy fixes", wide: true, cls: "easy-modal", body,
    buttons: [{ label: "Check again", onclick: async () => { try { await load(); } catch (e) { toast(e.message, "error"); } } },
              { label: "Cancel" },
              { label: "Apply", kind: "primary", ref: (el) => { applyBtn = el; }, onclick: (close, el) => apply(close, el) }] });
  update();
  return m;
}

// ------------------------------------------------------------------ guided fixes

async function copyText(text, btn) {
  const label = btn.dataset.label || (btn.dataset.label = btn.textContent);
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied";
  } catch {
    const pre = btn.parentElement.querySelector("code, pre");     // no clipboard access: select it instead
    if (pre) {
      const range = document.createRange();
      range.selectNodeContents(pre);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      btn.textContent = "Selected: Ctrl+C";
    } else {                                                       // nothing shown to select: a hidden text box
      const ta = h("textarea", { style: "position: fixed; opacity: 0", autocomplete: "off" });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      btn.textContent = document.execCommand("copy") ? "Copied" : "Couldn't copy";
      ta.remove();
    }
  }
  setTimeout(() => { btn.textContent = label; }, 2500);
}

// Beside a Copy button for something the app keeps off the disk (deleted file names, an unredacted report): a
// clipboard history that saves to the disk, as of the last scan, would keep it there
function clipboardKept(what) {
  const clip = S.report?.results?.["desk.clipboard_history"];
  const spec = S.state?.catalogue?.find(s => s.id === "desk.clipboard_history");
  if (clip?.status !== "fail" || !spec) return null;
  return h("div", { class: "notebox risk small" }, h("b", {}, "Copying keeps it on the disk. "),
    `${clip.summary} ${what} copied from here would be saved there too (as of the last scan).`,
    h("div", { class: "orow" }, fixButtons(spec, clip)));
}

function commandBlock(cmds) {
  return h("div", { class: "cmds" }, cmds.map(c => h("div", { class: "cmd" }, h("code", {}, c),
    h("button", { class: "small ghost", onclick: (e) => copyText(c, e.target) }, "Copy"))));
}

// a choice that shapes the step's options (a size, a yes/no): changing it builds the guide again,
// so the dry run below always shows exactly what applying does
function guideInput(inp, params, rebuild) {
  const set = (v) => { params[inp.name] = v; rebuild(); };
  let el;
  if (inp.kind === "bool") {
    el = h("input", { type: "checkbox", checked: !!inp.value, onchange: (e) => set(e.target.checked) });
  } else if (inp.kind === "choice") {
    el = h("select", { onchange: (e) => set(e.target.value) },
      inp.choices.map(([v, label]) => h("option", { value: v, selected: v === inp.value }, label)));
  } else {
    el = h("input", { type: "number", min: inp.min, max: inp.max, value: inp.value, class: "num",
      onchange: (e) => { const v = parseInt(e.target.value, 10); set(Number.isFinite(v) ? v : inp.default); } });
  }
  const label = inp.kind === "bool" ? h("label", { class: "check" }, el, inp.label)
    : h("label", {}, h("span", {}, inp.label), el, inp.unit ? h("span", { class: "muted small" }, inp.unit) : null);
  return h("div", { class: "ginput" }, label, inp.help ? h("div", { class: "muted small" }, inp.help) : null);
}

// After a step is applied, the guide is built again. A firewall can hold that request: OpenSnitch, restarted by its
// own guide's steps, forgets answers given until restart and asks again about the window's new connection to this
// app (WebKitGTK opens one for every POST), holding it until answered or timed out. The page says so, not frozen.
const SLOW_REFRESH_MS = 4000;

async function refreshAfterApply(refresh, msg) {
  msg.className = "small muted";
  msg.textContent = "Updating the guide…";
  const slow = setTimeout(() => {
    msg.textContent = "Still waiting for the app to answer. If a firewall such as OpenSnitch is asking about a "
      + "connection to 127.0.0.1 or localhost, that is this window reaching the app itself: allow it. "
      + "Otherwise it goes on once the question times out.";
  }, SLOW_REFRESH_MS);
  try { await refresh(); } finally { clearTimeout(slow); }
}

function guideStep(step, n, refresh, params = {}, rebuild = refresh) {
  const box = h("div", { class: `gstep${step.done ? " done" : ""}` });
  box.append(h("div", { class: "ghead" }, h("span", { class: "num" }, n), h("b", {}, step.title),
    step.done ? h("span", { class: "badge st-pass" }, "done") : null));
  if (step.text) box.append(h("p", {}, step.text));
  if (step.parts?.length) box.append(h("dl", { class: "gparts" }, step.parts.flatMap(([head, text]) => [h("dt", {}, head), h("dd", {}, text)])));
  if (step.inputs?.length) box.append(h("div", { class: "ginputs" }, step.inputs.map(i => guideInput(i, params, rebuild))));
  if (step.options.length) {
    let chosen = Math.max(0, step.options.findIndex(o => o.recommended));
    const detail = h("div", { class: "optdetail" });
    const confirm = h("input", { type: "checkbox" });
    const apply = h("button", { class: "primary" }, "Apply this step");
    const msg = h("div", { class: "small" });
    const show = () => {
      const o = step.options[chosen], plan = o.plan;
      const irreversible = plan.steps.some(st => st.irreversible);
      confirm.checked = false;
      fill(detail,
        o.detail ? h("p", { class: "muted small" }, o.detail) : null,
        plan.blockers.length ? h("div", { class: "warnbox bad" }, plan.blockers.join(" ")) : null,
        h("ul", { class: "steps" }, plan.steps.map(stepLine)),
        plan.side_effects.length ? h("ul", { class: "small effects" }, plan.side_effects.map(x => h("li", {}, x))) : null,
        irreversible ? h("label", { class: "check confirm" }, confirm,
          "I understand that what the items marked “can't be undone” delete, or clear from a file, is gone for good.") : null,
        plan.needs_root && !S.adminActive ? h("p", { class: "muted small" }, ROOT_NOTE) : null);
      apply.className = irreversible ? "danger" : "primary";
      apply.textContent = irreversible ? "Apply and delete" : "Apply this step";
      apply.disabled = plan.blockers.length > 0 || irreversible;
      confirm.onchange = () => { apply.disabled = plan.blockers.length > 0 || !confirm.checked; };
    };
    if (step.options.length > 1) {
      const name = `opt-${Math.random().toString(36).slice(2)}`;
      box.append(h("div", { class: "opts" }, step.options.map((o, i) => h("label", { class: "opt" },
        h("input", { type: "radio", name, checked: i === chosen, onchange: () => { chosen = i; show(); } }),
        o.label, o.recommended ? h("span", { class: "rec" }, "recommended") : null))));
    }
    show();
    apply.addEventListener("click", async () => {
      const plan = step.options[chosen].plan;
      apply.disabled = true;
      apply.textContent = "Applying…";
      try {
        const r = await applyPlan(plan, confirm.checked);
        toast(`Done: ${plan.title}.` + (r.result?.status === "pass" ? " The check passes now." : ""), "ok");
        apply.textContent = "Applied";
        doneDialog([r.entry]);
        await refreshAfterApply(refresh, msg);
      } catch (e) {
        msg.className = "small errmsg";
        msg.textContent = e.declined ? e.message : `Failed, and rolled back: ${e.message}`;
        apply.textContent = "Apply this step";
        apply.disabled = false;
        setStatus(e.message, "failed");
        if (e.data?.entry) doneDialog([e.data.entry], e.message);
      }
    });
    box.append(detail, h("div", { class: "gactions" }, apply, msg));
  }
  if (step.commands.length) {
    box.append(h("div", { class: "muted small" }, step.options.length ? "Or yourself, in a terminal:" : "In a terminal:"),
      commandBlock(step.commands));
  }
  if (step.side_effects.length) {
    box.append(h("div", {}, h("h4", {}, "Worth knowing"), h("ul", { class: "small effects" }, step.side_effects.map(x => h("li", {}, x)))));
  }
  return box;
}

async function openGuide(spec) {
  const body = h("div", { class: "guide" });
  const params = {};          // the guide's inputs as set here
  let m;
  const load = async () => {
    const data = await api("POST", `/api/fix/${encodeURIComponent(spec.id)}/plan`, { params });
    if (data.result && S.report) { S.report.results[spec.id] = data.result; renderChecks(); }
    return data;
  };
  const render = (data) => {
    const g = data.guide;
    const passing = data.result?.status === "pass";
    fill(body,
      passing ? h("div", { class: "notebox info" }, "This check passes now.") : null,
      g.intro ? h("p", {}, g.intro) : null,
      h("p", { class: "muted small" }, g.advice
        ? "The app doesn't make this change itself: each step says what to do, for this machine."
        : "Nothing changes until you apply a step. Each one shows exactly what it does; "
          + "settings changes can be reverted from History."),
      g.steps.map((st, i) => guideStep(st, i + 1, refresh, params, refresh)));
  };
  const refresh = async () => {
    try { render(await load()); } catch (e) {
      body.replaceChildren(h("div", { class: "warnbox" }, e.message));
    }
  };
  let data;
  try { data = await load(); } catch (e) { toast(e.message, "error"); return; }
  m = modal({ title: data.guide.title, wide: true, body,
    buttons: [{ label: "Check again", onclick: () => refresh() }, { label: "Close", kind: "primary" }] });
  render(data);
  return m;
}

// ------------------------------------------------------------------ the welcome warning
// Shown at start-up until the user ticks "Don't show this again" (kept by the server, with the warning's
// version, so a warning that changes is shown once more); the app's name in the top bar opens it again.

function welcomeLink(name) {
  const url = S.state?.welcome?.links?.[name] || "";
  return h("a", { href: url, class: "extlink", title: "Opens in your web browser", onclick: async (e) => {
    e.preventDefault();
    try { await api("POST", "/api/open", { link: name }); toast(`Opening ${url} in your web browser.`, "info"); }
    catch (err) { toast(err.message, "error", 10000); }
  } }, url);
}

function openWelcome() {
  const again = h("input", { type: "checkbox", checked: S.state?.welcome?.show === false });
  const body = h("div", { class: "welcome-body" },
    h("img", { class: "welcome-banner", src: "/static/dabanner.jpg", alt: "Digital Archon: take back control of your data" }),
    h("p", { class: "lead" }, "It is important to understand what this tool is and isn't."),
    h("section", { class: "wbeta" },
      h("h3", {}, "Public beta: expect bugs"),
      h("p", {}, h("b", {}, "DA Privacy Kit is in public beta. "), "It has been extensively tested, but there will "
        + "certainly still be bugs: in what it detects, in what it tells you, and in what its fixes and tools do."),
      h("p", {}, "For now it is best used to scan for problems, to learn about your own system, and to experiment with its "
        + "tools. ", h("b", {}, "Don't rely on it yet for critical privacy matters:"), " check what it finds and what it "
        + "advises for yourself."),
      h("p", {}, "Nothing it does should leave your system with a problem you can't undo. It shows every change before "
        + "making it, the settings it changes can be reverted from History, and the clean-ups that delete files (caches, "
        + "histories), which can't be undone, each ask you separately first. ", h("b", {}, "But it isn't risk-free: "),
        "several of its fixes and tools run commands with administrator rights (it asks for your password first), and a "
        + "bug in one of those can affect the whole system. Keep backups, as you always should."),
      h("p", {}, "If you find a bug, please report it. The app sends nothing by itself, so the project only hears of "
        + "it from you: ", welcomeLink("issues"))),
    h("section", { class: "wnot" },
      h("h3", {}, "What this tool is NOT"),
      h("p", {}, h("b", {}, "It is in no way a replacement for, or an alternative to, Tails or Qubes OS.")),
      h("p", {}, "If what you need is a system you start on any computer from a USB stick, that sends all your Internet "
        + "traffic through Tor and leaves no trace of your activity on that computer, with a limited set of applications "
        + "at the highest level of privacy, you need Tails. It is free: ", welcomeLink("tails")),
      h("p", {}, "If you need an installed, fully featured desktop operating system built for security first, you need "
        + "Qubes OS. It keeps your work, your browsing and your devices in separate virtual machines, so one compromised "
        + "program can't reach the rest. It is free: ", welcomeLink("qubes"), ". There is a learning curve, and it needs "
        + "capable hardware (it isn't made for gaming or 3D work), but for some people it is worth it."),
      h("p", {}, "Nor is it antivirus: it can't tell whether this computer has already been compromised, and it doesn't "
        + "make you anonymous online.")),
    h("section", { class: "wis" },
      h("h3", {}, "What this tool IS"),
      h("p", {}, "It helps in four ways:"),
      h("ol", {},
        h("li", {}, "Its scans, reports and fixes help you improve the privacy of the system you already have. It will "
          + "probably show you problems you weren't aware of, and help you fix them, or accept that in your case they "
          + "don't matter."),
        h("li", {}, "It helps you understand where your private information is, and where it may go. Often you may simply "
          + "not mind. But if this computer is mostly for gaming and you do some banking on it, it is still worth knowing "
          + "what protects your data if, say, the computer is stolen: there may be steps you hadn't considered."),
        h("li", {}, "It gives you tools to use proactively on the system you already have. They are not as strong as Tails "
          + "or Qubes, but used with their limits in mind, they are a real improvement on how a normal system works."),
        h("li", {}, h("b", {}, "It is also meant to teach. "), "It is worth actually reading what it checks, what it finds, "
          + "why each one matters and how it recommends fixing it, not just pressing the buttons. Each one is an example "
          + "of a way your privacy can be at risk. Once you understand the kinds of ways it happens, you can think it "
          + "through for yourself, in the places and situations no scan can look at."))),
    h("div", { class: "wfinal" },
      h("p", {}, h("b", {}, "Finally: most privacy losses don't come from technical failures or breaches, but from how "
        + "computers and accounts are used.")),
      h("p", {}, "Even Tails won't protect you if you log in to your Google account and upload all your private data to "
        + "it. If your privacy matters to you, learn as much as you can about how your computer and the apps you use work, "
        + "so you can make the right decisions. This app's scans and guides give you a good grounding in what can go "
        + "wrong, and what can be done about it.")),
    h("p", { class: "muted small" }, "You can read this again at any time: click DA Privacy Kit at the top left."),
    h("p", { class: "muted small" }, `Version ${S.state?.app?.version || S.state?.version || "?"}`
      + (S.state?.app?.built_text ? `, built ${S.state.app.built_text}.` : " (run from source).")));
  modal({ title: "Important privacy warning", wide: true, cls: "welcome", sticky: true, body,
    foot: h("label", { class: "check" }, again, "Don't show this again"),
    buttons: [{ label: "I understand", kind: "primary", onclick: async (close) => {
      close();
      try { S.state.welcome = { ...S.state.welcome, ...(await api("POST", "/api/welcome", { hide: again.checked })) }; }
      catch { /* shown again next time */ }
    } }] });
}

// ------------------------------------------------------------------ history

async function openHistory() {
  let data;
  try { data = await api("GET", "/api/undo"); } catch (e) { toast(e.message, "error"); return; }
  const list = h("div", { class: "history" });
  const render = (entries) => {
    list.replaceChildren();
    if (!entries.length) list.append(h("div", { class: "empty" }, "No fixes have been applied yet."));
    for (const en of entries) list.append(historyEntry(en, render));
  };
  render(data.entries);
  const forget = async (everything) => {
    try {
      const r = await api("POST", "/api/undo/forget", { everything });
      toast(r.forgotten ? `Forgot ${plural(r.forgotten, "entry", "entries")} and their backups.` : "Nothing to forget.", "ok");
      if (S.report && r.undone) { S.report.undone = r.undone; renderChecks(); }
      render(r.entries);
    } catch (e) { toast(e.message, "error"); }
  };
  modal({ title: "History", wide: true, body: [h("p", { class: "muted small" },
    "Every fix applied, newest first. Settings can be put back; deleted files can't. Each entry keeps a copy of "
    + "what it changed (in ~/.local/state/daprivacyscanner) until it is forgotten."), helperRow(), list],
    buttons: [
      { label: "Export everything…", onclick: () => openExport("everything") },
      { label: "Forget reverted and old entries", onclick: (close) => forget(false) },
      { label: "Forget everything", kind: "danger", onclick: (close) => {
        modal({ title: "Forget all history?", body: h("p", {}, "The changes stay as they are; they just can't be reverted from here any more, and the backups of the files they changed are deleted. The saved results of the last scan are deleted too."),
          buttons: [{ label: "Keep it" }, { label: "Forget everything", kind: "danger", onclick: (c2) => { c2(); forget(true); } }] });
      } },
      { label: "Close", kind: "primary" }] });
}

function historyEntry(en, rerender) {
  const when = new Date(en.applied * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  const msg = h("div", { class: "small" });
  const revert = async (force) => {
    try {
      if (en.needs_root && !S.adminActive) setStatus("Waiting for administrator authorization…", "busy");
      const r = await api("POST", `/api/undo/${en.id}/revert`, { force });
      if (en.needs_root) { S.adminActive = true; renderTop(); setStatus("Reverted.", "done"); }
      takeRecheck(r);
      msg.className = `small ${r.ok ? "okmsg" : "errmsg"}`;
      msg.replaceChildren(r.messages.join(" "));
      if (r.conflict) {
        msg.append(" ", h("button", { class: "small danger", onclick: () => revert(true) }, "Revert anyway"));
      }
      const fresh = await api("GET", "/api/undo");
      const keep = msg;
      rerender(fresh.entries);
      document.querySelector(`[data-entry="${en.id}"] .msgslot`)?.replaceWith(keep);
    } catch (e) { toast(e.message, "error"); }
  };
  return h("div", { class: "entry", "data-entry": en.id },
    h("div", { class: "ehead" }, h("b", {}, en.title), h("span", { class: "muted small" },
      `${checkTitle(en.check_id)} · ${when}`),
      h("span", { class: `badge state-${en.state.replace(" ", "-")}` }, en.state),
      en.undone_since ? h("span", { class: "badge undone", title: "What this fixed is a problem again: something changed it back" },
        `changed back (found ${new Date(en.undone_since * 1000).toLocaleDateString([], { dateStyle: "medium" })})`) : null,
      h("span", { class: "spacer" }),
      en.can_revert ? h("button", { class: "small", title: en.needs_root ? ROOT_NOTE : "", onclick: () => revert(false) },
        en.needs_root && !S.adminActive ? "Revert (as administrator)" : "Revert") : null),
    en.via_text ? h("div", { class: "small muted" }, en.via_text) : null,
    en.state === "failed" ? h("div", { class: "small errmsg" }, `Failed: ${en.error || "the fix couldn't be applied"}`
      + (en.failed_step ? ` (at: ${en.failed_step})` : "") + ". The steps that had run were put back, as listed."
      + (en.can_revert ? " One couldn't be: revert it from here." : "")) : null,
    entrySteps(en, false, rerender),
    h("div", { class: "msgslot" }, msg));
}

// ------------------------------------------------------------------ what a scan reads, export, helper note

function openReads() {
  const body = h("div", { class: "reads" },
    h("p", {}, "A scan only reads. This is everything it looks at, and why; nothing is sent anywhere."),
    S.state.reads.map(r => h("div", { class: "read" }, h("b", {}, r.what), r.why, h("div", { class: "how" }, r.how))),
    h("div", {}, h("h4", {}, "What it never does"), h("ul", { class: "small" }, S.state.never.map(x => h("li", {}, x)))));
  modal({ title: "What a scan reads", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
}

const EXPORT_WHAT = {
  report: ["This report", "report", "To share, for example when asking for help."],
  everything: ["Everything: the report, accepted findings and every change made", "everything",
    "To keep with your backups: every change in History with what it was before and how to undo it by hand, even "
    + "without this app. Copies of changed files and anything deleted are never in it."],
};

async function openExport(what = "report") {
  const everything = what === "everything";
  const redact = h("input", { type: "checkbox", checked: !everything });
  const fmt = h("select", {}, h("option", { value: "text" }, "Text"), h("option", { value: "json" }, "JSON"));
  const sel = h("select", {}, Object.entries(EXPORT_WHAT).map(([k, [label]]) =>
    h("option", { value: k, selected: k === what, disabled: k === "report" && !S.report }, label)));
  const about = h("p", { class: "muted small" });
  const pre = h("pre", {}, "…");
  const load = async () => {
    about.textContent = EXPORT_WHAT[sel.value][2];
    const path = sel.value === "everything" ? "/api/export" : "/api/report";
    try { pre.textContent = await api("GET", `${path}?format=${fmt.value}&redact=${redact.checked ? 1 : 0}`, undefined, true); }
    catch (e) { pre.textContent = e.message; }
  };
  redact.addEventListener("change", load);
  fmt.addEventListener("change", load);
  sel.addEventListener("change", load);
  await load();
  const body = h("div", { class: "export" },
    h("div", { class: "orow" }, sel, h("span", { class: "spacer" }), fmt),
    about,
    h("div", { class: "orow" }, h("label", { class: "check" }, redact, "Redact: your name, host name, account and network names, addresses, paths under your home, drive labels, disk IDs and the names of your keys and wallets")),
    h("p", { class: "muted small" }, "Read it before sharing: redaction replaces what it knows to look for, not everything that could identify you."),
    clipboardKept("A report"),
    pre);
  modal({ title: everything ? "Export everything" : "Export the report", wide: true, body, buttons: [
    { label: "Copy", onclick: (close, el) => copyText(pre.textContent, el) },
    { label: "Download", onclick: () => {
      const blob = new Blob([pre.textContent], { type: fmt.value === "json" ? "application/json" : "text/plain" });
      const name = sel.value === "everything" ? "everything" : "report";
      const a = h("a", { href: URL.createObjectURL(blob), download: `daprivacyscanner-${name}-${new Date().toISOString().slice(0, 10)}.${fmt.value === "json" ? "json" : "txt"}` });
      document.body.append(a); a.click(); a.remove();
    } },
    { label: "Close", kind: "primary" }] });
}

// installs this version's helper root-owned (asks for the password), then updates the note
async function installHelper(close, btn) {
  btn.disabled = true;
  btn.textContent = "Waiting for authorization…";
  try {
    const r = await api("POST", "/api/helper/install", {});
    S.state.helper_installed = r.helper_installed;
    S.state.helper_stale = r.helper_stale;
    S.adminActive = false;
    renderTop();
    close();
    toast(`Installed ${r.installed}: the password prompt now names DA Privacy Kit.`, "ok");
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Install it";
    toast(e.message, "error", 10000);
  }
}

// in History, while the helper is installed: it is a change to the system too, and can be removed
function helperRow() {
  if (!S.state.helper_installed) return null;
  const row = h("div", { class: "orow helperrow" },
    h("span", { class: "small" }, S.state.helper_stale
      ? "An administrator helper from another version of the app is installed (/usr/libexec/daprivacyscanner)."
      : "The administrator helper is installed root-owned (/usr/libexec/daprivacyscanner), with its polkit action."),
    h("span", { class: "spacer" }),
    h("button", { class: "small", onclick: () => modal({ title: "Remove the administrator helper?", body: [
      h("p", {}, "The changes it made stay as they are, and can still be reverted from History. Root work then goes "
        + "through a copy of the helper run with `pkexec /usr/bin/python3` again, so the password prompt names python3 "
        + "rather than DA Privacy Kit."),
      h("p", { class: "muted small" }, "You can install it again from the note at the top, or with "
        + "`daprivacyscanner --install-helper`."),
    ], buttons: [{ label: "Keep it" }, { label: "Remove it", kind: "danger",
      onclick: (close, el) => uninstallHelper(close, el, row) }] }) }, "Remove it…"));
  return row;
}

async function uninstallHelper(close, btn, row) {
  btn.disabled = true;
  btn.textContent = "Waiting for authorization…";
  try {
    const r = await api("POST", "/api/helper/install", { uninstall: true });
    S.state.helper_installed = r.helper_installed;
    S.state.helper_stale = r.helper_stale;
    S.adminActive = false;
    renderTop();
    close();
    if (!r.helper_installed) row.remove();
    toast("Removed the administrator helper and its polkit action.", "ok");
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Remove it";
    toast(e.message, "error", 10000);
  }
}

function openHelperNote() {
  const install = { label: S.state.helper_stale ? "Install this version's" : "Install it", kind: "primary",
    onclick: (close, el) => installHelper(close, el) };
  if (S.state.helper_stale) {
    modal({ title: "The administrator helper is out of date", body: [
      h("p", {}, "The helper installed in /usr/libexec/daprivacyscanner comes from another version of DA Privacy "
        + "Kit, so this version refuses it rather than ask it for actions it may not have. Until it is reinstalled, "
        + "scans run without administrator access and fixes that need it can't be applied."),
      h("p", { class: "muted small" }, "Installing asks for your password once. From a terminal:"),
      commandBlock(["daprivacyscanner --install-helper"]),
    ], buttons: [{ label: "Close" }, install] });
    return;
  }
  modal({ title: "The administrator helper isn't installed", body: [
    h("p", {}, "Until it is, root work is done by a copy of the helper run with `pkexec /usr/bin/python3`: the password "
      + "prompt therefore names python3 rather than DA Privacy Kit, and what runs as root is only as safe as "
      + "your own account. Installing it root-owned, with its own polkit action, fixes both."),
    h("p", { class: "muted small" }, "Installing asks for your password once. From a terminal:"),
    commandBlock(["daprivacyscanner --install-helper", "daprivacyscanner --uninstall-helper"]),
  ], buttons: [{ label: "Close" }, install] });
}


// ------------------------------------------------------------------ tools (docs/TECHNICAL.md, Tools)
// Tools work on files the user chooses, only when started; nothing they show is kept or sent.

const fmtSize = (n) => n >= 1e12 ? `${(n / 1e12).toFixed(1)} TB` : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB`
  : n >= 1e3 ? `${Math.round(n / 1e3)} kB` : `${n} bytes`;

async function toolsInfo() {
  return api("GET", "/api/tools");
}

async function openTools() {
  let data;
  try { data = await toolsInfo(); } catch (e) { toast(e.message, "error"); return; }
  const body = h("div", { class: "tools" });
  const reload = async () => { try { render(await toolsInfo()); } catch (e) { toast(e.message, "error"); } };
  const render = (d) => {
    data = d;
    const groups = (d.groups || [{ id: "", title: "" }]).map(g => ({ ...g, tools: d.tools.filter(t => !g.id || t.group === g.id) }));
    fill(body,
      h("p", { class: "muted small" }, "Tools work on files you choose, only when you start them. Nothing is sent anywhere "
        + "(the browser download names the servers it contacts before it starts), and nothing they show is kept."),
      groups.filter(g => g.tools.length).map(g => h("section", { class: `toolgroup group-${g.id}` },
        g.title ? h("h4", {}, g.title) : null,
        // two or four tiles in rows of two, three in a row of three: no tile left alone on a row
        h("div", { class: `toolgrid cols-${g.tools.length % 2 === 0 ? 2 : 3}` }, g.tools.map(t => toolCard(t, d, reload))))),
      h("h4", {}, "Set-ups that last"),
      h("p", { class: "muted small" }, "Each is set up step by step, and can be undone from History."),
      h("div", { class: "features" }, d.features.map(featureRow)));
  };
  modal({ title: "Tools", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
  render(data);
}

// Each tool's icon: line drawings on a 24-unit grid, drawn in the tile's group colour (the app's own, no icon font
// or remote asset). [element, attributes] pairs.
const TOOL_ICONS = {
  verify: [["path", { d: "M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6z" }], ["path", { d: "M9 12l2 2 4-4" }]],
  metadata: [["rect", { x: 3, y: 4, width: 18, height: 15, rx: 2 }], ["circle", { cx: 8.5, cy: 9.5, r: 1.5 }],
    ["path", { d: "M21 15l-5-5-9 9" }], ["path", { d: "M2 2l20 20" }]],
  ramdisk: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 1.5 }], ["rect", { x: 9.5, y: 9.5, width: 5, height: 5 }],
    ["path", { d: "M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" }]],
  browser: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M3 12h18" }],
    ["path", { d: "M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9S9.5 5.5 12 3z" }]],
  trim: [["rect", { x: 2, y: 13, width: 20, height: 8, rx: 2 }], ["path", { d: "M6 17h.01M10 17h.01" }],
    ["path", { d: "M8 6.5l3 3 5-5.5" }]],
  names: [["path", { d: "M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h4" }], ["path", { d: "M13 3v5h5l-5-5" }],
    ["path", { d: "M18 8v2" }], ["circle", { cx: 15.5, cy: 15.5, r: 3 }], ["path", { d: "M17.7 17.7L21 21" }]],
  handover: [["rect", { x: 7, y: 10, width: 10, height: 12, rx: 2 }], ["path", { d: "M9 10V3h6v7" }],
    ["path", { d: "M11 6h.01M13 6h.01" }]],
  retire: [["path", { d: "M3 6h18" }], ["path", { d: "M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" }],
    ["path", { d: "M5 6l1 14a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1l1-14" }], ["path", { d: "M10 11v6M14 11v6" }]],
  travel: [["rect", { x: 3, y: 7, width: 18, height: 13, rx: 2 }], ["path", { d: "M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" }],
    ["path", { d: "M8 7v13M16 7v13" }]],
  presentation: [["path", { d: "M8.7 3.6A6 6 0 0 1 18 8c0 3 .6 5.1 1.4 6.5" }], ["path", { d: "M17 17H3s3-2 3-9c0-.6.1-1.1.2-1.6" }],
    ["path", { d: "M10 21a2 2 0 0 0 4 0" }], ["path", { d: "M2 2l20 20" }]],
  inuse: [["circle", { cx: 12, cy: 10, r: 7 }], ["circle", { cx: 12, cy: 10, r: 3 }], ["path", { d: "M12 17v3M8 21h8" }]],
  trial: [["path", { d: "M9 3h6" }], ["path", { d: "M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4a2 2 0 0 0 1.8-3l-5-9V3" }],
    ["path", { d: "M7.5 15h9" }]],
  keeps: [["rect", { x: 3, y: 4, width: 13, height: 10, rx: 1.5 }], ["path", { d: "M3 7.5h13" }],
    ["circle", { cx: 16.5, cy: 16, r: 3.5 }], ["path", { d: "M19 18.5L22 21.5" }]],
};

function toolIcon(id) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", width: 22, height: 22, fill: "none", stroke: "currentColor",
    "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) svg.setAttribute(k, v);
  for (const [tag, attrs] of TOOL_ICONS[id] || [["circle", { cx: 12, cy: 12, r: 8 }]]) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.append(el);
  }
  return h("span", { class: "toolicon" }, svg);
}

// what a tool's tile says of its state now: open, on, or what it needs installed (with the command as its tooltip)
function toolStatus(t, data) {
  const v = data.verify || {}, m = data.metadata || {}, rd = data.ramdisk || {};
  if (t.id === "verify" && !v.gpgv && !v.sqv) return { text: "Needs gpgv", kind: "warn", title: v.install || "" };
  if (t.id === "metadata") {
    if (!m.mat2?.installed && !m.exiftool?.installed) return { text: "Needs mat2", kind: "warn", title: m.mat2?.install || "" };
    if (!m.mat2?.installed) return { text: "Needs mat2 to clean", kind: "warn", title: m.mat2?.install || "" };
  }
  if (t.id === "ramdisk") {
    if (rd.other) return { text: "Unavailable", kind: "warn", title: `Something else (${rd.other}) is mounted on ~/RAMDisk` };
    if (rd.open) return { text: rd.size ? `Open · ${rd.size}` : "Open", kind: "on" };
  }
  if (t.id === "browser" && data.browser_disk) return { text: "~/TempBrowser open", kind: "on" };
  if (t.id === "trial" && data.trial) return { text: data.trial === "running" ? "Running" : data.trial === "ended" ? "Result waiting" : "Prepared", kind: "on" };
  if (t.id === "keeps" && data.keeps) return ["asking", "running", "ending"].includes(data.keeps) ? { text: "Watching", kind: "warn" }
    : data.keeps === "done" ? { text: "Result waiting", kind: "on" } : null;
  if (t.id === "presentation" && S.presentation?.on) {
    const since = S.presentation.since ? new Date(S.presentation.since * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
    return { text: since ? `On since ${since}` : "On", kind: "warn" };
  }
  return null;
}

function toolCard(t, data, reload) {
  const st = toolStatus(t, data);
  const card = h("div", { class: "toolcard", id: `tool-${t.id}` },
    h("div", { class: "toolhead" }, toolIcon(t.id),
      h("div", { class: "tooltitle" }, h("b", {}, t.title), t.short ? h("div", { class: "small" }, t.short) : null),
      st ? h("span", { class: `toolstate ${st.kind}`, title: [st.text, st.title].filter(Boolean).join(": ") }, st.text) : null),
    t.short ? h("details", { class: "toolmore small" }, h("summary", {}, "More about it"), h("p", {}, t.text))
      : h("p", { class: "small" }, t.text));
  if (t.id === "verify") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: () => openVerify(data) }, t.button)));
  } else if (t.id === "metadata") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: () => openMetadata(data) }, t.button)));
  } else if (t.id === "ramdisk") {
    card.append(ramdiskPanel(data.ramdisk, reload));
  } else if (t.id === "browser") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: () => openBrowserTool(reload) }, t.button)));
  } else if (t.id === "trim") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: openTrim }, t.button)));
  } else if (t.id === "names") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: () => openNames() }, t.button)));
  } else if (t.id === "handover") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: openHandover }, t.button)));
  } else if (t.id === "retire") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: openRetire }, t.button)));
  } else if (t.id === "travel") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: openTravel }, t.button)));
  } else if (t.id === "presentation") {
    card.append(presentationCard(reload));
  } else if (t.id === "inuse") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: openInuse }, t.button)));
  } else if (t.id === "trial") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: () => openTrial(reload) }, t.button)));
  } else if (t.id === "keeps") {
    card.append(h("div", { class: "orow" }, h("button", { class: "primary small", onclick: openKeeps }, t.button)));
  }
  return card;
}

function featureRow(id) {
  const spec = S.state.catalogue.find(s => s.id === id);
  if (!spec) return null;
  const r = S.report?.results?.[id];
  const done = r?.status === "pass";
  // a set-up's risks stay in view with it (OpenSnitch in allow mode, its answers in a log) until dealt with
  const risks = (r?.notes || []).filter(n => n.kind === "risk");
  return h("div", { class: "feature" },
    h("div", { class: "titles" }, h("b", {}, spec.title),
      h("div", { class: "small muted" }, r ? r.summary : "Scan to see whether it is set up."),
      risks.map(n => h("div", { class: "notebox risk small" }, h("b", {}, n.title), ": ", n.text)),
      h("div", { class: "small" }, spec.remedy)),
    id === "app.boxes" ? h("button", { class: "small primary", title: "Your Boxes: start one, see its runs",
      onclick: () => openBoxes() }, "Open…") : null,
    h("button", { class: `small ${done ? "" : "primary"}`, onclick: () => openGuide(spec) },
      id === "app.boxes" && done ? "Add one…" : done ? "Review…" : "Set up…"));
}

// a path box with Choose… (the file dialog) and, for one file, the newest downloads to pick from
function pathPicker(data, { multiple = false, onPick, label = "File" }) {
  const input = h("input", { type: "text", class: "path", autocomplete: "off", placeholder: "/home/you/Downloads/file.iso, or ~/…",
    spellcheck: "false" });
  const choose = async (btn) => {
    btn.disabled = true;
    try {
      const r = await api("POST", "/api/tools/pick", { multiple });
      if (r.unavailable) { toast("No file dialog here: type or paste the path.", "info"); input.focus(); return; }
      if (r.paths.length) { input.value = r.paths.join("\n"); onPick?.(r.paths); }
    } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  };
  return { input, row: h("div", { class: "orow" }, h("span", { class: "small muted" }, label), input,
    data.can_pick ? h("button", { class: "small", onclick: (e) => choose(e.target) }, "Choose…") : null) };
}

const VERDICT_CLASS = { verified: "ok", signed: "info", intact: "warn", bad: "bad", unchecked: "warn" };

async function openVerify(data, path = "") {
  data = data || await toolsInfo();
  const out = h("div", { class: "verdict-slot" });
  const file = pathPicker(data, { label: "File", onPick: () => run() });
  file.input.value = path;
  const keyfile = pathPicker(data, { label: "Key file (optional)" });
  const paste = h("input", { type: "text", class: "path", autocomplete: "off", placeholder: "a checksum from the download page (optional)",
    spellcheck: "false" });
  const keyring = h("input", { type: "checkbox", checked: true });
  const btn = h("button", { class: "primary" }, "Verify");
  const run = async () => {
    if (!file.input.value.trim()) { file.input.focus(); return; }
    btn.disabled = true;
    fill(out, h("div", { class: "orow" }, h("span", { class: "spinner on" }), "Reading the file and checking its signatures…"));
    try {
      const r = await api("POST", "/api/tools/verify", { path: file.input.value.trim(), expected: paste.value,
        key_files: keyfile.input.value.trim() ? [keyfile.input.value.trim()] : [], use_keyring: keyring.checked });
      fill(out, verdictBox(r.verdict));
    } catch (e) { fill(out, h("div", { class: "warnbox bad" }, e.message)); }
    finally { btn.disabled = false; }
  };
  btn.addEventListener("click", run);
  const recent = data.downloads.length ? h("div", { class: "recent" }, h("span", { class: "small muted" }, `Newest in ${data.downloads_dir}:`),
    data.downloads.slice(0, 8).map(d => h("button", { class: "small ghost", title: `${fmtSize(d.size)}`,
      onclick: () => { file.input.value = d.path; run(); } }, d.name))) : null;
  const body = h("div", { class: "verify" },
    h("p", { class: "small" }, "Checks that a file is the one its makers published. Put the signature (.asc, .sig, .gpg, "
      + ".sign) or the signed checksum list (SHA256SUMS and SHA256SUMS.gpg, sha256sum.txt and .gpg, CHECKSUM…) from the "
      + "download page next to the file; the app finds them, and reads the signature inside .deb and .rpm packages. It "
      + "knows the release keys of Linux Mint, Ubuntu, Debian, Fedora, openSUSE, Arch, Manjaro, EndeavourOS, CachyOS, "
      + "Kali, Tails, Qubes OS, Whonix, Tor Browser and Mullvad Browser, Firefox and Thunderbird, Mullvad VPN, Proton VPN, "
      + "IVPN, VeraCrypt, KeePassXC and Cryptomator, and this app's own releases."),
    !data.verify.gpgv && !data.verify.sqv ? h("div", { class: "warnbox" }, "Checking OpenPGP signatures needs gpgv, which "
      + "isn't installed. Checksums can still be compared.", data.verify.install ? commandBlock([data.verify.install]) : null) : null,
    file.row, recent,
    h("details", {}, h("summary", { class: "small" }, "More: a pasted checksum, a key file"),
      h("div", { class: "vmore" },
        h("div", { class: "orow" }, h("span", { class: "small muted" }, "Checksum"), paste),
        keyfile.row,
        h("label", { class: "check small" }, keyring, "Also use the keys in my GnuPG keyring (only read, never changed)"))),
    h("div", { class: "gactions" }, btn),
    out);
  modal({ title: "Verify a download", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
  if (path) run();
}

function verdictBox(v) {
  const sigLine = (s) => h("li", {},
    h("span", { class: `badge sig-${s.status}` }, s.status === "good" ? "good signature" : s.status.replace("_", " ")),
    " ", h("code", {}, s.path.split("/").pop()), s.inside ? ` (inside it: ${s.inside})` : "",
    s.project ? ` by ${s.project}'s key (${s.key_name})` : s.key_name ? ` by ${s.key_name}` : "",
    s.fingerprint_grouped || s.issuer ? h("div", { class: "fpr" }, s.fingerprint_grouped || s.issuer) : null,
    s.detail ? h("div", { class: "small muted" }, s.detail) : null,
    s.install ? commandBlock([s.install]) : null);
  const sigs = [...v.signatures, ...v.lists.filter(l => l.signature).map(l => l.signature)];
  return h("div", { class: `verdict ${VERDICT_CLASS[v.level] || "warn"}` },
    h("div", { class: "vtitle" }, v.title),
    h("p", {}, v.text),
    v.steps.length ? h("ul", { class: "small" }, v.steps.map(x => h("li", {}, x))) : null,
    v.notes.map(n => h("div", { class: "notebox info small" }, n)),
    h("div", { class: "vdetails" },
      h("div", { class: "small" }, h("b", {}, v.name), ` · ${fmtSize(v.size)}`),
      Object.entries(v.hashes).filter(([a]) => ["sha256", "sha512"].includes(a)).map(([a, d]) =>
        h("div", { class: "cmd" }, h("span", { class: "small muted" }, a === "sha256" ? "SHA-256" : "SHA-512"), h("code", {}, d),
          h("button", { class: "small ghost", onclick: (e) => copyText(d, e.target) }, "Copy"))),
      sigs.length ? h("div", {}, h("h4", {}, "Signatures"), h("ul", { class: "small sigs" }, sigs.map(sigLine))) : null,
      v.lists.length ? h("div", {}, h("h4", {}, "Checksum lists"), h("ul", { class: "small" }, v.lists.flatMap(l =>
        l.entries.map(e => h("li", {}, h("code", {}, l.name), `: ${e.algo_title} `, e.matches ? "matches" : h("b", { class: "errmsg" }, "doesn't match")))))) : null,
      v.pasted ? h("div", { class: "small" }, `Pasted ${v.pasted.algo_title} checksum: `, v.pasted.matches ? "matches" : h("b", { class: "errmsg" }, "doesn't match")) : null));
}

const META_WARN = new Set(["location", "people", "device"]);
const META_SHORT = { location: "where", people: "who", device: "device", software: "software", dates: "dates",
                     text: "text", other: "other" };
const META_FILTERS = [["all", "All"], ["location", "Where it was made"], ["people", "Who made it"], ["device", "The device"],
                      ["none", "Nothing found"], ["uncleanable", "Can't be cleaned"], ["unread", "Couldn't be read"]];
const META_SKIPPED = { hidden: ["hidden", "hidden"], links: ["link (not followed)", "links (not followed)"],
                       unfinished: ["unfinished download", "unfinished downloads"],
                       other_disks: ["folder on another disk", "folders on another disk"],
                       special: ["special file", "special files"], unreadable: ["unreadable", "unreadable"],
                       too_deep: ["folder nested too deep", "folders nested too deep"] };
const META_PAGE = 100;

// a long list shown a page at a time
function pagedList(items, row, cls = "meta-list") {
  const box = h("div", { class: cls });
  let shown = 0;
  const more = h("button", { class: "small ghost" });
  const next = () => {
    box.append(...items.slice(shown, shown + META_PAGE).map(row));
    shown = Math.min(items.length, shown + META_PAGE);
    more.textContent = `Show ${Math.min(META_PAGE, items.length - shown)} more (${items.length - shown} not shown)`;
    more.hidden = shown >= items.length;
  };
  more.addEventListener("click", next);
  next();
  return h("div", {}, box, h("div", { class: "orow" }, more));
}

// one file of many: what it carries in a line, the first few items when opened, everything on request
function metaRow(f, { path = f.path, tick = null, open = false } = {}) {
  const badges = [
    ...f.groups.map(g => h("span", { class: `badge${META_WARN.has(g.id) ? " st-warn" : ""}`, title: g.title },
      `${META_SHORT[g.id] || g.id} ${g.count}`)),
    !f.count && !f.error ? h("span", { class: "badge st-pass" }, "nothing found") : null,
    f.error && !f.count ? h("span", { class: "badge st-error", title: f.error }, "couldn't be read") : null,
    f.cleanable === false ? h("span", { class: "badge", title: "mat2 doesn't clean this kind of file" }, "can't be cleaned") : null];
  const body = h("div", { class: "meta-detail" });
  const full = async (btn) => {
    if (btn) btn.disabled = true;
    try {
      const r = await api("POST", "/api/tools/metadata/show", { paths: [path] });
      fill(body, metaFile(r.files[0]));
    } catch (e) { fill(body, h("div", { class: "small errmsg" }, e.message)); if (btn) btn.disabled = false; }
  };
  const samples = () => {
    const more = f.groups.some(g => g.count > g.sample.length);
    fill(body, f.error ? h("div", { class: "small errmsg" }, f.error) : null,
      !f.count && !f.error ? h("div", { class: "small muted" }, "Nothing the app can see: no location, names, device or "
        + "dates in it.") : null,
      f.groups.map(g => h("div", { class: `metagroup${META_WARN.has(g.id) ? " warn" : ""}` }, h("h4", {}, g.title),
        h("ul", { class: "small" }, g.sample.map(it => h("li", {}, h("span", { class: "muted" }, it.key + ": "), it.value,
          it.member ? h("span", { class: "muted" }, ` (in ${it.member})`) : null)),
          g.count > g.sample.length ? h("li", { class: "muted" }, `and ${g.count - g.sample.length} more`) : null))),
      more ? h("div", { class: "orow" }, h("button", { class: "small", onclick: (e) => full(e.target) }, "Show everything")) : null);
  };
  const det = h("details", { class: "meta-det" }, h("summary", {}, h("span", { class: "meta-name" }, f.rel || f.name),
    h("span", { class: "meta-badges" }, badges)), body);
  let loaded = false;
  det.addEventListener("toggle", () => {
    if (!det.open || loaded) return;
    loaded = true;
    if (open) full(); else samples();
  });
  if (open && f.count) det.open = true;
  return h("div", { class: "meta-row" }, tick, det);
}

async function openMetadata(data, paths = []) {
  data = data || await toolsInfo();
  const mat2 = data.metadata.mat2.installed;
  let last = null;
  try { last = (await api("GET", "/api/tools/metadata/job")).job; } catch { /* none */ }
  const resume = last && (last.state === "running" || !paths.length);
  const chosen = resume ? [...(last.paths || [])] : [...paths];
  let read = null;                   // the last reading, while the list of what was chosen is unchanged
  let ticked = new Set();
  let filter = "all", query = "", busyNow = false;
  const chosenList = h("div", { class: "meta-chosen" });
  const out = h("div", { class: "meta-slot" });
  const hidden = h("input", { type: "checkbox", checked: !!(resume && last.hidden) });
  const light = h("input", { type: "checkbox" });
  const showBtn = h("button", { class: "primary" }, "Show what they carry");
  const cleanBtn = h("button", { disabled: !mat2 }, "Make clean copies");
  const typed = h("input", { type: "text", class: "path", spellcheck: "false", autocomplete: "off",
    placeholder: "or type a path and press Enter: ~/Pictures/Holiday, /home/you/photo.jpg" });
  const addFiles = h("button", { class: "small", onclick: () => pickInto(false) }, "Add files…");
  const addFolder = h("button", { class: "small", onclick: () => pickInto(true) }, "Add a folder…");

  const cleanLabel = () => {
    cleanBtn.textContent = read ? `Make clean copies of ${plural(ticked.size, "ticked file")}` : "Make clean copies";
  };
  const busy = (on) => {
    busyNow = on;
    for (const b of [showBtn, addFiles, addFolder, typed]) b.disabled = on;
    cleanBtn.disabled = on || !mat2;
    renderChosen();
  };
  const changed = () => { read = null; ticked = new Set(); fill(out); renderChosen(); cleanLabel(); };
  const addPaths = (ps) => {
    let n = 0;
    for (const p of ps) if (p && !chosen.includes(p)) { chosen.push(p); n++; }
    if (n) changed();
  };
  const renderChosen = () => fill(chosenList, chosen.length ? chosen.map((p, i) => h("div", { class: "meta-item" },
    h("code", {}, p), h("button", { class: "small ghost", title: "Take it off the list", disabled: busyNow,
      onclick: () => { chosen.splice(i, 1); changed(); } }, "✕")))
    : h("div", { class: "small muted" }, "Nothing chosen yet: add files, a folder (its subfolders too), or type a path."));
  const pickInto = async (folder) => {
    try {
      const r = await api("POST", "/api/tools/pick", folder ? { folder: true } : { multiple: true });
      if (r.unavailable) { toast("No file dialog here: type or paste the path.", "info"); typed.focus(); return; }
      addPaths(r.paths);
    } catch (e) { toast(e.message, "error"); }
  };
  typed.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const v = typed.value.trim();
    if (v) { addPaths([v]); typed.value = ""; }
  });

  const progress = (job) => {
    const stop = h("button", { class: "small", onclick: async () => {
      stop.disabled = true; stop.textContent = "Stopping…";
      try { await api("POST", "/api/tools/metadata/stop"); } catch (e) { toast(e.message, "error"); } } }, "Stop");
    return h("div", { class: "trim-progress" },
      h("div", { class: "orow" }, h("span", { class: "spinner on" }), h("b", {}, job.phase || "…"),
        job.total ? h("span", { class: "small muted" }, `${job.done} of ${job.total}`) : null,
        job.current ? h("span", { class: "small muted meta-current" }, job.current) : null),
      job.total ? h("div", { class: "obar" }, h("div", { style: `width: ${Math.round(100 * job.done / job.total)}%` })) : null,
      h("div", { class: "orow" }, stop));
  };
  const follow = async (job) => {
    busy(true);
    try {
      while (job && job.state === "running") {
        fill(out, progress(job));
        await new Promise(r => setTimeout(r, 400));
        if (!out.isConnected) return;          // closed: it goes on, and is shown when the dialog is opened again
        job = (await api("GET", "/api/tools/metadata/job")).job;
      }
    } catch (e) { fill(out, h("div", { class: "warnbox bad" }, e.message)); return; }
    finally { busy(false); }
    if (job) (job.kind === "read" ? takeRead : showCleaned)(job);
  };
  const start = async (kind, extra = {}) => {
    if (!chosen.length) { typed.focus(); return; }
    busy(true);
    try {
      const r = await api("POST", `/api/tools/metadata/${kind}`, { paths: chosen, hidden: hidden.checked, ...extra });
      follow(r.job);
    } catch (e) { busy(false); fill(out, h("div", { class: "warnbox bad" }, e.message)); }
  };

  const takeRead = (job) => {
    if (job.state === "failed") { fill(out, h("div", { class: "warnbox bad" }, job.error)); return; }
    if (job.state === "stopped" || !job.result) { fill(out, h("div", { class: "notebox info small" }, "Stopped. Nothing was changed.")); return; }
    read = { files: job.result.files, selection: job.selection };
    ticked = new Set(read.files.filter(f => f.cleanable !== false).map(f => f.path));
    filter = "all"; query = "";
    cleanLabel();
    renderRead();
  };
  const renderRead = () => {
    const files = read.files, sel = read.selection;
    const has = (f, g) => f.groups.some(x => x.id === g);
    const match = { all: () => true, location: f => has(f, "location"), people: f => has(f, "people"),
      device: f => has(f, "device"), none: f => !f.count && !f.error, uncleanable: f => f.cleanable === false,
      unread: f => !!f.error && !f.count };
    const counts = Object.fromEntries(META_FILTERS.map(([k]) => [k, files.filter(match[k]).length]));
    const q = query.toLowerCase();
    const visible = files.filter(f => match[filter](f) && (!q || f.rel.toLowerCase().includes(q)));
    const said = [counts.location && `${counts.location} say where they were made`, counts.people && `${counts.people} who made them`,
      counts.device && `${counts.device} the device`, counts.none && `${counts.none} carry nothing the app can see`]
      .filter(Boolean);
    const skipped = Object.entries(sel.skipped || {}).map(([k, n]) => plural(n, ...(META_SKIPPED[k] || [k, k])));
    const count = h("span", { class: "small muted" }, `${ticked.size} of ${files.length} ticked`);
    const tickAll = (on) => {
      for (const f of visible) if (f.cleanable !== false) on ? ticked.add(f.path) : ticked.delete(f.path);
      cleanLabel(); renderRead();
    };
    const search = h("input", { type: "search", class: "meta-search", placeholder: "Find by name", value: query, autocomplete: "off" });
    search.addEventListener("input", () => { query = search.value; const at = search.selectionStart; renderRead();
      const s2 = out.querySelector(".meta-search"); s2.focus(); s2.setSelectionRange(at, at); });
    const single = files.length <= 3;
    fill(out,
      h("p", { class: "small" }, h("b", {}, plural(files.length, "file")),
        sel.folders.length ? ` (in ${sel.folders.join(", ")}, subfolders included)` : "",
        said.length ? `: ${said.join(", ")}.` : "."),
      sel.truncated ? h("div", { class: "warnbox small" }, `Only the first ${sel.limit} files are listed and can be cleaned. `
        + "Choose the subfolders one at a time for the rest.") : null,
      skipped.length ? h("div", { class: "small muted" }, `Left out: ${skipped.join(", ")}.`,
        sel.skipped?.hidden && !hidden.checked ? " Tick “Include hidden files” to read those too." : "") : null,
      single ? null : h("div", { class: "meta-filters" }, META_FILTERS.filter(([k]) => k === "all" || counts[k]).map(([k, label]) =>
        h("button", { class: `chip${filter === k ? " on" : ""}`, onclick: () => { filter = k; renderRead(); } }, `${label} ${counts[k]}`)),
        search),
      mat2 && !single ? h("div", { class: "orow" }, h("button", { class: "small ghost", onclick: () => tickAll(true) },
        filter === "all" && !q ? "Tick all" : "Tick these"),
        h("button", { class: "small ghost", onclick: () => tickAll(false) }, filter === "all" && !q ? "Untick all" : "Untick these"),
        count) : null,
      visible.length ? pagedList(visible, f => metaRow(f, { open: single, tick: mat2 ? h("input", { type: "checkbox",
        checked: ticked.has(f.path), disabled: f.cleanable === false, title: f.cleanable === false ? "mat2 doesn't clean this kind of file" : "Clean this one",
        onchange: (e) => { e.target.checked ? ticked.add(f.path) : ticked.delete(f.path); count.textContent = `${ticked.size} of ${files.length} ticked`; cleanLabel(); } }) : null }))
        : h("div", { class: "small muted" }, "None."));
  };

  const showCleaned = (job) => {
    if (job.state === "failed") { fill(out, h("div", { class: "warnbox bad" }, job.error)); return; }
    const res = job.result;
    if (!res) { fill(out, h("div", { class: "notebox info small" }, "Stopped before anything was cleaned.")); return; }
    const ok = res.results.filter(r => r.ok), failed = res.results.filter(r => !r.ok);
    const leaky = ok.filter(r => r.remaining?.groups.some(g => META_WARN.has(g.id)));
    const rest = ok.filter(r => r.remaining?.count && !leaky.includes(r));
    const open = (folder) => h("button", { class: "small", onclick: async () => {
      try { await api("POST", "/api/tools/metadata/open", { folder }); } catch (e) { toast(e.message, "error"); } } }, "Open the folder");
    const singles = ok.filter(r => !r.root);
    read = null; ticked = new Set(); cleanLabel();
    fill(out,
      h("div", { class: `notebox ${failed.length ? "risk" : "info"} small` }, job.state === "stopped" ? "Stopped. " : "",
        `${plural(ok.length, "clean copy", "clean copies")} made`, failed.length ? `; ${failed.length} couldn't be cleaned (listed below)` : "",
        ". The originals weren't changed."),
      res.folders.map(f => h("div", { class: "orow small" }, f.output ? [h("code", {}, f.folder), " → ", h("code", {}, f.output),
        open(f.output_path)] : `Nothing in ${f.folder} could be cleaned, so no cleaned folder was made.`)),
      singles.length ? h("div", { class: "small" }, singles.length === 1 ? null : h("div", {}, "Beside the files chosen on their own:"),
        singles.slice(0, 50).map(r => h("div", { class: "orow" }, h("code", {}, r.name), " → ", h("code", {}, r.output_name),
          open(r.path.slice(0, r.path.lastIndexOf("/")) || "/")))) : null,
      leaky.length ? h("div", { class: "warnbox small" }, `${plural(leaky.length, "cleaned copy still says", "cleaned copies still say")} `
        + "where it was made, who made it or the device: mat2 couldn't remove all of it. Look before you share them.",
        pagedList(leaky, r => metaRow(r.remaining, { path: r.output }))) : null,
      rest.length ? h("details", {}, h("summary", { class: "small" }, `What is still in ${plural(rest.length, "other copy", "other copies")}`
        + " (mostly what any file of its kind has: its format, size, colours)"),
        pagedList(rest, r => metaRow(r.remaining, { path: r.output }))) : null,
      failed.length ? h("div", {}, h("h4", {}, "Couldn't be cleaned (no copy made)"),
        pagedList(failed, r => h("div", { class: "meta-row small" }, h("code", {}, r.rel), " ", h("span", { class: "errmsg" }, r.message)))) : null);
  };

  showBtn.addEventListener("click", () => start("read"));
  cleanBtn.addEventListener("click", async () => {
    if (read && !ticked.size) { toast("Tick at least one file to clean.", "info"); return; }
    start("clean", { files: read ? [...ticked] : null, lightweight: light.checked });
  });
  hidden.addEventListener("change", () => { if (read) changed(); });

  const need = !mat2;
  const body = h("div", { class: "metadata" },
    h("p", { class: "small" }, "Photos carry where they were taken and the camera or phone; documents carry who wrote them "
      + "and with what. Choose files, or whole folders (their subfolders too), see what each one carries, and make clean "
      + "copies of the ones you tick. The originals aren't changed: a file chosen on its own gets its clean copy beside it "
      + "(photo.jpg → photo.cleaned.jpg); the files of a folder go into a new folder beside it, “Holiday (cleaned)”, with "
      + "the same subfolders. A file mat2 can't clean gets no copy there, so nothing in it passes for clean."),
    need ? h("div", { class: "warnbox" }, "Making clean copies needs mat2"
      + (data.metadata.exiftool.installed ? " (exiftool, installed, can only show what files carry)." : "."),
      data.metadata.mat2.install ? commandBlock([data.metadata.mat2.install]) : null) : null,
    chosenList,
    h("div", { class: "orow" }, data.can_pick ? [addFiles, addFolder] : null, typed),
    h("div", { class: "gactions" }, showBtn, cleanBtn,
      h("label", { class: "check small", title: "Files whose names start with a dot, and hidden folders" }, hidden,
        "Include hidden files"),
      h("label", { class: "check small", title: "PDFs only: the normal mode turns every page into an image, so text can't be "
        + "selected any more; lightweight keeps the text and removes less" }, light, "Lightweight (keep PDF text)")),
    h("p", { class: "muted small" }, "Only hidden details are removed: what you can see in the file (faces, text, a reflection, "
      + "a street sign) stays, and so do file names. Deleting the original afterwards doesn't erase it from the disk; "
      + "encryption is what protects it."),
    out);
  modal({ title: "Remove metadata", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
  renderChosen();
  if (resume) {
    if (last.state === "running") follow(last);
    else if (last.kind === "read") takeRead(last);
    else showCleaned(last);
  } else if (paths.length) start("read");
}

function metaFile(f) {
  return h("div", { class: "metafile" },
    h("div", { class: "orow" }, h("b", {}, f.name), h("span", { class: "small muted" },
      f.count ? `${plural(f.count, "item")} (read with ${f.tool})` : f.error ? "" : `Nothing found (read with ${f.tool})`)),
    f.error ? h("div", { class: "small errmsg" }, f.error) : null,
    f.groups.map(g => h("div", { class: `metagroup${META_WARN.has(g.id) ? " warn" : ""}` },
      h("h4", {}, g.title),
      h("ul", { class: "small" }, g.items.slice(0, 40).map(it => h("li", {}, h("span", { class: "muted" }, it.key + ": "), it.value,
        it.member ? h("span", { class: "muted" }, ` (in ${it.member})`) : null)),
        g.items.length > 40 ? h("li", { class: "muted" }, `and ${g.items.length - 40} more`) : null))));
}

// what opening a RAM disk runs as root (the helper does the same through system calls), following the
// size and the programs box as they change
function ramdiskOpenCommands(rd, sizeInput, noexec) {
  const slot = h("div", {});
  const show = () => {
    const mb = parseInt(sizeInput.value, 10);
    const cmds = ((noexec ? noexec() : true) ? rd.commands?.open : rd.commands?.open_exec) || [];
    fill(slot, cmds.length ? [h("div", { class: "muted small" }, "Opening runs, as root:"),
      commandBlock(cmds.map(c => Number.isFinite(mb) ? c.replace(/size=\d+M/, `size=${mb}M`) : c))] : null);
  };
  sizeInput.addEventListener("input", show);
  sizeInput.addEventListener("change", show);
  show();
  return { slot, show };
}

function ramdiskPanel(rd, reload) {
  const box = h("div", { class: "ramdisk" });
  const notes = rd.notes.map(n => h("div", { class: "notebox risk small" }, n));
  if (rd.other) {
    return fill(box, h("div", { class: "warnbox" }, `Something else (${rd.other}) is mounted on ~/RAMDisk, so the RAM disk can't be used there.`));
  }
  if (rd.open) {
    const pct = rd.total ? Math.round(rd.used / rd.total * 100) : 0;
    return fill(box,
      h("div", { class: "orow" }, h("span", { class: "badge st-pass" }, "open"), h("code", {}, rd.path),
        h("span", { class: "small muted" }, `${fmtSize(rd.used)} of ${fmtSize(rd.total)} used (${pct}%), ${plural(rd.files, "file")}`)),
      h("div", { class: "small muted" }, (rd.noexec ? "Programs can't run from it. " : "Programs can run from it. ")
        + (rd.noswap ? "Kept out of swap." : "This kernel can't keep it out of swap.")),
      notes,
      h("div", { class: "orow" },
        h("button", { class: "small", onclick: async () => { try { await api("POST", "/api/tools/ramdisk/show"); } catch (e) { toast(e.message, "error"); } } }, "Show in the file manager"),
        h("button", { class: "small danger", onclick: () => closeRamdisk(rd, reload) }, "Close and overwrite…")));
  }
  const size = h("input", { type: "number", class: "num", min: 50, max: rd.max_mb, value: Math.min(rd.default_mb, rd.max_mb) });
  const noexec = h("input", { type: "checkbox", checked: true });
  const cmds = ramdiskOpenCommands(rd, size, () => noexec.checked);
  noexec.addEventListener("change", cmds.show);
  const open = h("button", { class: "small primary" }, "Open");
  open.addEventListener("click", async () => {
    const mb = parseInt(size.value, 10);
    if (!(mb >= 50 && mb <= rd.max_mb)) { toast(`Choose a size from 50 to ${rd.max_mb} MB.`, "error"); return; }
    open.disabled = true;
    open.textContent = S.adminActive ? "Opening…" : "Waiting for authorization…";
    try {
      const r = await api("POST", "/api/tools/ramdisk/open", { size_mb: mb, noexec: noexec.checked });
      S.adminActive = !!r.admin_active; renderTop();
      toast("~/RAMDisk is open: what you put in it stays in memory.", "ok");
      await reload();
    } catch (e) { toast(e.message, "error", 10000); open.disabled = false; open.textContent = "Open"; }
  });
  return fill(box,
    h("div", { class: "orow" }, h("span", { class: "badge" }, "closed"),
      h("label", { class: "small" }, "Size ", size, " MB"),
      h("label", { class: "check small", title: "Safer: a program or script saved in it can't be started from there. Turn it off "
        + "to run something from it, such as a portable browser." }, noexec, "Programs can't run from it"),
      open),
    h("div", { class: "small muted" }, "It takes memory only for what is in it, up to the size. Opening needs administrator "
      + "access. Closing it here overwrites and deletes everything in it; restarting the computer ends it too (logging out "
      + "doesn't)."),
    leftoverNote(rd, reload, "tool"),
    cmds.slot,
    notes);
}

// The empty, read-only folder an open left when a restart ended the mount: opening uses it again, and closing puts it
// back; without opening, this puts it back as it was (as you: no password).
function leftoverNote(rd, reload, disk) {
  if (!rd.leftover) return null;
  const btn = h("button", { class: "small" }, "Put the folder back");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      const r = await api("POST", "/api/tools/ramdisk/tidy", { disk });
      toast(r.done, "ok");
      await reload();
    } catch (e) { toast(e.message, "error", 10000); btn.disabled = false; }
  });
  return h("div", { class: "small muted" }, `An empty, read-only ${rd.path} folder is left from before a restart, which `
    + "ended the RAM disk. Opening uses it again; or put it back as it was before (removed if the app made it).", " ", btn);
}

function closeRamdisk(rd, reload) {
  const browserDisk = rd.name === "TempBrowser";
  modal({ title: `Close ${rd.path || "~/RAMDisk"}?`, body: [
    h("p", {}, `Every file in ${rd.path || "~/RAMDisk"} (${plural(rd.files, "file")}) is overwritten with zeros where it lies in memory, `
      + "deleted, and the RAM disk is unmounted. This can't be undone."
      + (browserDisk ? " The browser goes with it: downloading it again takes a few minutes." : "")),
    h("div", { class: "small" }, h("b", {}, "What this doesn't reach: "), "copies other programs made of these files (an "
      + "editor's autosave, the clipboard, a browser's cache), thumbnails and the recent-files list (see the checks for "
      + "them), the files' names" + (rd.noswap ? "" : ", and anything swapped to disk") + "."),
    h("div", { class: "small" }, h("b", {}, "The system's log: "), "the app keeps systemd from noting there that the RAM "
      + "disk was opened or closed, but the log, kept on the disk, has a line each time administrator access is given to "
      + "the app (when, not what for)."),
    h("p", { class: "muted small" }, "If a program still has a file in it open, nothing is closed: the app says which "
      + "program to close first."),
    rd.commands?.close?.length ? h("div", {}, h("div", { class: "muted small" }, "After overwriting and deleting the files (as "
      + "you), closing runs, as root:"), commandBlock(rd.commands.close),
      h("div", { class: "muted small" }, "and then removes the empty folder underneath, or puts its permissions back if it "
        + "was there before.")) : null,
  ], buttons: [{ label: "Keep it open" }, { label: "Close and overwrite", kind: "danger", onclick: async (close, el) => {
    el.disabled = true;
    el.textContent = "Overwriting…";
    try {
      const r = await api("POST", "/api/tools/ramdisk/close", { disk: browserDisk ? "browser" : "tool" });
      S.adminActive = !!r.admin_active; renderTop();
      close();
      const w = r.wiped;
      toast(w ? `Closed: ${plural(w.files, "file")} (${fmtSize(w.bytes)}) overwritten and deleted.`
        + (w.failed.length ? ` ${w.failed.length} couldn't be overwritten.` : "") : "Closed.", "ok", 10000);
      await reload();
    } catch (e) { close(); toast(e.message, "error", 12000); await reload(); }
  } }] });
}

// ------------------------------------------------------------------ Before you hand over a drive
// Removable and external drives only; every file to delete is listed, and deleting is confirmed.
// Deleting doesn't erase (rule 8): the page says so before anything else.

const NOT_ERASED = "Deleting doesn't erase. On a USB stick, an SD card or a disk, deleted files (these, and anything deleted "
  + "from the drive before) can usually be recovered with free tools. If what was on it matters, erase the whole drive "
  + "(Retire a drive) instead, or keep the drive encrypted from the start next time.";

async function openHandover() {
  const body = h("div", { class: "handover" });
  let chosen = null;
  const m = modal({ title: "Before you hand over a drive", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
  const start = async () => {
    let d;
    try { d = await api("GET", "/api/tools/handover"); } catch (e) { fill(body, h("div", { class: "warnbox bad" }, e.message)); return; }
    const usable = d.drives.filter(x => !x.blocked);
    if (!usable.some(x => x.mount === chosen)) chosen = usable[0]?.mount || null;
    const look = h("button", { class: "primary", disabled: !chosen }, "Look at the drive");
    look.addEventListener("click", async () => {
      look.disabled = true; look.textContent = "Looking…";
      try { fill(body, handoverPlan(await api("POST", "/api/tools/handover/plan", { mount: chosen }), start, m.close)); }
      catch (e) { toast(e.message, "error"); look.disabled = false; look.textContent = "Look at the drive"; }
    });
    fill(body,
      h("p", {}, "A drive you give away carries more than the files you see: its trash, thumbnails of pictures, and what "
        + "other computers left on it. This lists them, every file, and deletes them when you confirm."),
      h("div", { class: "warnbox" }, NOT_ERASED),
      h("h4", {}, "Drive"),
      d.drives.length ? d.drives.map(x => h("div", { class: "trim-target" },
        h("label", { class: "check" }, h("input", { type: "radio", name: "handover-drive", checked: x.mount === chosen, disabled: !!x.blocked,
          onchange: () => { chosen = x.mount; look.disabled = false; } }),
          h("b", {}, x.label || x.mount), h("span", { class: "small muted" }, ` ${x.mount}, ${x.fstype || "unknown filesystem"}`
            + (x.transport ? `, ${x.transport.toUpperCase()}` : ""))),
        x.blocked ? h("div", { class: "small muted" }, x.blocked) : null))
        : h("div", { class: "notebox small" }, "No removable or external drive is mounted. Plug it in and open it in the file "
          + "manager (that mounts it), then look again.", h("div", { class: "orow" }, h("button", { class: "small", onclick: start }, "Look again"))),
      h("div", { class: "orow" }, look));
  };
  await start();
}

function handoverPlan(p, back, closeAll) {
  const confirm = h("input", { type: "checkbox" });
  const gone = h("ul", { class: "small" });                // what the chosen fixes delete, each named
  const go = h("button", { class: "danger", disabled: true }, `Delete ${plural(p.files, "file")}`);
  const out = h("div", {});
  confirm.addEventListener("change", () => { go.disabled = !confirm.checked; });
  go.addEventListener("click", async () => {
    go.disabled = true; go.textContent = "Deleting…";
    try {
      const r = await api("POST", "/api/tools/handover/clean", { plan_id: p.plan_id, confirm: true });
      fill(out, h("div", { class: "verdict ok" }, h("div", { class: "vtitle" }, `Deleted ${plural(r.deleted, "file")}`
        + (r.skipped ? `; ${r.skipped} couldn't be (another account's, or gone already)` : "")),
        h("p", { class: "small" }, "Eject the drive before unplugging it, so everything is written."),
        h("p", { class: "small" }, NOT_ERASED)));
      go.remove(); confirm.closest("label").remove();
    } catch (e) { toast(e.message, "error", 10000); go.disabled = false; go.textContent = `Delete ${plural(p.files, "file")}`; }
  });
  const name = p.drive.label || p.drive.mount;
  const group = (g) => h("div", { class: "hgroup" },
    h("div", { class: "orow" }, h("b", {}, g.title), h("span", { class: "small muted" }, `${plural(g.count, "file")}, ${fmtSize(g.bytes)}`)),
    h("div", { class: "small" }, g.text),
    h("details", {}, h("summary", { class: "small" }, "Every file"),
      h("ul", { class: "small files" },
        g.folders.map(f => h("li", {}, h("code", {}, f + "/"), h("span", { class: "muted" }, " (the folder, with everything in it)"))),
        g.files.map(f => h("li", {}, h("code", {}, f))),
        g.more ? h("li", { class: "muted" }, `and ${g.more} more`) : null)));
  return [
    h("div", { class: "orow" }, h("button", { class: "small ghost", onclick: back }, "← Drives"), h("b", {}, name),
      h("span", { class: "small muted" }, p.drive.mount)),
    p.groups.length ? h("div", { class: "verdict warn" }, h("div", { class: "vtitle" },
      `${name} carries ${plural(p.files, "file")} (${fmtSize(p.bytes)}) besides yours`),
      h("p", { class: "small" }, "Nothing has been deleted yet. Your own files aren't touched: only what is listed below."))
      : h("div", { class: "verdict ok" }, h("div", { class: "vtitle" }, "Nothing to clean"),
        h("p", { class: "small" }, "The drive carries none of the leftovers the app knows about.")),
    p.truncated ? h("div", { class: "notebox small" }, "The drive holds a great many files; only the first 200,000 were looked at.") : null,
    p.groups.map(group),
    p.in_use.length ? h("div", { class: "warnbox bad" }, `Close ${p.in_use.join(", ")} first: `
      + `${p.in_use.length === 1 ? "it is" : "they are"} using files that would be deleted.`) : null,
    p.groups.length ? [h("div", { class: "warnbox" }, NOT_ERASED),
      h("label", { class: "check confirm" }, confirm, "I understand that these files are deleted for good, and that deleting "
        + "doesn't erase them from the drive."),
      h("div", { class: "gactions" }, go)] : null,
    out,
    p.media_count ? h("div", { class: "notebox small" }, `${plural(p.media_count, "photo, video or document", "photos, videos or documents")} `
      + "on the drive can carry where they were made and by whom.",
      h("div", { class: "orow" }, h("button", { class: "small", onclick: () => openMetadata(null, p.media) },
        p.media_count > p.media.length ? `Show what the first ${p.media.length} carry…` : "Show what they carry…"))) : null,
  ];
}

// ------------------------------------------------------------------ Retire a drive
// Commands only, run by the user: shown once they type the drive's name. The app erases nothing.

const RETIRE_WHAT = {
  hdd: "A hard disk: one full overwrite erases it, apart from sectors it has set aside after errors; ATA Secure Erase reaches those too.",
  ssd: "An SSD: overwriting doesn't reach the blocks it keeps out of sight. Its own erase command helps but can't be checked; "
    + "destroying its keys works if it was encrypted from the start; otherwise, destroy it if it held secrets.",
  nvme: "An NVMe SSD: overwriting doesn't reach the blocks it keeps out of sight. Its own sanitize command helps but can't be "
    + "checked; destroying its keys works if it was encrypted from the start; otherwise, destroy it if it held secrets.",
  emmc: "Built-in flash: like an SSD, its own erase can't be checked; destroying its keys works if it was encrypted from the start.",
  flash: "A USB stick or card reader: there is no reliable erase. Destroying its keys works if it was encrypted from the start; "
    + "otherwise, destroy it if it held secrets.",
  card: "An SD card: there is no reliable erase. Destroying its keys works if it was encrypted from the start; otherwise, destroy it "
    + "if it held secrets.",
  "usb-disk": "An external disk: through USB the app can't tell whether it is a hard disk or an SSD. Say which below if you know.",
  virtual: "A virtual disk: erasing it from inside says nothing about where the host keeps it. Delete its image on the host.",
  unknown: "The app can't tell what kind of drive this is: treat it as flash.",
};

async function openRetire() {
  const body = h("div", { class: "retire" });
  let data, chosen = null;
  const answers = { kind: "", from_start: false };
  const m = modal({ title: "Retire a drive", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
  const load = async () => { data = await api("GET", "/api/tools/retire"); };
  const render = () => {
    const d = data.drives.find(x => x.name === chosen);
    const rows = data.drives.map(x => h("div", { class: "trim-target" },
      h("label", { class: "check" }, h("input", { type: "radio", name: "retire-drive", checked: x.name === chosen, disabled: !!x.blocked,
        onchange: () => { chosen = x.name; answers.kind = ""; answers.from_start = false; render(); } }),
        h("b", {}, x.model || x.name), h("span", { class: "small muted" }, ` ${x.path}, ${fmtSize(x.size)}, ${x.kind_title}`
          + (x.serial ? `, serial ${x.serial}` : ""))),
      x.blocked ? h("div", { class: "small muted" }, x.blocked) : null));
    fill(body,
      h("p", {}, "Before a drive is sold, given away or thrown out. What really erases a drive depends on what kind it is, "
        + "and drives' own erase commands can't be checked: the steps say what each one does and doesn't do. You run the "
        + "commands yourself; the app erases nothing."),
      h("h4", {}, "Drive"), rows,
      d ? retireDrive(d, data, answers, render, m) : null);
  };
  try { await load(); } catch (e) { fill(body, h("div", { class: "warnbox bad" }, e.message)); return; }
  render();
}

function retireDrive(d, data, answers, render, m) {
  const facts = data.facts[d.name];
  const out = h("div", { class: "guide" });
  const typed = h("input", { type: "text", class: "path", placeholder: d.name, spellcheck: "false", autocomplete: "off" });
  const show = h("button", { class: "primary" }, "Show the commands");
  show.addEventListener("click", async () => {
    try {
      const r = await api("POST", "/api/tools/retire/guide", { disk: d.name, typed: typed.value, kind: answers.kind, from_start: answers.from_start });
      const g = r.guide;
      fill(out, h("p", {}, g.intro), g.steps.map((st, i) => guideStep(st, i + 1, async () => {})));
    } catch (e) { fill(out, h("div", { class: "warnbox bad" }, e.message)); }
  });
  const readFacts = h("button", { class: "small" }, facts ? "Read again" : "Read what the drive says (administrator access)");
  readFacts.addEventListener("click", async () => {
    readFacts.disabled = true; readFacts.textContent = S.adminActive ? "Reading…" : "Waiting for authorization…";
    try {
      const r = await api("POST", "/api/tools/retire/facts", { disk: d.name });
      data.facts[d.name] = r.facts; S.adminActive = !!r.admin_active; renderTop(); render();
    } catch (e) { toast(e.message, "error", 10000); readFacts.disabled = false; readFacts.textContent = "Read what the drive says (administrator access)"; }
  });
  const yes = (v) => v === true ? "yes" : v === false ? "no" : "unknown";
  const ata = facts?.ata, nv = facts?.nvme;
  return h("div", { class: "retire-drive" },
    h("div", { class: "notebox small" }, RETIRE_WHAT[d.kind] || RETIRE_WHAT.unknown),
    d.smr ? h("div", { class: "warnbox" }, "This disk is listed as drive-managed SMR (or says it is zoned): even an overwrite may "
      + "leave old copies. Prefer its own ATA Secure Erase; destroy it if it held secrets.") : null,
    d.mounted.length || d.open_crypt.length ? h("div", { class: "warnbox" }, `In use now: ${[...d.mounted, ...d.open_crypt].join(", ")}. `
      + "The first step unmounts it.") : null,
    ["hdd", "ssd", "usb-disk", "nvme", "unknown"].includes(d.kind) ? h("div", { class: "orow" }, readFacts,
      facts ? h("span", { class: "small muted" }, facts.source ? `From ${facts.source}.` : facts.notes.join("; ")) : null) : null,
    ata ? h("ul", { class: "small" },
      h("li", {}, `ATA security: supported ${yes(ata.supported)}, frozen ${yes(ata.frozen)}, enhanced erase ${yes(ata.enhanced)}`
        + (ata.erase_minutes ? `, about ${ata.enhanced && ata.enhanced_minutes ? ata.enhanced_minutes : ata.erase_minutes} min` : "")),
      h("li", {}, `Sanitize: ${ata.sanitize.supported ? ["crypto", "block", "overwrite"].filter(k => ata.sanitize[k]).join(", ") || "supported" : "no"}`),
      ata.frozen ? h("li", { class: "errmsg" }, "Frozen: suspend and wake the computer, then read again.") : null) : null,
    nv ? h("ul", { class: "small" },
      h("li", {}, `Sanitize: ${["crypto", "block", "overwrite"].filter(k => nv.sanitize[k]).join(", ") || "no"}`),
      h("li", {}, `Format with secure erase: ${nv.format ? (nv.format_crypto ? "yes, including crypto erase" : "yes") : "no"}`)) : null,
    d.kind === "usb-disk" ? h("label", {}, h("span", { class: "small" }, "What is it? "),
      h("select", { onchange: (e) => { answers.kind = e.target.value; } },
        [["", "Not sure"], ["hdd", "A hard disk (it spins)"], ["ssd", "An SSD"]].map(([v, l]) => h("option", { value: v, selected: answers.kind === v }, l)))) : null,
    d.luks.length ? h("label", { class: "check small" }, h("input", { type: "checkbox", checked: answers.from_start,
      onchange: (e) => { answers.from_start = e.target.checked; } }),
      `Everything on it was encrypted (${d.luks.join(", ")}) from the day it was first used`) : null,
    h("div", { class: "orow" }, h("span", { class: "small" }, `Type the drive's name (${d.name}) to show the commands:`), typed, show),
    out);
}

// ------------------------------------------------------------------ Before you travel
// A checklist made of the scan's own checks, with why each matters on a trip; no detection of its own.

// the button a check's row offers (Fix…, Guide…, Set up…, Clean…), and How to… for advice with steps
function fixButtons(spec, r) {
  return [
    r?.fixable ? h("button", { class: "small primary", onclick: () => hasGuide(spec) ? openGuide(spec) : openFix(spec) },
      spec.tier === "feature" ? "Set up…" : spec.tier === "guided" ? "Guide…" : (spec.kind === "hygiene" ? "Clean…" : "Fix…")) : null,
    r?.how_to ? h("button", { class: "small", onclick: () => openGuide(spec) }, "How to…") : null,
  ];
}

const TRAVEL_STATE = {
  done: ["st-pass", "done"], todo: ["st-fail", "to do"], accepted: ["accepted", "accepted"], na: ["st-not_applicable", "doesn't apply"],
  unknown: ["st-unknown", "couldn't check"], unscanned: ["st-unscanned", "not scanned"],
};

// a finding the user accepted isn't "to do" (nor counted), as in the list: it says accepted, until its severity rises
function travelState(r, id) {
  if (!r) return "unscanned";
  if (["unknown", "error"].includes(r.status)) return "unknown";
  if (r.status === "not_applicable" || !r.effective_severity) return r.status === "pass" ? "done" : "na";
  if (!["fail", "warn"].includes(r.status)) return "done";
  return acceptedHidden(id) ? "accepted" : "todo";
}
const ACCEPTED_HERE = "You accepted this risk, so it isn't counted here. Un-accept it in the list to deal with it.";

async function openTravel() {
  const body = h("div", { class: "travel" });
  let data;
  const render = () => {
    const rows = data.items.map(it => {
      const spec = S.state.catalogue.find(s => s.id === it.id);
      if (!spec) return null;
      const r = S.report?.results?.[it.id];
      const st = travelState(r, it.id);
      return h("div", { class: `trow ${st}` },
        h("span", { class: `badge ${TRAVEL_STATE[st][0]}` }, TRAVEL_STATE[st][1]),
        h("div", { class: "titles" },
          h("b", {}, spec.title),
          r?.summary ? h("div", { class: "small muted" }, r.summary) : null,
          h("div", { class: "small" }, it.why),
          st === "accepted" ? h("div", { class: "small muted" }, ACCEPTED_HERE) : null,
          r?.needs_admin ? h("div", { class: "small muted" }, "Needs a scan with administrator access to check.") : null),
        h("div", { class: "orow" }, st === "todo" ? fixButtons(spec, r) : null,
          h("button", { class: "small ghost", onclick: () => { m.close(); reveal(it.id); } }, "In the list")));
    });
    const counted = data.items.map(it => travelState(S.report?.results?.[it.id], it.id));
    const disks = data.ramdisks || [data.ramdisk];
    const todo = counted.filter(x => x === "todo").length + disks.filter(d => d.open).length;
    fill(body,
      h("p", {}, data.intro),
      !S.report ? h("div", { class: "warnbox" }, "Scan first: the checklist shows what the scan found on this machine.",
        h("div", { class: "orow" }, h("button", { class: "small primary", onclick: async () => { await scan(); render(); } }, "Scan"))) :
        h("div", { class: `verdict ${todo ? "warn" : "ok"}` }, h("div", { class: "vtitle" },
          todo ? `${plural(todo, "thing")} to deal with before you go` : "Nothing on the list needs doing"),
          h("p", { class: "small" }, `From the scan of ${new Date(S.report.started * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}. `
            + "Scan again after changing something yourself.")),
      h("div", { class: "tlist" }, rows,
        // the browser's RAM disk only when it is open: most people never use it
        disks.filter(rd => rd.name !== "TempBrowser" || rd.open).map(rd => h("div", { class: `trow ${rd.open ? "todo" : "done"}` },
          h("span", { class: `badge ${rd.open ? "st-fail" : "st-pass"}` }, rd.open ? "to do" : "done"),
          h("div", { class: "titles" }, h("b", {}, rd.name === "TempBrowser" ? "The browser's RAM disk is closed" : "The RAM disk is closed"),
            h("div", { class: "small" }, `What is in ${rd.path || "~/RAMDisk"} stays in memory while the laptop is on or asleep: close it before you go.`)),
          h("div", { class: "orow" }, rd.open ? h("button", { class: "small danger", onclick: () => closeRamdisk(rd, reload) }, "Close and overwrite…") : null)))),
      h("h4", {}, "Also"),
      h("ul", { class: "small" }, data.advice.map(a => h("li", {}, a))));
  };
  const reload = async () => {
    try { data = await api("GET", "/api/tools/travel"); render(); } catch (e) { toast(e.message, "error"); }
  };
  try { data = await api("GET", "/api/tools/travel"); } catch (e) { toast(e.message, "error"); return; }
  const m = modal({ title: "Before you travel", wide: true, body,
    buttons: [{ label: "Check again", onclick: () => reload() }, { label: "Close", kind: "primary" }] });
  render();
}

// ------------------------------------------------------------------ Presentation mode
// Notification banners and clipboard history off together for screen sharing, back together after.
// Not a fix: it isn't in History; the top bar shows it while it is on, and quitting turns it off.

function presentationCard(reload) {
  const on = !!S.presentation?.on;
  const lapsed = on && (S.presentation.lapsed || []).length > 0;
  return h("div", {},                     // that it is on, and since when, is the tile's status (toolStatus)
    h("div", { class: "orow" },
      lapsed ? h("button", { class: "small primary", onclick: () => presentationRenew(reload) }, "Turn Do Not Disturb on again") : null,
      h("button", { class: `small ${on ? "" : "primary"}`, onclick: () => on ? presentationOff(reload) : openPresentation(reload) },
        on ? "Turn off" : "Turn on…"),
      on ? h("button", { class: "small ghost", onclick: presentationChanged }, "What it changed…") : null),
    lapsed ? h("div", { class: "notebox small" }, PRESENTATION_LAPSED) : null);
}

// what Presentation mode changed, the commands that did it, and how each goes back by hand (it isn't a fix:
// nothing of it is in History, so this is where to see it)
async function presentationChanged() {
  let d;
  try { d = await api("GET", "/api/tools/presentation"); } catch (e) { toast(e.message, "error"); return; }
  modal({ title: "What Presentation mode changed", wide: true, body: [
    d.changed.length ? h("ul", { class: "small" }, d.changed.map(c => h("li", {}, c)))
      : h("p", { class: "small muted" }, "Nothing: banners were already off and no clipboard history was recording."),
    d.ran?.length ? [h("div", { class: "muted small" }, "Ran:"), commandBlock(d.ran)] : null,
    d.undo.length ? [h("div", { class: "muted small" }, "To put each back by hand (Turn off does this):"), commandBlock(d.undo)] : null,
    h("p", { class: "small muted" }, "Turning it off puts everything back; nothing of this is kept in History.")],
    buttons: [{ label: "Close", kind: "primary" }] });
}

const PRESENTATION_LAPSED = "Do Not Disturb ended when the app stopped (it lasts only while the app runs), so notifications "
  + "show again although Presentation mode is on. Turn it on again before you share your screen.";

async function presentationRenew(reload) {
  try {
    const r = await api("POST", "/api/tools/presentation/renew");
    S.presentation = { on: r.on, since: r.since, lapsed: r.lapsed }; renderTop();
    toast("Do Not Disturb is on again.", "ok");
    reload?.();
  } catch (e) { toast(e.message, "error", 10000); }
}

async function openPresentation(reload) {
  let d;
  try { d = await api("GET", "/api/tools/presentation"); } catch (e) { toast(e.message, "error"); return; }
  if (d.on) { S.presentation = { on: true, since: d.since, lapsed: d.lapsed }; renderTop(); reload?.(); return; }
  modal({ title: "Presentation mode", wide: true, body: [
    h("p", {}, "Before you share your screen: notification banners and clipboard history are turned off together, so a message "
      + "or something you copied earlier doesn't pop up in front of everyone. Turning it off puts each one back as it was."),
    d.plan.length ? h("div", {}, h("h4", {}, `On this desktop (${d.desktop})`), h("ul", { class: "steps" }, d.plan.map(c =>
      h("li", { class: "step undo" }, h("span", { class: "tag" }, "put back after"), h("b", {}, c.what), " ", h("code", {}, c.text)))))
      : h("div", { class: "notebox small" }, "Nothing needs changing here now: banners are already off and no clipboard history "
        + "the app knows is recording. It can still be turned on, to remember to turn things back."),
    d.notes.map(n => h("div", { class: "notebox small" }, n)),
    h("p", { class: "muted small" }, "It isn't a fix, so it isn't in History. The top bar shows it while it is on; quitting the app turns it off."),
  ], buttons: [{ label: "Cancel" }, { label: "Turn on", kind: "primary", onclick: async (close, el) => {
    el.disabled = true;
    try {
      const r = await api("POST", "/api/tools/presentation/on");
      S.presentation = { on: true, since: r.since, lapsed: r.lapsed }; renderTop();
      close();
      toast("Presentation mode is on: notification banners and clipboard history are off.", "ok");
      reload?.();
    } catch (e) { el.disabled = false; toast(e.message, "error", 10000); }
  } }] });
}

async function presentationOff(reload) {
  try {
    const r = await api("POST", "/api/tools/presentation/off");
    S.presentation = { on: r.on, since: r.since, lapsed: r.lapsed }; renderTop();
    if (r.failed.length) toast(`Not everything could be put back: ${r.failed.join("; ")}. Presentation mode stays on, to try again.`, "error", 12000);
    else toast(r.kept.length ? `Presentation mode is off, and the rest is back as it was. ${r.kept.join(" ")}`
      : "Presentation mode is off: everything is back as it was.", "ok", 9000);
    reload?.();
  } catch (e) { toast(e.message, "error"); }
}

// ------------------------------------------------------------------ camera and microphone
// A live view: asked again every few seconds while it is open. Only looks; never touches the programs.

const INUSE_WHAT = { camera: "Camera", microphone: "Microphone", screen: "Screen", playback: "What the computer plays",
                     video: "Video", audio: "Sound" };

async function openInuse() {
  const body = h("div", { class: "inuse" });
  const m = modal({ title: "Camera and microphone", wide: true, body, buttons: [{ label: "Close", kind: "primary" }] });
  const tick = async () => {
    if (!m.box.isConnected) return;
    try { fill(body, inuseView(await api("GET", "/api/tools/inuse"))); }
    catch (e) { fill(body, h("div", { class: "warnbox bad" }, e.message)); }
    if (m.box.isConnected) setTimeout(tick, 3000);
  };
  fill(body, h("div", { class: "orow" }, h("span", { class: "spinner on" }), "Looking…"));
  await tick();
}

function inuseView(d) {
  const active = d.streams.filter(s => s.active);
  const waiting = d.streams.filter(s => !s.active);
  const streamRow = (s) => h("li", {},
    h("span", { class: `badge ${s.active ? "st-fail" : ""}` }, s.active ? "now" : s.state || "idle"), " ",
    h("b", {}, s.app), ` is ${s.active ? "using" : "connected to"} ${s.what_title}`,
    s.source ? h("span", { class: "muted" }, ` (${s.source})`) : null,
    s.what === "playback" ? h("span", { class: "small muted" }, ": volume meters and recorders of the computer's own sound do this") : null);
  const deviceRow = (x) => h("li", {},
    h("span", { class: `badge ${x.holders.length ? "st-fail" : "st-pass"}` }, x.holders.length ? "open" : "not in use"), " ",
    h("b", {}, x.name),
    x.holders.length ? `: ${x.holders.map(p => `${p.name} (process ${p.pid})`).join(", ")}` : null,
    !x.holders.length && x.via_server.length ? h("span", { class: "small muted" }, ` (held by ${x.via_server.join(", ")} for the programs listed above)`) : null);
  const cams = d.devices.filter(x => x.kind === "camera");
  const mics = d.devices.filter(x => x.kind === "microphone");
  return [
    h("div", { class: `verdict ${d.using.length ? "warn" : "ok"}` },
      h("div", { class: "vtitle" }, d.using.length ? `In use now: ${d.using.join(", ")}` : "Nothing is using the camera, a microphone or the screen right now."),
      h("p", { class: "small" }, "Updated every few seconds while this is open. Nothing here stops or changes a program: to stop one, "
        + "use its own controls, or close it.")),
    h("h4", {}, "Programs receiving sound or video"),
    active.length || waiting.length ? h("ul", { class: "small inuse-list" }, [...active, ...waiting].map(streamRow))
      : h("p", { class: "small muted" }, d.server ? `None (through ${d.server === "pipewire" ? "PipeWire" : "PulseAudio"}).` : "Couldn't be asked: no sound server answered."),
    h("h4", {}, "Cameras"),
    cams.length ? h("ul", { class: "small inuse-list" }, cams.map(deviceRow)) : h("p", { class: "small muted" }, "No camera is connected."),
    mics.some(x => x.holders.length) ? [h("h4", {}, "Sound cards opened directly"),
      h("ul", { class: "small inuse-list" }, mics.filter(x => x.holders.length).map(deviceRow))] : null,
    mics.length && !mics.some(x => x.holders.length) ? h("p", { class: "small muted" },
      `${plural(mics.length, "sound card")} with a microphone input: none is opened by a program directly, past the sound server.`) : null,
    d.notes.map(n => h("div", { class: "notebox small" }, n)),
  ];
}

// ------------------------------------------------------------------ Tor or Mullvad Browser in the RAM disk
// Downloading is the only part that reaches the network: the hosts are named before it starts.

async function openBrowserTool(reloadTools) {
  let data;
  try { data = await api("GET", "/api/tools/browser"); } catch (e) { toast(e.message, "error"); return; }
  const body = h("div", { class: "browser-tool" });
  let timer = null, closed = false;
  // how it starts: in the sandbox (when it can be), sound and the graphics card off unless asked; kept while the panel is open
  const opts = { sandbox: !!data.sandbox?.available, sound: false, nested: false, gpu: false };
  const stopFollowing = () => { closed = true; clearTimeout(timer); reloadTools?.(); };
  const m = modal({ title: "Tor or Mullvad Browser in memory", wide: true, body, buttons: [{ label: "Close", kind: "primary",
    onclick: (close) => { stopFollowing(); close(); } }] });
  const overlay = m.box.parentElement;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) stopFollowing(); });
  // After anything done here (a start above all), and for as long as a browser runs, the panel follows it: Tor's
  // progress, the browser ending (Start again), downloads arriving.
  let followUntil = 0;
  const reload = async () => {
    followUntil = Date.now() + FOLLOW_AFTER;
    try { data = await api("GET", "/api/tools/browser"); render(); } catch (e) { toast(e.message, "error"); }
  };
  const poll = async () => {
    let d = null;
    try { d = await api("GET", "/api/tools/browser"); } catch { /* the next poll tries again */ }
    if (closed || !body.isConnected) return;
    const el = document.activeElement;
    const editing = el && body.contains(el) && /^(TEXTAREA|INPUT|SELECT)$/.test(el.tagName);
    if (d && !editing && browserShown(d) !== browserShown(data)) { data = d; render(); return; }
    follow();                                     // unchanged, or the user is typing here: not under their hands
  };
  const follow = () => {
    clearTimeout(timer);
    if (closed) return;
    if (data.job?.state === "running") timer = setTimeout(reload, 1000);
    else if (data.browsers?.some(b => b.running || b.outbox?.on) || Date.now() < followUntil) timer = setTimeout(poll, 2000);
  };
  const render = () => {
    S.adminActive = !!data.admin_active; renderTop();
    const job = data.job;
    fill(body, browserIntro(data), browserRamdisk(data, reload), browserSandbox(data, opts), browserRisks(data, reload),
      browserJob(job, data, reload),
      job?.state === "running" ? null : browserCards(data, reload, opts), browserLimits(data));
    follow();
  };
  render();
}

const FOLLOW_AFTER = 20000;          // ms the panel keeps following after something was done in it

// What the panel shows that changes while a browser runs: it is drawn again when this changes.
function browserShown(d) {
  return JSON.stringify([d.ramdisk?.open, d.job?.state, (d.browsers || []).map(b => [b.running, b.installed,
    b.start_error, b.connection, b.downloads, b.downloads_other, b.uploads,
    b.outbox && [b.outbox.on, b.outbox.waiting, b.outbox.partial, b.outbox.originals, b.outbox.not_cleaned,
      b.outbox.recent]])]);
}

function browserIntro(data) {
  return [h("p", { class: "small" }, "Tor Browser and Mullvad Browser keep no history, cookies or cache between sessions. "
    + "Run from a RAM disk of its own, ~/TempBrowser (separate from the RAM disk tool's ~/RAMDisk), the browser itself, and "
    + "everything it writes while it runs, stays in memory too: closing ~/TempBrowser overwrites and removes all of it."),
    h("p", { class: "small" }, "Quitting the browser doesn't close ~/TempBrowser: the browser and what you saved stay there, "
      + "ready to start again, until you close it here or quit this app. Quitting the app closes it (asking for your password "
      + "if administrator access has ended), unless the browser is still running then: it stays open until you close it "
      + "here or restart the computer."),
    h("p", { class: "small" }, h("b", {}, "It is for one session, or a few over a day. "),
      "Set it up, browse, then close ~/TempBrowser: don't leave it set up for days, which defeats the point (nothing "
      + "of it should outlive the session). It never updates itself: each time you set it up, it downloads the latest "
      + "version. If you start it more than 24 hours after setting it up, it first asks the project's server "
      + "(aus1.torproject.org for Tor Browser, cdn.mullvad.net for Mullvad Browser) whether a newer version is out, "
      + "directly, as the download did; if one is, it won't start: save what you need from its Downloads, close "
      + "~/TempBrowser and set it up again. If it can't tell (the server blocked where you are), it starts only while its "
      + "signature is less than 30 days old."),
    data.platform ? null : h("div", { class: "warnbox" }, "Neither browser is made for this computer's processor.")];
}

function browserRamdisk(data, reload) {
  const rd = data.ramdisk;
  if (rd.other) return h("div", { class: "warnbox" }, `Something else (${rd.other}) is mounted on ~/TempBrowser.`);
  // not while a browser is being set up in it: closing would wipe the download or the unpacking under it
  const closeBtn = () => data.job?.state === "running"
    ? h("span", { class: "muted" }, "It can be closed once the set-up has finished or been stopped.")
    : h("button", { class: "small danger", onclick: () => closeRamdisk(rd, reload) }, "Close and overwrite…");
  if (rd.open && rd.noexec) {
    return h("div", { class: "notebox risk small" }, h("b", {}, "~/TempBrowser doesn't allow programs to run. "),
      "Close it (that overwrites what is in it) and open it again here, with programs allowed.",
      h("div", { class: "orow" }, closeBtn()));
  }
  if (rd.open) {
    const free = rd.total - rd.used;
    return h("div", { class: "orow small" }, h("span", { class: "badge st-pass" }, "~/TempBrowser open"),
      h("span", { class: "muted" }, `${fmtSize(free)} free of ${fmtSize(rd.total)}; programs can run from it.`),
      free < data.min_mb * 0.5 * 1048576 ? h("span", { class: "errmsg" }, "That may be too little: a browser needs about 500 MB.") : null,
      closeBtn());
  }
  const want = Math.min(rd.max_mb, Math.max(data.min_mb, 1536));
  const size = h("input", { type: "number", class: "num", min: data.min_mb, max: rd.max_mb, value: want });
  const cmds = ramdiskOpenCommands(rd, size, () => false);
  const open = h("button", { class: "small primary" }, "Open the RAM disk");
  open.addEventListener("click", async () => {
    const mb = parseInt(size.value, 10);
    if (!(mb >= data.min_mb && mb <= rd.max_mb)) { toast(`Choose a size from ${data.min_mb} to ${rd.max_mb} MB.`, "error"); return; }
    open.disabled = true;
    open.textContent = S.adminActive ? "Opening…" : "Waiting for authorization…";
    try {
      const r = await api("POST", "/api/tools/ramdisk/open", { size_mb: mb, noexec: false, disk: "browser" });
      S.adminActive = !!r.admin_active;
      await reload();
    } catch (e) { toast(e.message, "error", 10000); open.disabled = false; open.textContent = "Open the RAM disk"; }
  });
  return h("div", { class: "notebox info small" }, h("b", {}, "First, open the browser's RAM disk, ~/TempBrowser. "),
    "Programs are allowed to run from it, so the browser can. It takes memory only for what is in it: about 500 MB for the "
    + "browser, more as you browse. Opening needs administrator access.",
    h("div", { class: "orow" }, h("label", {}, "Size ", size, " MB"), open), cmds.slot, leftoverNote(rd, reload, "browser"));
}

// The sandbox: what it keeps the browser from, whether it can run here, its network, Landlock, and the
// session's display. On X11 no sandbox keeps programs from each other's windows and keystrokes: said,
// with the way to Wayland. On wlroots desktops (Sway, Hyprland…) Wayland itself lets any program
// capture the screen and read the clipboard: said too.
function browserSandbox(data, opts) {
  const sb = data.sandbox || {};
  const out = [];
  const guide = (id, label) => {
    const spec = S.state.catalogue.find(s => s.id === id);
    return spec ? h("button", { class: "small", onclick: () => openGuide(spec) }, label) : null;
  };
  if (sb.available) {
    const soundNote = h("div", { class: "notebox risk small sound-risks" }, h("b", {}, "What allowing sound gives away. "),
      ...soundRisks());
    soundNote.hidden = !(opts.sound && opts.sandbox);
    const gpuNote = h("div", { class: "notebox risk small gpu-risks" }, h("b", {}, "What allowing the graphics card costs. "),
      ...gpuRisks());
    gpuNote.hidden = !(opts.gpu && opts.sandbox);
    const notes = () => { soundNote.hidden = !(opts.sound && opts.sandbox); gpuNote.hidden = !(opts.gpu && opts.sandbox); };
    const sandbox = h("input", { type: "checkbox", checked: opts.sandbox, onchange: (e) => {
      opts.sandbox = e.target.checked; sound.disabled = !e.target.checked || !sb.sound; gpu.disabled = !e.target.checked || !sb.gpu;
      notes(); } });
    const sound = h("input", { type: "checkbox", checked: opts.sound, disabled: !opts.sandbox || !sb.sound,
      onchange: (e) => { opts.sound = e.target.checked; notes(); } });
    const gpu = h("input", { type: "checkbox", checked: opts.gpu, disabled: !opts.sandbox || !sb.gpu,
      onchange: (e) => { opts.gpu = e.target.checked; notes(); } });
    out.push(h("div", { class: "notebox info small" }, h("b", {}, "It runs in a sandbox. "),
      "The browser sees only its own folder in the RAM disk: not your home folder, your other programs, your keyring, "
      + "or your SSH and GPG keys, and not your name or this computer's (inside, it is \"user\" on \"localhost\"), nor "
      + "this computer's settings beyond what it needs to run (its clock is on UTC, as Tor Browser shows sites anyway). "
      + "It can't change its own program files, only its profile and Downloads. ",
      h("b", {}, "Tor Browser"), " has no network of its own: only Tor's, through a filter that lets it show its "
      + "circuits and ask for a new identity but never change how Tor connects. So even a website that got past the "
      + "browser's own protections couldn't reach your real address, this computer's services or your local network. ",
      h("b", {}, "Mullvad Browser"), sb.pasta?.available
        ? (sb.pasta.lan_blocked
          ? " gets a network of its own: the internet, but not this computer's services, your local network (the router, "
            + "printers, other computers), this computer's or the router's hardware address, or other programs' hidden "
            + "sockets. Mullvad VPN's own proxies are let through, so its extension can change the browser's country while "
            + "the VPN is connected. Your router's public address can't be refused (this computer doesn't know it), and many "
            + "routers show their settings page there too: keep that page behind a password of its own."
          : " gets a network of its own: the internet, but not this computer's own services or other programs' hidden "
            + `sockets. It can still reach your local network: ${sb.pasta.lan_why}`)
        : " shares this computer's network: see the warning below.",
      " Files go in and out through each browser's To upload and Downloads folders, below.",
      h("div", { class: "muted" }, "What it doesn't hide from a website that got past the browser: the kernel's version and "
        + "build (any program can ask the kernel), the distribution (its name file, which libraries read), the "
        + "processor's model and its known flaws (/sys/devices/system/cpu, which the browser reads), the names this "
        + "computer gives the disks its programs come from (on Fedora a disk encryption's id, on Debian often the "
        + "computer's name), and when the computer was started (every program can read its clock), which stays the same "
        + "until you restart, as does your login session's number: in two sessions before a restart, a website that got "
        + "that far could tell they were on the same computer. Restart between sessions you want kept apart. Unless you allow it "
        + "below, it has no graphics card: pages draw with the processor (WebGL and video work, more slowly and with more of the processor), which "
        + "keeps the graphics drivers, a large part of the kernel, out of its reach. A website can see one detail of that: "
        + "WebGL answers as drawing in software does, which differs in one value from what the graphics card would give "
        + "the browser outside the sandbox (with Intel graphics, or NVIDIA's driver on X11)."),
      h("div", { class: "orow" }, h("label", {}, sandbox, " Run it in a sandbox"),
        h("label", { title: sb.sound ? "" : "No sound server was found" }, sound, " Allow sound (it gives away more than sound: read why)"),
        h("label", { title: sb.gpu ? "" : "No graphics card's device files were found" }, gpu,
          " Allow the graphics card (faster, but within a website's reach: read why)")),
      soundNote, gpuNote,
      h("div", { class: "muted" }, "A screen reader or an input method (for Chinese, Japanese or Korean, say) can't reach a "
        + "sandboxed browser: untick the sandbox if you need one. A browser that has run in the sandbox can't then be "
        + "started without it (what a website left in it would run outside): close ~/TempBrowser and set it up again.")));
    if (!sb.pasta?.available && sb.pasta?.apparmor) {
      // Ubuntu 24.04 and what is built on it: passt is there, but AppArmor's restriction on user namespaces stops pasta
      const profile = "sudo tee /etc/apparmor.d/pasta-userns >/dev/null <<'EOF'\nabi <abi/4.0>,\ninclude <tunables/global>\n\n"
        + "profile pasta /usr/bin/pasta{,.avx2} flags=(unconfined) {\n  userns,\n}\nEOF\nsudo apparmor_parser -r /etc/apparmor.d/pasta-userns";
      out.push(h("div", { class: "notebox danger small" },
        h("b", {}, "Mullvad Browser shares this computer's network here: AppArmor stops passt."),
        `passt is installed, but AppArmor keeps it from the user namespace it works in (${sb.pasta.why.replace(/\.$/, "")}), as it `
        + "does bubblewrap until that has a profile. Until it can run, a website that got past the browser's own protections "
        + "could read this computer's and your router's hardware addresses and reach every device on your network. A "
        + "profile for pasta, like bubblewrap's, lets it run (undo it with sudo rm /etc/apparmor.d/pasta-userns and a "
        + "restart); then close this panel and open it again:",
        commandBlock([profile]),
        h("div", { class: "muted" }, "Turning the restriction off until the next restart (above) does the same for both. Tor "
          + "Browser isn't affected: it has no network but Tor's.")));
    } else if (!sb.pasta?.available) {
      out.push(h("div", { class: "notebox danger small" },
        h("b", {}, "Install passt before you use Mullvad Browser here."),
        `Without it Mullvad Browser shares this computer's network${sb.pasta?.why ? ` (${sb.pasta.why.replace(/\.$/, "")})` : ""}, `
        + "and a website that got past the browser's own protections could:",
        h("ul", {},
          h("li", {}, "read this computer's network and hardware (MAC) addresses, and those of your router and the other devices "
            + "on your network. A router's hardware address is usually its Wi-Fi's, or next to it, and public Wi-Fi maps can "
            + "say where that is, whatever VPN you use;"),
          h("li", {}, "reach services running on this computer, and every device on your network: the router's settings page, "
            + "printers, a NAS, cameras;"),
          sb.landlock ? null : h("li", {}, "reach other programs' hidden sockets (see Landlock, below).")),
        "passt gives it a network of its own, fenced off from all of that. Install it, then close this panel and open it again"
        + (sb.pasta?.install ? ":" : " (your distribution's passt package)."),
        sb.pasta?.install ? commandBlock([sb.pasta.install]) : null,
        h("div", { class: "muted" }, "Tor Browser isn't affected: it has no network but Tor's.")));
    }
    if (!sb.landlock) {
      const shared = !sb.pasta?.available;
      out.push(h("div", { class: `notebox ${shared ? "risk" : "info"} small` }, h("b", {}, "This kernel doesn't have Landlock's scopes (Linux 6.12). "),
        "Landlock lets a sandbox keep whatever shares this computer's network from other programs' hidden (abstract) sockets, "
        + "such as XWayland's, through which a browser taken over by a website could read and type into other windows. "
        + "Here, Tor Browser has no network of its own, so it can't reach them"
        + (shared ? "; Mullvad Browser shares the network, so it could, until passt is installed or the kernel is newer."
          : ", and nor can Mullvad Browser in its own network.")
        + " tor itself needs this computer's network: its sandbox keeps your display's socket and cookie from it, but "
        + "without Landlock a flaw in tor, or in a bridge's program, could still reach the display's hidden socket.",
        h("div", { class: "orow" }, guide("kern.landlock", "How to get a kernel with it…"))));
    }
  } else {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "It can't run in a sandbox here. "),
      `${sb.why || ""} It starts as an ordinary program, which can read your other files and reach the network directly. `
      + (sb.apparmor ? "" : "Installing bubblewrap (the bubblewrap package) lets the app keep it to its own folder.")));
    if (sb.apparmor) out.push(browserAppArmor());
  }
  if (sb.display === "x11") {
    const nestedBox = h("input", { type: "checkbox", checked: opts.nested, disabled: !sb.xephyr?.available,
      onchange: (e) => { opts.nested = e.target.checked; } });
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "This is an X11 session. "),
      "X11 doesn't keep programs apart: any program you run can see what the browser shows and what you type into it, "
      + "and a browser that had been taken over could do the same to every other window, even type into a terminal, "
      + "which no sandbox stops. A Wayland session keeps each program to its own windows."
      + (sb.available ? " Here the sandbox protects your files and your address, not your screen, unless the browser "
        + "has a display of its own:" : ""),
      sb.available ? h("div", { class: "orow" }, h("label", {}, nestedBox, " Give it a display of its own (Xephyr)")) : null,
      sb.available ? h("div", { class: "muted" }, sb.xephyr?.available
        ? "It then opens in one window that is a separate X display: the browser can't see or type into your other "
          + "windows. Not the other way round: that window is still a window of this X11 session, so another program "
          + "here could read what it shows or type into it. The cost: copy and paste between it and your other windows "
          + "doesn't work (type addresses in), "
          + "its window has no title bar of its own inside, and keyboard layouts other than the computer's may need "
          + "setting again inside. It closes by itself a few seconds after the browser."
        : ["This needs Xephyr, a nested X server, which isn't installed"
          + (sb.xephyr?.install ? ":" : " (your distribution's Xephyr package)."),
          sb.xephyr?.install ? commandBlock([sb.xephyr.install]) : null]) : null,
      h("div", { class: "orow" }, guide("sbx.x11_session", "How to use Wayland…"))));
  } else if (sb.display === "wayland" && sb.available && sb.wayland_context && sb.wayland_risky?.length) {
    const what = [...new Set(sb.wayland_risky.map(r => r.what))];
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "This desktop still offers the sandboxed browser more "
      + "than its own windows. "), "It marks the browser's connection as a sandbox's, but still offers that connection "
      + "what would let it (whether each works for it is up to the desktop; reading the clipboard does on KDE Plasma 6.7, "
      + "tested):",
      h("ul", {}, what.map(w => h("li", {}, w))),
      "A browser taken over by a website could do the same. Don't copy passwords or other secrets while it runs (or clear "
      + "the clipboard first), and treat a password prompt that appears over other windows with suspicion.",
      h("div", { class: "muted" }, `Asked of the desktop itself: ${sb.wayland_risky.map(r => r.global).join(", ")}.`)));
  } else if (sb.display === "wayland" && sb.available && sb.wayland_risky === null) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "What this desktop offers a sandboxed program couldn't be "
      + "asked. "), "The compositor didn't answer the app's question (it may be busy, or not a Wayland compositor at all), so "
      + "whether the browser's connection is marked as a sandbox's, and what that keeps from it, isn't known: don't take "
      + "it as kept from the screen and the clipboard. Open this panel again in a minute to ask again."));
  } else if (sb.display === "wayland" && sb.available && sb.wayland_context) {
    out.push(h("div", { class: "small muted" }, "This is a Wayland session, and this desktop marks the browser's "
      + "connection as a sandbox's: it gets only its own windows, and can't record the screen, read the clipboard in the "
      + "background or type into other programs (asked of the desktop itself)"
      + (sb.wlroots ? ", although other programs on this desktop can." : ".")));
  } else if (sb.display === "wayland" && sb.available && sb.wlroots) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "This desktop lets any program capture the screen. "),
      "On Sway, Hyprland and other desktops built on wlroots, every Wayland program, the browser included, can record "
      + "the whole screen and read the clipboard without asking. The sandbox keeps the browser off X11, but not from "
      + "those. Desktops that can mark a sandbox's connection (the security-context protocol, in recent Sway and KDE "
      + "Plasma releases) keep the browser from them: this one can't. On GNOME a program gets only its own windows."));
  } else if (sb.display === "wayland" && sb.available) {
    out.push(h("div", { class: "small muted" }, "This is a Wayland session: the browser gets only its own windows. On "
      + "GNOME and KDE Plasma, other programs can't see what it shows or what you type into it, and it can't see theirs "
      + "(some desktops built on wlroots, such as Sway and Hyprland, let any program record the screen)."));
  }
  return out;
}

// Before you start: what can put the session on the disk however the browser is run. Swap that reaches
// a disk (the browser's own memory, not just the RAM disk), with buttons that turn it off for the
// session and back on (the helper's swap_off and swap_on), the commands shown so they can be learnt;
// thumbnails the file manager keeps on the disk of what is in To upload and Downloads; and crash dumps
// kept on the disk (the browser's own are started without memory; the check's guide turns them off).
// What turning swap off costs: with nowhere to put memory that runs short, the kernel ends a program to make room.
function memoryNote(mem, rd) {
  if (!mem?.total_mb) return null;
  const disk = rd?.open && rd.total ? Math.round(rd.total / 1048576) : 0;          // its size, in MB
  const need = disk + mem.browser_mb;
  const tight = mem.available_mb != null && mem.available_mb < need;
  return h("div", { class: tight ? "warnbox small" : "muted" },
    `Without swap, when memory runs out the system ends a program to make room, and the browser can be the one. This `
    + `computer has ${Math.round(mem.total_mb / 1024)} GB, ${mem.available_mb != null ? `${(mem.available_mb / 1024).toFixed(1)} GB free now; ` : ""}`
    + `the browser takes about ${mem.browser_mb / 1024} GB with a few tabs, and ~/TempBrowser up to ${disk ? `its ${disk} MB` : "its size"} as `
    + "it fills" + (tight ? ". That is more than is free now: close other programs first, or keep fewer tabs and downloads." : "."));
}

function browserRisks(data, reload) {
  const r = data.risks || {};
  const sw = r.swap || {}, th = r.thumbnails || {};
  const guide = (id, label) => {
    const spec = S.state.catalogue.find(s => s.id === id);
    return spec ? h("button", { class: "small", onclick: () => openGuide(spec) }, label) : null;
  };
  const cmds = (list) => commandBlock(list);
  const swapButton = (off, label) => h("button", { class: `small ${off ? "primary" : ""}`, onclick: async (e) => {
    e.target.disabled = true;
    e.target.textContent = S.adminActive ? (off ? "Turning it off…" : "Turning it on…") : "Waiting for authorization…";
    try {
      const res = await api("POST", "/api/tools/browser/swap", { off });
      S.adminActive = !!res.admin_active;
      const done = off ? res.swap?.off : res.swap?.on, failed = res.swap?.failed || [];
      if (failed.length) toast(`Not ${off ? "turned off" : "turned on"}: ${failed.join("; ")}`, "error", 12000);
      else toast(off ? `Swap is off for this session (${(done || []).join(", ")}).` : `Swap is back on (${(done || []).join(", ")}).`, "ok");
      await reload();
    } catch (err) { toast(err.message, "error", 12000); e.target.disabled = false; e.target.textContent = label; }
  } }, label);
  const out = [];
  if (sw.on_disk?.length) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: swap reaches the disk here. "),
      `${sw.on_disk.join(", ")}${sw.used_mb ? ` (${sw.used_mb} MB in use now)` : ""}. When memory runs short, the system `
      + "writes parts of it there, and the browser's memory (the pages you visit, what you type) can be among them. Swap "
      + "isn't cleared when the browser closes or ~/TempBrowser is overwritten: the RAM disk can't keep the browser out "
      + "of it. Fix that first: turn swap off for this session, or make swap safe for good (in memory with zram, or "
      + "encrypted with a new key at every start).",
      h("div", { class: "orow" }, swapButton(true, "Turn swap off for this session"), guide("enc.swap_persistent", "Make swap safe for good…")),
      h("div", { class: "muted" }, "Turn swap off… asks for your password and runs:"), cmds(sw.off_commands || []),
      h("div", { class: "muted" }, "Afterwards, Turn swap back on (here) runs the reverse, or restart the computer:"),
      cmds(sw.on_commands || []),
      h("div", { class: "muted" }, "Turning it off is refused if memory can't take back what is in swap now. It doesn't "
        + "erase what earlier sessions left there; only zram or encrypted swap does that, for the future."),
      memoryNote(r.memory, data.ramdisk)));
  } else if (sw.paused?.length) {
    out.push(h("div", { class: "notebox info small" }, h("b", {}, "Swap is off for this session. "),
      `It was turned off here (${sw.paused.join(", ")}): the browser's memory can't be written to the disk. Turn it back `
      + "on when you are done (it also comes back on at the next restart). That runs:", cmds(sw.on_commands || []),
      memoryNote(r.memory, data.ramdisk),
      h("div", { class: "orow" }, swapButton(false, "Turn swap back on"))));
  }
  if (th.in_memory === false) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, `Before you start: thumbnails are kept on the disk (${th.folder}). `),
      "If you open To upload or Downloads in your file manager, it makes thumbnails of the pictures, videos and documents "
      + "there and keeps them on the disk, each with the file's name and folder, long after ~/TempBrowser is gone. Keep "
      + "thumbnails in memory first, or don't open those folders in the file manager (Save… and Add a file to upload… "
      + "below don't make thumbnails).",
      h("div", { class: "orow" }, guide("desk.thumbnails", "Keep thumbnails in memory…"))));
  }
  const ix = r.indexing || {};
  const baloo = ix.baloo;
  if (baloo?.on || ix.localsearch) {
    const what = [baloo?.on ? `KDE's file search (Baloo${baloo.contents ? "" : ", file names only"})` : null,
                  ix.localsearch ? `GNOME's ${ix.localsearch}` : null].filter(Boolean).join(" and ");
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, `Before you start: file search is on here (${what}). `),
      baloo?.on
        ? (baloo.covers ? "Baloo indexes ~/TempBrowser too (it doesn't skip a RAM disk in your home folder: tested): the "
            + "names of what you download and upload" + (baloo.contents ? ", and the words inside them," : "") + " go into "
            + "its index on the disk, long after ~/TempBrowser is gone. " : "")
          + "Baloo can't be trusted to forget: excluding a folder stops new indexing there, but what it already took "
          + "stays in its index (tested). Turn it off and delete its index first. "
        : "",
      "Whatever you save out of the browser into folders that are indexed (Documents, Downloads, Pictures…) is indexed "
      + "there, its words included, and kept on the disk for a while even after you delete it. Turning file search off "
      + "is recommended.",
      h("div", { class: "orow" },
        baloo?.on ? h("button", { class: "small primary",
          onclick: () => openGuideOption("desk.indexers", "baloo_off", reload) }, "Turn Baloo off and delete its index…") : null,
        guide("desk.indexers", "File search…"))));
  } else if (baloo?.index) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: Baloo's index is still on the disk. "),
      "File search is off, but the index it made (names, and words inside your documents) is still there. Delete it.",
      h("div", { class: "orow" }, h("button", { class: "small", onclick: () => openGuideOption("desk.indexers", "baloo_off", reload) },
        "Delete Baloo's index…"))));
  }
  // the scan's own answer (context.detect_hibernation): true, false, or null when it couldn't be told
  if (r.hibernation === null) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: whether this computer can hibernate couldn't be told. "),
      "If it can, hibernating writes all of memory to the disk, the browser's and ~/TempBrowser's included. Close the "
      + "browser and ~/TempBrowser before you hibernate.",
      h("div", { class: "orow" }, guide("enc.hibernate_unencrypted", "Hibernation…"))));
  } else if (r.hibernation) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: this computer can hibernate. "),
      "Hibernating writes all of memory to the disk: the browser's, and ~/TempBrowser's, though it is kept out of swap. "
      + "It stays there until it is overwritten, after the computer has woken up. Close the browser and ~/TempBrowser "
      + "before you hibernate (and before a sleep your system may turn into hibernation after a while), or turn "
      + "hibernation off.",
      h("div", { class: "orow" }, guide("enc.hibernate_unencrypted", "Hibernation…"))));
  }
  const os = r.opensnitch;
  if (os) {
    const kept = [os.log ? `its log (${os.log}, which any account on this computer can read) gets a line naming the `
                   + `website for every question it asks, at log level ${os.log_level}` : null,
                  os.database ? `its window keeps its list of connections in a file (${os.database}): every connection, `
                   + "with the website's name" : null].filter(Boolean);
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: OpenSnitch keeps a record on the disk. "),
      `OpenSnitch is running, and ${kept.join("; and ")}. Mullvad Browser's connections are among them, named after `
      + "the sites (Tor Browser's are only Tor's relays). Its guide sets the log level to 3 and keeps the list in memory.",
      h("div", { class: "orow" }, guide("net.outgoing_firewall", "OpenSnitch…"))));
  }
  const clip = S.report?.results?.["desk.clipboard_history"];
  const clipSpec = S.state.catalogue.find(s => s.id === "desk.clipboard_history");
  if (clip?.status === "fail" && clipSpec) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: clipboard history is saved to the disk. "),
      `${clip.summary} Whatever you copy in the browser, an address or a password, is kept there. The browser's own `
      + "display (X11 with a display of its own) keeps the clipboard to itself; otherwise turn the history off first "
      + "(as of the last scan).",
      h("div", { class: "orow" }, fixButtons(clipSpec, clip))));
  }
  const cd = r.crash_dumps || {};
  if (cd.kept) {
    out.push(h("div", { class: "notebox risk small" }, h("b", {}, "Before you start: this computer keeps crash dumps on the disk. "),
      "When a program crashes, a copy of its memory is saved and kept for days: what it showed, what was typed into it, "
      + "and a record in the system's log of its command and the files it had open. The app starts the browser, and what "
      + "it opens files with, so that a crash leaves neither (as a shell would, with the commands below): only the "
      + "kernel's note that a program of that name crashed. Other programs' crashes still keep both. Turning crash dumps "
      + "off for the whole computer is recommended.",
      cmds(cd.start || []),
      h("div", { class: "orow" }, guide("enc.coredumps_retained", "Stop keeping crash dumps…"))));
  }
  return out;
}

// Ubuntu 24.04 and later (and what is built on it) keep programs without an AppArmor profile of their own from the
// user namespaces bubblewrap needs. The two ways round it, each with what it costs, as commands the user runs.
function browserAppArmor() {
  const profile = "sudo tee /etc/apparmor.d/bwrap-userns >/dev/null <<'EOF'\nabi <abi/4.0>,\ninclude <tunables/global>\n\n"
    + "profile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\nEOF\nsudo apparmor_parser -r /etc/apparmor.d/bwrap-userns";
  return h("div", { class: "notebox info small" }, h("b", {}, "Keeping it sandboxed on Ubuntu. "),
    "AppArmor here keeps programs without a profile of their own from the user namespaces a sandbox is built from: they "
    + "are a common route for attacks on the kernel, so each way round it weakens that for every program. Choose one, "
    + "then close this panel and open it again:",
    h("ul", {},
      h("li", {}, h("b", {}, "A profile for bubblewrap only "), "(the way Ubuntu documents for programs that need them). Any "
        + "program can then get namespaces through bubblewrap, but the restriction stays on for everything else, and it "
        + "lasts. Undo it with sudo rm /etc/apparmor.d/bwrap-userns and a restart.", commandBlock([profile])),
      h("li", {}, h("b", {}, "The restriction off until the next restart, "), "for the whole computer:",
        commandBlock(["sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0"]))),
    h("div", { class: "muted" }, "Or start it without the sandbox, as an ordinary program, which is what it does now."));
}

// Tor Browser in the sandbox: how its tor connects (its own Connect page and bridge settings are off
// there, since it doesn't start tor), and how far tor has got.
function browserTor(b, reload) {
  const br = b.bridges || { mode: "none", builtin: [] };
  const names = { none: "Directly (no bridge)", obfs4: "Built-in bridge: obfs4", snowflake: "Built-in bridge: Snowflake",
    meek: "Built-in bridge: meek (Azure)", custom: "Bridges I have…" };
  const modes = ["none", ...["obfs4", "snowflake", "meek"].filter(m => br.builtin.includes(m)), "custom"];
  const select = h("select", {}, modes.map(m => h("option", { value: m, selected: m === br.mode }, names[m])));
  const lines = h("textarea", { rows: 3, class: "path", placeholder: "obfs4 192.0.2.1:443 1234…ABCD cert=… iat-mode=0", spellcheck: "false", autocomplete: "off" });
  const linesRow = h("div", { style: br.mode === "custom" ? "" : "display:none" }, lines,
    h("div", { class: "muted" }, br.mode === "custom" ? `${plural(br.count, "bridge")} set; paste others to replace them.` :
      "Get bridges at bridges.torproject.org, by email to bridges@torproject.org, or from @GetBridgesBot on Telegram."));
  select.addEventListener("change", () => { linesRow.style.display = select.value === "custom" ? "" : "none"; });
  const save = h("button", { class: "small", onclick: async () => {
    try {
      await api("POST", "/api/tools/browser/bridges", { browser: b.id, mode: select.value, lines: lines.value });
      toast(b.running ? "Saved: restart Tor Browser to connect this way." : "Saved: Tor Browser connects this way when it starts.", "ok");
      await reload();
    } catch (e) { toast(e.message, "error", 10000); }
  } }, "Save");
  const c = b.connection;
  const state = !c ? null : c.state === "connected" ? h("span", { class: "badge st-pass" }, "Tor connected")
    : c.state === "connecting" || c.state === "starting" ? h("span", { class: "badge st-warn" }, `Tor connecting ${c.progress}%`)
    : c.state === "failed" ? h("span", { class: "badge st-fail" }, "Tor couldn't start") : h("span", { class: "badge" }, "Tor stopped");
  return h("div", { class: "small" },
    h("div", { class: "orow" }, h("label", {}, "Connect to Tor ", select), save, b.running ? state : null),
    linesRow,
    b.running && c && c.state !== "connected" && (c.summary || c.problem)
      ? h("div", { class: "muted" }, [c.summary, c.problem].filter(Boolean).join(" · ")) : null,
    h("div", { class: "muted" }, "In the sandbox, Tor Browser's own Connect page and bridge settings are off (it doesn't "
      + "start Tor itself there): choose here. Bridges help where Tor is blocked, and hide from your network that you "
      + "use Tor. Without the sandbox, Tor Browser's own settings apply."));
}

// Files in and out: copied by the app, so the browser never sees your folders.
function browserFiles(b, data, reload) {
  const ups = b.uploads || [], downs = b.downloads || [];
  const showBtn = (which, label) => h("button", { class: "small", onclick: async () => {
    try { await api("POST", "/api/tools/browser/show", { browser: b.id, which }); } catch (e) { toast(e.message, "error"); } } }, label);
  const clean = h("input", { type: "checkbox", checked: !!data.mat2, disabled: !data.mat2 });
  const add = h("button", { class: "small" }, "Add a file to upload…");
  add.addEventListener("click", async () => {
    let paths = [];
    if (data.can_pick) {
      try { const r = await api("POST", "/api/tools/pick", { multiple: true }); if (!r.unavailable) paths = r.paths; else paths = null; }
      catch (e) { toast(e.message, "error"); return; }
    } else paths = null;
    if (paths === null) { const p = await askPath("Which file?", "/home/you/Pictures/photo.jpg, or ~/…"); paths = p ? [p] : []; }
    if (!paths.length) return;
    add.disabled = true;
    try {
      const r = await api("POST", "/api/tools/browser/upload", { browser: b.id, paths, clean: clean.checked });
      for (const err of r.errors || []) toast(err, "error", 10000);
      if (r.added?.length) toast(`Ready to upload: ${r.added.map(a => a.name).join(", ")}${clean.checked ? " (metadata removed)" : ""}.`, "ok");
      await reload();
    } catch (e) { toast(e.message, "error", 10000); } finally { add.disabled = false; }
  });
  const save = async (f, btn) => {
    if (f.warnings.length && !await confirmModal(`Save ${f.name}?`, [h("p", {}, "This file:"),
      h("ul", {}, f.warnings.map(w => h("li", {}, w)))], "Save it")) return;
    let folder = null;
    if (data.can_pick) {
      try { const r = await api("POST", "/api/tools/pick", { folder: true }); if (r.unavailable) folder = undefined; else folder = r.paths[0]; }
      catch (e) { toast(e.message, "error"); return; }
    }
    if (folder === undefined || !data.can_pick) folder = await askPath("Save it in which folder?", "/home/you/Documents, or ~/…");
    if (!folder) return;
    btn.disabled = true;
    try {
      const r = await api("POST", "/api/tools/browser/save", { browser: b.id, name: f.name, check: f.check, folder });
      toast(`Saved as ${r.saved}. It is a copy: the one in the RAM disk goes when the RAM disk is closed.`, "ok", 10000);
    } catch (e) { toast(e.message, "error", 15000); if (e.data?.changed) await reload(); } finally { btn.disabled = false; }
  };
  return h("div", { class: "browser-files small" },
    h("div", {}, "These two folders are ordinary folders on your side: open them in your file manager like any other, and "
      + "drag files in to upload, or copy downloads out. The buttons below do the same with extra care. Opening a "
      + "download from the file manager (or, when the browser runs without its sandbox, from its own list of downloads) "
      + "opens it in your usual program, outside any sandbox and online, which keeps it in its recent files and history "
      + "on the disk: use View offline… for that."),
    h("h4", {}, "To upload"),
    h("div", { class: "muted" }, `${b.uploads_folder}. In the browser's Browse… dialog it is To upload in its home folder. `
      + "The browser can read what is there, not change it. The Outbox below, or Add a file to upload…, removes a file's "
      + "metadata first (where a photo was taken, who wrote a document), out of the browser's sight; a file you drag into "
      + "To upload yourself goes as it is. Its name goes with it: sites see that too, so rename a file whose name says "
      + "something (\"IMG_20260105_143022.jpg\", your name on a CV) before you add it."),
    data.picker === "zenity" || data.picker === "kdialog" ? h("div", { class: "notebox risk small" },
      `Choosing a file with ${data.picker} (the file chooser, outside the app's window) adds it to your desktop's recent `
      + "files list, kept on the disk: a record that you used it now. In the app's window that is turned off. Recent "
      + "files' guide stops the list for good.", h("div", { class: "orow" }, (() => {
        const spec = S.state.catalogue.find(x => x.id === "desk.recent_files");
        return spec ? h("button", { class: "small", onclick: () => openGuide(spec) }, "Stop keeping recent files…") : null;
      })())) : null,
    browserOutbox(b, data, reload, showBtn),
    ups.length ? h("ul", {}, ups.map(u => h("li", {}, `${u.name} (${fmtSize(u.size)}) `,
      h("button", { class: "small ghost", title: "Take it out of the browser's folder", onclick: async () => {
        try { await api("POST", "/api/tools/browser/upload/remove", { browser: b.id, name: u.name }); await reload(); }
        catch (e) { toast(e.message, "error"); } } }, "Remove")))) : null,
    h("div", { class: "orow" }, add, h("label", { title: data.mat2 ? "" : "Install mat2 to remove metadata" }, clean,
      " Remove metadata first"), showBtn("uploads", "Open the folder")),
    h("h4", {}, "Downloads"),
    h("div", { class: "muted" }, `What the browser saves goes to ${b.downloads_folder}. Copy a file out with your file manager, `
      + "or with Save…, which copies it as a new file that can't run as a program and says first what it really is (by "
      + "its content, not its name): a program, a disk image, an archive, a document with macros. Don't open programs "
      + "from this folder. Opening a document from the web outside the browser can reveal your real address (it may "
      + "fetch things from the internet): View offline… opens it in your usual viewer with no network."),
    downs.length ? h("ul", {}, downs.map(f => h("li", {}, `${f.name} (${fmtSize(f.size)}) `,
      ["program", "disk image", "archive"].includes(f.kind) && f.what ? h("span", { class: "errmsg" }, `${f.what} `) : null,
      f.warnings.length ? h("span", { class: "errmsg", title: f.warnings.join("; ") }, "⚠ ") : null,
      h("button", { class: "small", onclick: (e) => save(f, e.target) }, "Save…"),
      f.viewable ? h("button", { class: "small", onclick: (e) => viewOffline(b, f, e.target) }, "View offline…") : null)))
      : h("div", { class: "muted" }, "Nothing yet."),
    b.downloads_other ? h("div", { class: "muted" }, `${b.downloads_other} other ${b.downloads_other === 1 ? "thing isn't" : "things aren't"} `
      + "listed: downloads still in progress or being checked, folders, links, or files that can't be a real download "
      + "(larger than ~/TempBrowser, or made of empty space).") : null,
    h("div", { class: "orow" }, showBtn("downloads", "Open the folder"), h("button", { class: "small ghost", onclick: reload }, "Refresh")));
}

// The TempOutbox: a folder in ~/TempBrowser, outside the browser's sight, that cleans what the user copies into it
// and passes the clean copy to To upload (tools/transfer.py). Where the permanent ~/Outbox is set up, that one.
function browserOutbox(b, data, reload, showBtn) {
  const o = b.outbox;
  if (!o) return null;
  const turn = (on) => async (e) => {
    e.target.disabled = true;
    try { await api("POST", "/api/tools/browser/outbox", { browser: b.id, on }); await reload(); }
    catch (err) { toast(err.message, "error", 12000); e.target.disabled = false; }
  };
  if (!o.on && o.permanent) {
    return h("div", { class: "notebox info small" }, h("b", {}, "Your Outbox. "),
      "You have the Outbox set up (~/Outbox): put a file in it, and copy the clean one from ~/Outbox/Cleaned into "
      + "To upload (drag it into the folder, or use Add a file to upload…). Files in ~/Outbox are on the disk, not in memory.",
      h("div", { class: "orow" }, showBtn("permanent", "Open ~/Outbox/Cleaned")));
  }
  if (!o.on) {
    return h("div", { class: "small" }, h("div", { class: "orow" },
      h("button", { class: "small", disabled: !o.mat2, title: o.mat2 ? "" : "Install mat2 to remove metadata",
        onclick: turn(true) }, `Turn on the Outbox for ${b.name}`)),
      h("div", { class: "muted" }, `A folder, ${o.folder}, that removes the metadata of what you copy into it and passes `
        + "the clean copy to To upload."));
  }
  const recent = (o.recent || []).slice(0, 5);
  return h("div", { class: "notebox info small" },
    h("b", {}, `Outbox: ${o.folder}`),
    h("div", {}, "Copy files into it with your file manager: the app removes their metadata (where a photo was taken, who "
      + "wrote a document) and puts the clean copy in To upload, out of the browser's sight until then; the original goes to "
      + "Originals inside it. A file that can't be cleaned goes to Not cleaned, and isn't passed on. Copy rather than move: "
      + `everything in ~/TempBrowser goes when it is closed. Folders put there are left as they are. Its name goes with it, as below.`),
    !o.mat2 ? h("div", { class: "warnbox small" }, "Removing metadata needs mat2, which isn't installed: nothing put there is "
      + "passed on until it is.") : null,
    !o.watched ? h("div", { class: "warnbox small" }, "This copy of the app isn't watching it: files wait there until the app "
      + "is started again.") : h("div", { class: "muted" }, "The app empties it while it is open; quit the app and files wait "
      + "there until it is opened again."),
    o.waiting ? h("div", {}, `${plural(o.waiting, "file")} waiting (a file still being copied in waits until it has `
      + "all arrived).") : null,
    o.partial ? h("div", { class: "muted" }, `${plural(o.partial, "file")} named as a copy still under way (.part, `
      + `.crdownload, a name ending in ~) ${o.partial === 1 ? "is" : "are"} left alone until renamed.`) : null,
    recent.length ? h("ul", {}, recent.map(r => h("li", {}, r.what === "cleaned"
      ? [h("code", {}, r.name), " → To upload", r.detail !== r.name ? ` as ${r.detail}` : "", h("span", { class: "okmsg" }, " (cleaned)")]
      : [h("code", {}, r.name), " → Not cleaned: ", h("span", { class: "errmsg" }, r.detail)]))) : null,
    o.not_cleaned.length ? h("div", { class: "errmsg" }, `In Not cleaned: ${o.not_cleaned.join(", ")}.`) : null,
    o.permanent ? h("div", { class: "muted" }, "You also have the permanent Outbox (~/Outbox), on the disk.") : null,
    h("div", { class: "orow" }, showBtn("outbox", "Open the Outbox"),
      h("button", { class: "small ghost", title: "Removes the folder (refused while it holds files)", onclick: turn(false) },
        "Turn it off")));
}

// View offline…: a document or picture from the browser opened in the usual viewer for it, in a sandbox
// with no network, so it can't fetch anything (tools/viewer.py). The page names the viewer and shows the
// command it runs first.
async function viewOffline(b, f, btn) {
  let plan;
  try { plan = (await api("POST", "/api/tools/browser/view", { browser: b.id, name: f.name, open: false })).viewer; }
  catch (e) { toast(e.message, "error", 12000); return; }
  const x11 = (await api("GET", "/api/tools/browser").catch(() => ({})))?.sandbox?.display === "x11";
  const ok = await confirmModal(`Open ${f.name} with no network?`, [
    h("p", {}, `It opens in ${plan.app}, your usual app for this kind of file, `
      + (plan.flatpak ? "in Flatpak's own sandbox with what it usually asks for taken away (the network, your folders, "
        + "sound, your other programs)" : "inside a sandbox with no network")
      + ": the file can't fetch anything, so opening it can't reveal your address. It gets a copy of this one file, "
      + "read-only, and nothing else of yours; what it saves is gone when it closes."),
    ...(plan.notes || []).map(n => h("p", { class: "small" }, n)),
    f.warnings.filter(w => !w.startsWith("can fetch things")).length
      ? h("ul", { class: "small" }, f.warnings.filter(w => !w.startsWith("can fetch things")).map(w => h("li", {}, w))) : null,
    x11 ? h("p", { class: "small muted" }, "This is an X11 session: the app can still see and type into other windows.") : null,
    h("div", { class: "small muted" }, plan.flatpak ? "It runs (the copy's folder gets a random name in place of <random>):"
      : "It runs, inside bubblewrap with no network (bwrap --unshare-all …):"),
    commandBlock([plan.command]),
  ], "Open it");
  if (!ok) return;
  btn.disabled = true;
  try {
    const r = await api("POST", "/api/tools/browser/view", { browser: b.id, name: f.name, open: true, check: f.check });
    toast(`${f.name} is opening in ${r.viewer.app}, with no network.`, "ok");
  } catch (e) { toast(e.message, "error", 15000); } finally { btn.disabled = false; }
}

function askPath(title, placeholder) {
  return new Promise((resolve) => {
    const input = h("input", { type: "text", class: "path", placeholder, spellcheck: "false", autocomplete: "off" });
    modal({ title, body: [input], buttons: [{ label: "Cancel", onclick: (close) => { close(); resolve(null); } },
      { label: "OK", kind: "primary", onclick: (close) => { close(); resolve(input.value.trim() || null); } }] });
    input.focus();
  });
}

function confirmModal(title, body, yes) {
  return new Promise((resolve) => modal({ title, body, buttons: [
    { label: "Cancel", onclick: (close) => { close(); resolve(false); } },
    { label: yes, kind: "primary", onclick: (close) => { close(); resolve(true); } }] }));
}

// What the sound server's socket gives a browser a website took over (tested from a sandbox holding only that
// socket, with PipeWire's PulseAudio server): the microphone, the user's and computer's names and the other
// programs using sound, and modules it loads on request: a connection out to any address, or a listener.
function soundRisks(list = false) {
  const items = [
    "record from the microphone;",
    "read your user name and this computer's name (the sound server tells any program that asks), and which other "
      + "programs are using sound;",
    "ask the sound server to connect to any address on the internet, or to listen for connections: it runs outside the "
      + "sandbox, on this computer's own network, so under Tor Browser that connection reveals your real address, and "
      + "under Mullvad Browser it can reach your local network.",
  ];
  if (list) return items;
  return ["The browser gets this computer's sound server, outside the sandbox. A website that got past the browser's own "
    + "protections could then:", h("ul", {}, items.map(t => h("li", {}, t))),
    "Leave it off unless you need sound, above all in Tor Browser."];
}

function gpuRisks() {
  return ["The browser gets the graphics card's device files. Pages draw faster (3D, maps, games, video effects), and "
    + "WebGL answers as the browser outside the sandbox would, so that detail no longer sets it apart. But the graphics "
    + "drivers then handle whatever a website sends them: the card's driver in the kernel, one of its largest and most "
    + "often flawed parts, and its driver in the browser itself (NVIDIA's closed one, on a computer with NVIDIA). A website "
    + "that got past the browser's own protections could use a flaw in them to get out of the sandbox: to your files, or "
    + "the whole computer.",
    "It also lets the browser read the card's own serial number (NVIDIA's driver gives it to every program that may use "
    + "the card), the same in every session.",
    "Leave it off unless a site you need is too slow without it, above all in Tor Browser. With a display of its own "
    + "(Xephyr, on X11) it isn't given the card: it would draw in software there anyway."];
}

// Mullvad Browser set up for Mullvad VPN (browser.preset_vpn): the tick on its card, on by default, kept while the app
// runs; sent with a download and with an archive the user picked (the server uses it for Mullvad Browser only)
const browserSetup = { vpn: true };

function mullvadVpnTick() {
  const box = h("input", { type: "checkbox", checked: browserSetup.vpn, onchange: () => { browserSetup.vpn = box.checked; } });
  return h("div", { class: "small vpnsetup" }, h("label", { class: "check" }, box, h("b", {}, "Set it up for Mullvad VPN")),
    h("p", { class: "muted" }, "Its extension then sends every website through Mullvad's proxy in Zurich, which is "
      + "reachable only inside Mullvad VPN's tunnel: with Mullvad VPN not connected, no page loads until you turn the "
      + "proxy off in the extension. Its permissions are granted, so it doesn't ask when first opened, and secure DNS is "
      + "off, as the extension advises with the VPN. Untick it if you don't use Mullvad VPN."));
}

// what the card says of a copy set up for Mullvad VPN, and how to undo each part in the browser
function mullvadVpnNote(vpn) {
  if (!vpn) return null;
  if (!vpn.set) return h("div", { class: "warnbox small" }, "Not set up for Mullvad VPN: " + vpn.why);
  return h("div", { class: "notebox info small" },
    h("b", {}, "Set up for Mullvad VPN: needs it connected. "),
    `Every website goes through Mullvad's proxy in ${vpn.city} (${vpn.server}), inside Mullvad VPN's tunnel, so with the `
    + "VPN not connected no page loads. Not using Mullvad VPN? Click the Mullvad extension's icon in the toolbar and turn "
    + "its proxy off, or choose another location there. Secure DNS is off, as the extension advises while connected: "
    + "without the VPN, turn it back on in Settings, Privacy & Security, DNS over HTTPS (Max Protection, Mullvad's own).");
}

function browserCards(data, reload, opts = { sandbox: true, sound: false, nested: false, gpu: false }) {
  const rd = data.ramdisk;
  const usable = rd.open && !rd.noexec && !rd.other;
  const cards = data.browsers.map(b => {
    let action;
    if (b.running) action = h("span", { class: "badge st-pass" }, "running");
    else if (b.installed) {
      action = h("button", { class: "small primary", onclick: async (e) => {
        if (b.release?.check_due && !await confirmModal(`Check for a newer ${b.name} first?`, [
          h("p", {}, `This copy was set up more than a day ago, so starting it first asks ${b.release.host} which `
            + "version is the latest, directly (not through Tor), as the download did: the server sees this computer's "
            + "address, nothing else."),
          h("p", {}, "If a newer version is out, or it can't tell, it won't start: save what you need from its Downloads, "
            + "then close ~/TempBrowser and set it up again."), proxyWarning(data, [b.release.host])], "Check and start")) return;
        if (b.tor && opts.sound && opts.sandbox && !await confirmModal("Start Tor Browser with sound?", [
          h("p", {}, "Sound connects the browser to this computer's sound server, which isn't in the sandbox and isn't "
            + "behind Tor. A website that got past the browser's own protections could then:"),
          h("ul", {}, soundRisks(true).map(t => h("li", {}, t))),
          h("p", {}, "The last one undoes what Tor is for. Start it without sound unless you need it.")], "Start with sound")) return;
        e.target.disabled = true;
        try {
          // what the panel showed of the sandbox: a start that would fall short of it is refused by the server
          const sb = data.sandbox || {};
          const expect = opts.sandbox ? { network: b.network, lan_blocked: b.tor || (b.network === "private" && !!sb.pasta?.lan_blocked),
                                          wayland_context: sb.wayland_context === true } : undefined;
          const r = await api("POST", "/api/tools/browser/start", { browser: b.id, sandbox: opts.sandbox, sound: opts.sound,
                                                                     nested: !!(opts.sandbox && opts.nested),
                                                                     gpu: !!(opts.sandbox && opts.gpu), expect });
          const net = { tor: ", with no network but Tor's", private: ", on a network of its own", shared: "" }[r.started?.network] || "";
          toast(`${b.name} is starting from the RAM disk${r.started?.sandboxed ? `, in its sandbox${net}` : ""}`
            + `${r.started?.nested ? ", in a display of its own" : ""}`
            + `${r.started?.sandboxed && r.started?.gpu ? ", with the graphics card" : ""}.`, "ok");
          await reload();
        } catch (err) { toast(err.message, "error", 10000); e.target.disabled = false; }
      } }, `Start ${b.name}`);
    } else {
      action = h("button", { class: "small", disabled: !usable || !b.available, onclick: () => browserDownload(b, data, reload) }, "Download…");
    }
    const vpnSetup = b.id === "mullvad" ? (b.installed ? mullvadVpnNote(b.release?.vpn) : mullvadVpnTick()) : null;
    return h("div", { class: "toolcard" }, h("b", {}, b.name), h("p", { class: "small" }, b.about),
      h("p", { class: "small" }, b.security === "safest"
        ? [h("b", {}, "It starts at the Safest security level, set by the app: "), "JavaScript is off on most sites and "
          + "more is turned off, which stops most of what an attack on the browser would need. If a site needs more, "
          + "lower it with the shield button in the toolbar (it stays lowered until ~/TempBrowser is closed)."]
        : [h("b", {}, "It starts at the Standard security level, "), "as the app leaves it: Mullvad Browser is for "
          + "everyday browsing, where sites need what Safer and Safest turn off. Raise it with the shield button in the "
          + "toolbar for a site you don't trust."]),
      h("p", { class: "small muted" }, b.tor
        ? "A trustworthy VPN underneath adds a second layer: if the browser were ever made to connect around Tor (the "
          + "sandbox stops that; without it, an exploit or a file opened outside could), sites would see the VPN's address, "
          + "not yours, and your network sees only the VPN, not that you use Tor. The VPN company then sees when you use Tor."
        : "With Mullvad VPN connected, its extension shows that the connection is protected and can route the browser "
          + "through another of Mullvad's locations. Without a VPN, sites see your real address."),
      b.installed ? h("div", { class: "small muted" }, `In ${b.folder}.`
        + (b.release?.version ? ` Version ${b.release.version}` + (b.release.unpacked ? `, set up ${fmtWhen(b.release.unpacked)}.` : ".") : "")
        + (b.release?.check_from && !b.release.check_due ? ` From ${fmtWhen(b.release.check_from)}, starting it first checks for a newer version.` : "")) : null,
      b.installed && b.release?.unchecked ? h("div", { class: "warnbox small" },
        `Whether this is the latest version couldn't be checked: ${b.release.host} couldn't be reached. It was accepted `
        + `because its signature was made ${plural(b.release.signed_days ?? 0, "day")} before it was set up, but a newer `
        + "version with security fixes may be out. Check when you can (the project's site, a mirror, or GetTor).") : null,
      b.installed && b.release?.stale ? h("div", { class: "warnbox small" },
        `This release was signed ${plural(b.release.signed_days, "day")} before it was set up. ${b.name} usually has a new `
        + "release every few weeks, so a newer one is likely out, even though the project's server said this was the "
        + "latest. Check the project's site, and set it up again if there is a newer one.") : null,
      b.installed && b.release?.check_due ? h("div", { class: "notebox info small" },
        `Set up more than a day ago: starting it first asks ${b.release.host} whether a newer version is out, and it won't `
        + "start if one is. Save what you need from its Downloads before then.") : null,
      !b.available ? h("div", { class: "small errmsg" }, "Not made for this processor.") : null,
      b.start_error ? h("div", { class: "warnbox small" }, b.start_error, " ", h("button", { class: "small", onclick: async () => {
        try { await api("POST", "/api/tools/browser/dismiss", { browser: b.id }); } catch (e) { toast(e.message, "error"); }
        await reload();
      } }, "OK")) : null,
      vpnSetup,
      h("div", { class: "orow" }, action),
      b.installed && b.tor && data.sandbox?.available ? browserTor(b, reload) : null,
      b.installed ? browserFiles(b, data, reload) : null);
  });
  const picker = pathPicker(data, { label: "Or an archive you downloaded (its .asc signature beside it)" });
  const use = h("button", { class: "small", disabled: !usable }, "Check and unpack");
  use.addEventListener("click", async () => {
    const path = picker.input.value.trim();
    if (!path) { toast("Choose the .tar.xz archive first.", "error"); return; }
    try { await api("POST", "/api/tools/browser/get", { archive: path, vpn: browserSetup.vpn }); await reload(); }
    catch (e) { toast(e.message, "error", 10000); }
  });
  return [h("div", { class: "toolgrid" }, cards), h("div", { class: "small" }, picker.row,
    h("div", { class: "muted" }, "Checking it first asks the project's server (aus1.torproject.org, or cdn.mullvad.net) "
      + "which version is the latest, directly, and refuses an older archive. Where that server can't be reached (blocked "
      + "where you are, say, and the archive came from GetTor or a mirror), it accepts one whose signature was made in the "
      + "last 30 days, and says so."),
    proxyWarning(data, ["aus1.torproject.org or cdn.mullvad.net"]),
    h("div", { class: "orow" }, use))];
}

const fmtWhen = (secs) => new Date(secs * 1000).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });

// The download and the version checks go out directly, never through a proxy set in the environment (as the online
// tests): said before either, as the online tests' dialog does.
function proxyWarning(data, hosts) {
  if (!data.proxy_vars?.length) return null;
  return h("div", { class: "warnbox bad small" }, `Your proxy settings (${data.proxy_vars.join(", ")}) are not used: `
    + `this connects directly, so ${hosts.join(" and ")} see${hosts.length === 1 ? "s" : ""} this computer's own address, not `
    + "the proxy's. If the proxy is what hides your address, don't go on from here.");
}

function browserDownload(b, data, reload) {
  modal({ title: `Download ${b.name}?`, body: [
    h("p", {}, `This contacts ${b.hosts.join(" and ")}, the project's own servers: to learn the latest version, then for `
      + "the archive (about 120–140 MB) and its signature. They see this computer's address, as with any download; "
      + "nothing else about it is sent."),
    proxyWarning(data, b.hosts),
    h("p", { class: "small muted" }, "The download goes straight into the RAM disk. The signature is checked against the "
      + "Tor Browser Developers key the app carries, and nothing is unpacked unless it is verified."),
    b.id === "mullvad" ? h("p", { class: "small" }, browserSetup.vpn
      ? "It is set up for Mullvad VPN (the tick on its card): no page loads unless Mullvad VPN is connected."
      : "It isn't set up for Mullvad VPN (the tick on its card): it starts as the browser leaves it.") : null,
  ], buttons: [{ label: "Cancel" }, { label: "Download", kind: "primary", onclick: async (close, el) => {
    el.disabled = true;
    try { await api("POST", "/api/tools/browser/get", { browser: b.id, vpn: browserSetup.vpn }); close(); await reload(); }
    catch (e) { close(); toast(e.message, "error", 10000); }
  } }] });
}

function browserJob(job, data, reload) {
  if (!job) return null;
  const dismiss = h("button", { class: "small", onclick: async () => { await api("POST", "/api/tools/browser/dismiss"); await reload(); } }, "OK");
  if (job.state === "running") {
    const frac = job.total ? Math.min(1, job.done / job.total) : null;
    return h("div", { class: "trim-progress" },
      h("div", { class: "orow" }, h("b", {}, job.name), h("span", { class: "small" }, job.phase || "…"),
        job.total ? h("span", { class: "small muted" }, `${fmtSize(job.done)} of ${fmtSize(job.total)}`) : null),
      frac != null ? h("div", { class: "obar" }, h("div", { style: `width: ${Math.round(frac * 100)}%` })) : null,
      h("div", { class: "orow" }, h("button", { class: "small", disabled: job.stopping,
        onclick: async () => { await api("POST", "/api/tools/browser/stop"); await reload(); } }, job.stopping ? "Stopping…" : "Stop")));
  }
  if (job.state === "done") {
    const v = job.verdict || {};
    return h("div", { class: "notebox info small" },
      h("b", {}, `${job.name}${job.version ? " " + job.version : ""} is in the RAM disk. `),
      `${v.title || "Verified"}: signed by ${v.signer || "Tor Browser Developers"} (${(v.fingerprint || "").replace(/(.{4})/g, "$1 ").trim()}).`,
      job.warning ? h("div", { class: "warnbox small" }, job.warning) : null,
      h("div", { class: "orow" }, dismiss));
  }
  return h("div", { class: job.state === "failed" ? "warnbox" : "notebox info small" }, job.error || "Stopped.",
    h("div", { class: "orow" }, dismiss));
}

function browserLimits(data) {
  return h("div", { class: "small muted" }, h("b", {}, "What this doesn't cover: "),
    "what you copy (a clipboard manager keeps it: see the clipboard check), files you copy out with Save… (they leave "
    + "memory then), and what websites and your network can see while you browse. "
    + (data.ramdisk.noswap === false && data.ramdisk.open ? "This kernel can't keep ~/TempBrowser out of swap. " : "")
    + "Closing ~/TempBrowser is refused while the browser runs: quit it first.");
}

// ------------------------------------------------------------------ the TRIM test
// A background job on the server (it reads the whole disk two or three times); this follows it while
// the dialog is open. The result is shown and can be copied, never kept.

const TRIM_CLASS = { pass: "ok", fail: "bad", inconclusive: "warn", not_run: "warn" };

const fmtMinutes = (s) => s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`
  : s >= 60 ? `${Math.round(s / 60)} min` : `${Math.max(1, Math.round(s))} s`;

// ------------------------------------------------------------------ Try an app
// A program the user doesn't know yet, in a sandbox with a throwaway home: prepared, started, watched, summed up,
// discarded. One trial at a time; everything of it is gone when it is discarded or the app quits.

const TRIAL_KIND = { appimage: "An AppImage", program: "A program", script: "A script", archive: "An archive",
  deb: "A .deb package", installed: "An installed app", flatpak: "A Flatpak app" };

async function openTrial(reloadTools) {
  let data;
  try { data = await api("GET", "/api/tools/trial"); } catch (e) { toast(e.message, "error"); return; }
  const body = h("div", { class: "activity trial" });
  let timer = null, closed = false;
  const shut = () => { closed = true; clearTimeout(timer); reloadTools?.(); };
  const m = modal({ title: "Try an app", wide: true, body, buttons: [{ label: "Close", kind: "primary",
    onclick: (close) => { shut(); close(); } }] });
  const overlay = m.box.parentElement;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) shut(); });
  const take = (r) => { data = { ...data, trial: r.trial }; render(); };
  const call = async (path, payload, btn, busy) => {
    const label = btn?.textContent;
    if (btn) { btn.disabled = true; if (busy) btn.textContent = busy; }
    try { take(await api("POST", path, payload || {})); return true; }
    catch (e) { toast(e.message, "error", 12000); if (btn) { btn.disabled = false; btn.textContent = label; } return false; }
  };
  const follow = () => {
    clearTimeout(timer);
    if (!closed) timer = setTimeout(async () => {
      try { take(await api("GET", "/api/tools/trial/status")); } catch (e) { toast(e.message, "error"); }
    }, 1500);
  };
  const render = () => {
    const t = data.trial;
    if (!t) fill(body, trialChoose(data, call));
    else if (t.state === "ready") fill(body, trialReady(data, t, call));
    else if (t.state === "running") { fill(body, trialRunning(t, call)); follow(); }
    else fill(body, trialResult(t, call));
  };
  render();
}

function trialChoose(data, call) {
  const st = data.status;
  let where = "memory", file = null;
  const places = st.places.map(p => h("label", { class: "check" },
    h("input", { type: "radio", name: "trial-where", checked: p.id === where, onchange: () => { where = p.id; } }),
    h("span", {}, `${p.words} (${fmtSize(p.free)} free)`),
    h("span", { class: "small muted" }, p.id === "memory" ? " nothing of the trial touches the disk; overwritten when discarded"
      : " for something large; deleted when discarded, which doesn't erase it from the disk")));
  const picker = pathPicker(data, { label: "File", onPick: (paths) => { file = paths[0]; } });
  const tryFile = h("button", { class: "primary", disabled: !st.available }, "Prepare it");
  tryFile.addEventListener("click", () => {
    const path = (picker.input.value || file || "").trim();
    if (!path) { toast("Choose a file first.", "info"); return; }
    call("/api/tools/trial/prepare", { path, where }, tryFile, "Copying it in…");
  });
  const pick = appChooser(data.apps, "trial-app");
  const tryApp = h("button", { class: "primary", disabled: !st.available }, "Try it with a throwaway home");
  tryApp.addEventListener("click", () => {
    const app = pick.chosen();
    if (!app) { toast("Choose an app first.", "info"); return; }
    call("/api/tools/trial/prepare", { app: app.id, where }, tryApp, "Preparing…");
  });
  return [
    !st.available ? h("div", { class: "warnbox" }, `Trials can't run here: ${st.why}`
      + (st.apparmor ? " The Tor or Mullvad Browser tool's panel gives the two ways round it." : "")) : null,
    h("p", {}, "Run a program you don't know yet where it can do no harm: in a sandbox, with a made-up home folder in "
      + "place of yours. None of your files, keys or accounts are within its reach. You see what it writes, which "
      + "decoy files it looks at, and which hosts it contacts if you let it online. Then everything of it is discarded."),
    h("ul", { class: "small" },
      h("li", {}, h("b", {}, "The file you choose isn't changed or run where it is: "), "a copy is tried."),
      h("li", {}, h("b", {}, "A sandbox isn't a guarantee. "), "It keeps a program from your files and, without a network, "
        + "from sending anything. A program made to break out of sandboxes through a flaw in the kernel isn't stopped by "
        + "it: don't run what you know to be hostile."),
      h("li", {}, h("b", {}, "A trial shows what a program does while you watch, "), "not what it would do next week.")),
    h("h4", {}, "Where the trial lives"), places,
    h("h4", {}, "A file you downloaded"),
    h("p", { class: "small muted" }, "An AppImage, a program, a script, an archive (tar, zip) or a .deb package. An archive "
      + "or package is unpacked inside a sandbox; a .deb is never installed."),
    picker.row, h("div", { class: "orow" }, tryFile),
    h("h4", {}, "Or an app that is installed"),
    h("p", { class: "small muted" }, "Started with a throwaway home, as on a first run: your real profile isn't touched. "
      + "A Flatpak app runs in Flatpak's own sandbox with the permissions it declares for itself dropped."),
    pick.el, h("div", { class: "orow" }, tryApp)];
}

function trialReady(data, t, call) {
  const st = data.status, flat = t.kind === "flatpak";
  let program = t.candidates[0]?.rel || "";
  const o = { network: "off", gpu: !!st.gpu, sound: false, nested: false, decoys: true };
  const args = h("input", { type: "text", class: "path", autocomplete: "off", spellcheck: "false", placeholder: "none",
    "aria-label": "Arguments" });
  const radio = (value, label, note, disabled) => h("label", { class: "check" },
    h("input", { type: "radio", name: "trial-net", checked: o.network === value, disabled, onchange: () => { o.network = value; } }),
    h("span", {}, label), note ? h("span", { class: "small muted" }, ` ${note}`) : null);
  const tick = (key, label, note, shown = true) => shown ? h("label", { class: "check" },
    h("input", { type: "checkbox", checked: o[key], onchange: (e) => { o[key] = e.target.checked; } }),
    h("span", {}, label), note ? h("span", { class: "small muted" }, ` ${note}`) : null) : null;
  const start = h("button", { class: "primary" }, "Start the trial");
  start.addEventListener("click", () => call("/api/tools/trial/start", { ...o, program, args: args.value }, start, "Starting…"));
  const discard = h("button", { class: "small" }, "Discard it");
  discard.addEventListener("click", () => call("/api/tools/trial/discard", {}, discard, "Discarding…"));
  const pasta = st.pasta || {};
  return [
    h("p", {}, h("b", {}, t.name), ` — ${TRIAL_KIND[t.kind] || t.what}. Nothing has run yet.`),
    t.notes.map(n => h("div", { class: "notebox info small" }, n)),
    t.candidates.length ? [h("h4", {}, "Which program in it to start"),
      h("div", { class: "applist" }, t.candidates.map(c => h("label", {},
        h("input", { type: "radio", name: "trial-prog", checked: c.rel === program, onchange: () => { program = c.rel; } }),
        h("code", {}, c.rel), h("span", { class: "small muted" }, `${c.what}${c.label ? `: ${c.label}` : ""}`))))] : null,
    h("div", { class: "orow" }, h("span", { class: "small muted" }, "Arguments for it"), args),
    h("h4", {}, "Network"),
    radio("off", "None", "it can reach nothing: not the internet, not this computer, not your network"),
    flat ? radio("on", "Its usual network", "Flatpak's sandbox can't be put behind the observer: what it contacts isn't listed")
      : radio("observed", "Its own, observed", pasta.available && pasta.lan_blocked
          ? "the internet only, your local network fenced off; the hosts it contacts are listed"
          : `needs pasta${pasta.install ? ` (${pasta.install})` : ""}`, !(pasta.available && pasta.lan_blocked)),
    h("h4", {}, "What it gets"),
    tick("decoys", "Decoy files in its home", "made-up SSH keys, browser profiles, wallets and documents: a program that opens them has gone looking"),
    tick("gpu", "The graphics card", "so it draws as it would outside; its drivers then handle what the program sends them", !!st.gpu),
    tick("sound", "Sound", "this also gives it the microphone", !!st.sound),
    tick("nested", "A display of its own", "it can't see or type into your other windows (needs Xephyr); no copy and paste with them",
      st.display === "x11" && !flat && !!st.xephyr?.available),
    st.display === "x11" ? h("div", { class: "notebox risk small" }, h("b", {}, "This is an X11 session. "),
        "Any program with a window can read what other windows show and what you type into them, and type into them. "
        + "Close anything sensitive first" + (flat || !st.xephyr?.available ? "." : ", or give it a display of its own."))
      : st.wayland_context === true && !flat ? h("div", { class: "small muted" }, "Its window is on a connection the desktop "
        + "marks as a sandbox's.") : null,
    h("div", { class: "orow" }, start, discard, keepAsBox(t))];
}

// a trial of a downloaded program can be kept: the Box's guide starts on it
function keepAsBox(t) {
  const spec = S.state.catalogue.find(s => s.id === "app.boxes");
  if (!spec || ["installed", "flatpak"].includes(t.kind)) return null;
  return h("button", { class: "small", title: "Keep this program in a sandbox for good, with a home folder of its own: "
    + "a guide, undone from History", onclick: () => openGuide(spec) }, "Keep it in a Box…");
}

function trialHow(how) {
  const net = { off: "no network", observed: "its own network, observed, your local network fenced off", on: "its usual network, not observed" };
  return [how.engine_name, net[how.network], how.nested ? "a display of its own" : how.display === "wayland" ? "Wayland" : "X11",
    how.gpu ? "the graphics card" : "no graphics card", how.sound ? "sound" : null,
    how.decoys ? `${how.decoys} decoy files` : "no decoys"].filter(Boolean).join(" · ");
}

function decoyList(decoys) {
  return h("ul", { class: "named" }, decoys.map(d => h("li", {}, h("b", {}, d.what), " (", h("code", {}, d.path), ") — ",
    [d.changed ? "changed" : null, d.opened ? `opened ${d.opened > 1 ? `${d.opened} times` : "once"}` : null,
     d.listed ? "its contents listed" : null].filter(Boolean).join(", "))));
}

function hostsTable(hosts) {
  return h("table", { class: "places" },
    h("thead", {}, h("tr", {}, h("th", {}, "Host"), h("th", {}, "Ports"), h("th", {}, "Connections"), h("th", {}, "Sent"), h("th", {}, "Received"))),
    h("tbody", {}, hosts.map(x => h("tr", {}, h("td", { class: "folder", title: x.named_by === "dns" ? "The name it looked up"
        : x.named_by === "tls" ? "The name it gave when connecting" : "It connected to the address without looking up a name" }, x.host),
      h("td", {}, x.ports.join(", ")), h("td", {}, `${x.connections}`), h("td", {}, fmtSize(x.sent)), h("td", {}, fmtSize(x.received))))));
}

function trialRunning(t, call) {
  const live = t.live || {};
  const stop = h("button", { class: "primary" }, "End the trial");
  stop.addEventListener("click", () => call("/api/tools/trial/stop", {}, stop, "Ending…"));
  return [
    h("p", {}, h("b", {}, `${t.name} is running in its sandbox`), t.started ? ` (${fmtMinutes(Math.max(0, t.now - t.started))}).` : ".",
      " Use it as you would; close it, or end the trial here, to see what it did."),
    h("div", { class: "small muted" }, trialHow(t.how)),
    h("div", { class: "tally" },
      h("span", {}, h("b", {}, `${live.written ?? 0}`), " files written"),
      h("span", {}, h("b", {}, `${live.decoys ?? 0}`), " decoys looked at"),
      live.hosts ? h("span", {}, h("b", {}, `${live.hosts.length}`), " hosts contacted") : null),
    live.decoys_seen?.length ? [h("div", { class: "warnbox" }, "It is looking at decoy files:"), decoyList(live.decoys_seen)] : null,
    live.hosts?.length ? hostsTable(live.hosts) : null,
    h("div", { class: "orow" }, stop)];
}

function trialResult(t, call) {
  const r = t.result, s = r.summary, opened = r.decoys.filter(d => d.opened || d.changed), listed = r.decoys.filter(d => !d.opened && !d.changed);
  const discard = h("button", { class: "primary" }, "Discard the trial");
  discard.addEventListener("click", () => call("/api/tools/trial/discard", {}, discard, "Discarding…"));
  return [
    h("p", {}, h("b", {}, t.name), ` ran for ${fmtMinutes(r.seconds)} and `, r.ended || (t.stopped ? "was ended here" : r.failed
      ? `ended with an error (exit status ${t.exit})` : "ended by itself"), "."),
    h("div", { class: "small muted" }, trialHow(t.how)),
    r.output.length ? h("details", { class: "small", open: r.failed }, h("summary", {}, "What it printed last"),
      h("pre", { class: "output" }, r.output.join("\n"))) : null,
    h("h4", {}, "Decoy files"),
    !r.decoys_planted ? h("p", { class: "small muted" }, "None were put in its home.")
      : opened.length ? [h("div", { class: "warnbox bad" }, `It opened ${plural(opened.length, "decoy file")} of ${r.decoys_planted}. `
          + "These stand for your keys, saved logins and wallets: a program that reads them without being asked to has gone "
          + "looking. An app opening its own kind of profile (a browser, Firefox's) is the exception."), decoyList(opened)]
      : h("p", { class: "small" }, `It opened none of the ${r.decoys_planted} decoy files (made-up SSH keys, browser profiles, `
          + "wallets, documents) while it ran."),
    listed.length ? h("details", { class: "small" }, h("summary", {}, `Folders it looked into (${listed.length})`), decoyList(listed)) : null,
    h("h4", {}, "Network"),
    r.network === "off" ? h("p", { class: "small" }, "It had no network.")
      : r.network === "on" ? h("p", { class: "small" }, "It had its usual network; what it contacted wasn't observed.")
      : r.hosts.hosts.length ? [h("p", { class: "small" }, `It contacted ${plural(r.hosts.hosts.length, "host")}. What it sent is `
          + "encrypted and can't be read; the names are the ones it asked for."), hostsTable(r.hosts.hosts),
          r.hosts.looked_up.length ? h("div", { class: "small muted" }, "Looked up and not connected to: " + r.hosts.looked_up.join(", ") + ".") : null]
      : h("p", { class: "small" }, "It could reach the internet and contacted nothing."
          + (r.hosts.looked_up.length ? ` It looked up: ${r.hosts.looked_up.join(", ")}.` : "")),
    h("h4", {}, "What it wrote in its home"),
    s.places.length ? [h("p", { class: "small muted" }, `${plural(r.left.files, "file")} (${fmtSize(r.left.bytes)}) are there now, `
        + "besides the decoys. On your computer these would be in your home folder."), placesTable(s)]
      : h("p", { class: "small" }, "Nothing."),
    s.regular.length ? [h("h4", {}, "Files it writes to all the time"),
      h("ul", { class: "named" }, s.regular.map(f => h("li", {}, h("code", {}, f.path), ` — ${f.type}, ${plural(f.writes, "write")}`)))] : null,
    r.missed ? h("div", { class: "small muted" }, "It did more than could be recorded: some of it is missing above.") : null,
    h("details", { class: "small" }, h("summary", {}, "The command that ran it"), commandBlock([t.how.whole])),
    h("div", { class: "orow" }, discard, keepAsBox(t), h("span", { class: "small muted" }, t.where === "memory"
      ? "Its folder is in memory: discarding overwrites and removes it."
      : "Its folder is on the disk: discarding deletes it, which doesn't erase it. Disk encryption is what protects deleted data."))];
}

// ------------------------------------------------------------------ Boxes
// Apps kept in a sandbox for good (the catalogue's app.boxes): started here as from the menu, each with its runs
// in numbers. Set up through the guide; removed by reverting in History.

const BOX_NET = { off: "no network", observed: "its own network, observed", on: "its usual network" };

async function openBoxes() {
  const body = h("div", { class: "activity boxes" });
  let timer = null, closed = false;
  const m = modal({ title: "Boxes", wide: true, body, buttons: [{ label: "Close", kind: "primary",
    onclick: (close) => { closed = true; clearTimeout(timer); close(); } }] });
  const overlay = m.box.parentElement;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) { closed = true; clearTimeout(timer); } });
  const spec = S.state.catalogue.find(s => s.id === "app.boxes");
  const load = async () => {
    let data;
    try { data = await api("GET", "/api/tools/boxes"); } catch (e) { toast(e.message, "error"); return; }
    fill(body, boxesBody(data.boxes, spec, load));
    clearTimeout(timer);
    if (!closed && data.boxes.some(b => b.running)) timer = setTimeout(load, 3000);
  };
  await load();
}

function boxesBody(boxes, spec, reload) {
  const act = (path, b, btn, after) => async () => {
    btn.disabled = true;
    try { await api("POST", path, { box: b.slug }); after?.(); setTimeout(reload, 1200); }
    catch (e) { toast(e.message, "error", 10000); btn.disabled = false; }
  };
  const when = (t) => new Date(t * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  return [
    h("p", { class: "small muted" }, "Each app here runs in a sandbox with a home folder of its own in ~/Boxes. It starts "
      + "from the menu too, as “NAME (in its Box)”. To remove one, revert it in History."),
    boxes.length ? boxes.map(b => {
      const start = h("button", { class: "small primary", disabled: b.running || !!b.problem }, b.running ? "Running" : "Start");
      start.addEventListener("click", act("/api/tools/boxes/start", b, start, () => toast(`${b.name} is starting in its Box.`, "ok")));
      const show = h("button", { class: "small" }, "Open its Exchange folder");
      show.addEventListener("click", act("/api/tools/boxes/show", b, show));
      const clear = h("button", { class: "small ghost" }, "Forget its runs");
      clear.addEventListener("click", act("/api/tools/boxes/clear", b, clear));
      return h("div", { class: "box-card" },
        h("div", { class: "orow" }, h("b", {}, b.name), h("span", { class: "small muted" },
          `${BOX_NET[b.network]} · ${b.gpu ? "the graphics card" : "no graphics card"}${b.sound ? " · sound" : ""}`),
          h("span", { class: "spacer" }), start, show),
        h("div", { class: "small muted" }, "Its home: ", h("code", {}, `${b.folder}/home`), ". Files go in and out through ",
          h("code", {}, b.exchange), b.kind === "flatpak" ? ", at that same path inside." : ", which it sees as ~/Exchange."),
        b.problem ? h("div", { class: "warnbox small" }, `It can't start: ${b.problem}.`) : null,
        !b.launcher ? h("div", { class: "warnbox small" }, "Its menu entry is missing, or starts another copy of the app. ",
          spec ? h("button", { class: "small", onclick: () => openGuide(spec) }, "Write it again…") : null) : null,
        b.runs.length ? h("details", { class: "small" }, h("summary", {}, `Its last ${plural(b.runs.length, "run")}, in numbers`),
          h("table", { class: "places" },
            h("thead", {}, h("tr", {}, h("th", {}, "Started"), h("th", {}, "Lasted"), h("th", {}, "Files written"),
              h("th", {}, "Hosts contacted"), h("th", { title: "Hosts it had never contacted in an earlier run" }, "New hosts"),
              h("th", {}, "Sent"))),
            h("tbody", {}, b.runs.map(r => h("tr", {}, h("td", { class: "folder" }, when(r.when) + (r.failed ? (r.signal ? ` (crashed, ${r.signal})` : " (ended with an error)")
                : r.signal ? ` (ended by ${r.signal})` : "")),
              h("td", {}, fmtMinutes(r.seconds)), h("td", {}, `${r.written}`),
              h("td", { class: r.hosts === null ? "zero" : "" }, r.hosts === null ? (r.network === "off" ? "no network" : "not observed") : `${r.hosts}`),
              h("td", { class: r.new_hosts ? "" : "zero" }, r.new_hosts === null ? "" : `${r.new_hosts}`),
              h("td", {}, r.sent === null ? "" : fmtSize(r.sent)))))),
          h("div", { class: "orow" }, clear, h("span", { class: "muted" }, "Numbers only: no names of sites or files are kept.")))
          : h("div", { class: "small muted" }, "It hasn't run yet."));
    }) : h("p", {}, "No Box is set up yet."),
    spec ? h("div", { class: "orow" }, h("button", { class: "small", onclick: () => openGuide(spec) }, "Set up another…")) : null];
}

// ------------------------------------------------------------------ What does this app keep?
// One app from the menu, started and watched for as long as the user leaves it on; then where it read and wrote.
// Counts per folder: the files a person opened are never listed (that list would be a recent-files record itself).

const APP_KIND = { native: "", flatpak: "Flatpak", snap: "Snap" };

// a list of the menu's apps to pick one from, with a filter; returns { el, chosen() }
function appChooser(apps, name) {
  let chosen = null;
  const list = h("div", { class: "applist" });
  const draw = (q) => fill(list, apps.filter(a => !q || `${a.name} ${a.command}`.toLowerCase().includes(q)).map(a =>
    h("label", {}, h("input", { type: "radio", name, checked: a.id === chosen, onchange: () => { chosen = a.id; } }),
      h("span", {}, a.name), APP_KIND[a.kind] ? h("span", { class: "kindtag" }, APP_KIND[a.kind]) : null,
      h("span", { class: "small muted" }, a.comment || ""))));
  const filter = h("input", { type: "search", autocomplete: "off", spellcheck: "false", placeholder: "Find an app…",
    "aria-label": "Find an app", oninput: (e) => draw(e.target.value.trim().toLowerCase()) });
  draw("");
  return { el: h("div", {}, h("div", { class: "orow" }, filter), list), chosen: () => apps.find(a => a.id === chosen) || null };
}

async function openKeeps() {
  let data;
  try { data = await api("GET", "/api/tools/keeps"); } catch (e) { toast(e.message, "error"); return; }
  const body = h("div", { class: "activity" });
  let timer = null, closed = false;
  const m = modal({ title: "What does this app keep?", wide: true, body, buttons: [{ label: "Close", kind: "primary",
    onclick: (close) => { closed = true; clearTimeout(timer); close(); } }] });
  const overlay = m.box.parentElement;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) { closed = true; clearTimeout(timer); } });
  const reload = async () => {
    try { data = await api("GET", "/api/tools/keeps"); render(); } catch (e) { toast(e.message, "error"); }
  };
  const follow = () => { clearTimeout(timer); if (!closed) timer = setTimeout(reload, 2000); };
  const render = () => {
    const job = data.job;
    S.adminActive = !!data.admin_active; renderTop();
    if (job && ["asking", "running", "ending"].includes(job.state)) { fill(body, keepsProgress(job, reload)); follow(); return; }
    if (job && job.state === "done" && job.result) { fill(body, keepsResult(job, reload)); return; }
    fill(body, keepsStart(data, job, reload));
  };
  render();
}

function keepsStart(data, job, reload) {
  const pick = appChooser(data.apps, "keeps-app");
  const btn = h("button", { class: "primary", disabled: !!data.unavailable }, "Start the app and watch it");
  btn.addEventListener("click", async () => {
    const app = pick.chosen();
    if (!app) { toast("Choose an app first.", "info"); return; }
    btn.disabled = true;
    btn.textContent = S.adminActive ? "Starting…" : "Waiting for authorization…";
    try { await api("POST", "/api/tools/keeps/start", { app: app.id }); await reload(); }
    catch (e) { toast(e.message, "error", 10000); btn.disabled = false; btn.textContent = "Start the app and watch it"; }
  });
  return [
    job && job.state === "failed" ? h("div", { class: "warnbox bad" }, `The last watch failed: ${job.error}`) : null,
    data.unavailable ? h("div", { class: "warnbox" }, data.unavailable) : null,
    h("p", {}, "The scan knows where many apps keep their data, but not every app. This shows what one app does on this "
      + "computer, whether the scan knows it or not: pick it, use it as you normally would, then end the watch and see "
      + "where it read and wrote."),
    h("div", { class: "notebox risk" }, h("b", {}, "Administrator access for the whole time. "), data.warning),
    h("ul", { class: "small" },
      h("li", {}, h("b", {}, "Close the app first. "), "It is started from here, so that everything it does is seen "
        + "from its first moment."),
      h("li", {}, h("b", {}, "What you get: "), "its own folders with how many files it read, changed, made and "
        + "deleted; the files it writes to all the time, by name; which of your own folders it opened files in, as "
        + "counts; and which files, written meanwhile by it or by another program, hold the names of what you opened."),
      h("li", {}, h("b", {}, "Nothing is kept. "), "The result stays in this window's memory until you dismiss it or "
        + "quit: it isn't saved, put in a report or exported, since a list of what you opened is itself a record.")),
    h("details", { class: "small" }, h("summary", {}, "What it can't see"), h("ul", {}, data.limits.map(t => h("li", {}, t)))),
    h("h4", {}, "App to watch"),
    pick.el,
    h("div", { class: "orow" }, btn)];
}

function keepsProgress(job, reload) {
  const stop = h("button", { class: "primary", disabled: job.stopping || job.state !== "running" },
    job.stopping || job.state === "ending" ? "Ending…" : "End the watch and show what it did");
  stop.addEventListener("click", async () => {
    stop.disabled = true; stop.textContent = "Ending…";
    try { await api("POST", "/api/tools/keeps/stop"); await reload(); } catch (e) { toast(e.message, "error"); }
  });
  if (job.state === "asking") return [h("p", {}, `Waiting for administrator access to watch ${job.app}…`)];
  const c = job.counts || {};
  const since = job.started ? fmtMinutes(Math.max(0, job.now - job.started)) : "";
  return [
    h("p", {}, h("b", {}, `Watching ${job.app}`), since ? ` for ${since}. ` : ". ",
      "Use it as you normally do, with everything you usually do in it, then end the watch here."),
    h("div", { class: "notebox risk small" }, "Administrator access is held until you end the watch: end it as soon as "
      + "is practical."),
    h("div", { class: "tally" },
      h("span", {}, h("b", {}, `${c.files ?? 0}`), " files touched by the app"),
      h("span", {}, h("b", {}, `${c.others ?? 0}`), " written by your other programs meanwhile"),
      h("span", { class: "muted" }, `${c.events ?? 0} events seen`)),
    job.closed ? h("div", { class: "notebox info" }, `${job.app} has closed. End the watch to see what it did.`) : null,
    job.absent ? h("div", { class: "warnbox" }, `${job.app} doesn't seem to have started, or it handed over to a copy `
      + "that was already running, which isn't watched. End the watch, close the app everywhere, and try again.") : null,
    job.quiet ? h("div", { class: "warnbox" }, `${job.app} is running but hasn't opened a single file of yours or of its `
      + "own: it may have handed over to a copy that was already running (a window elsewhere, or one in the background), "
      + "which isn't watched. If so, end the watch, close the app everywhere, and try again.") : null,
    c.overflow ? h("div", { class: "warnbox" }, "The computer was too busy for every event to be recorded: some of what "
      + "happened is missing.") : null,
    (job.not_watched || []).length ? h("div", { class: "small muted" }, "Not watched: "
      + job.not_watched.map(([m, why]) => `${m} (${why})`).join("; ") + ".") : null,
    h("div", { class: "orow" }, stop)];
}

// folders with counts, by kind; `named`: a trial's own files may be listed under their folder
function placesTable(r) {
  const cell = (n) => h("td", { class: n ? "" : "zero" }, `${n}`);
  const rows = [];
  let kind = null;
  for (const p of r.places) {
    if (p.kind !== kind) { kind = p.kind; rows.push(h("tr", { class: "kind" }, h("td", { colspan: 6 }, r.kinds[kind] || kind))); }
    rows.push(h("tr", {}, h("td", { class: "folder" }, p.folder), cell(p.opened), cell(p.written), cell(p.created), cell(p.deleted),
      h("td", { class: p.left ? "" : "zero" }, p.left ? `${p.left} (${fmtSize(p.bytes)})` : "0")));
    if (p.files?.length) rows.push(h("tr", {}, h("td", { colspan: 6, class: "folder" }, h("details", { class: "small" },
      h("summary", {}, `Its files (${p.files.length}${p.files.length >= 60 ? ", the first" : ""})`),
      h("ul", { class: "named" }, p.files.map(f => h("li", {}, h("code", {}, f.name), ` ${f.did}`)))))));
  }
  return h("table", { class: "places" },
    h("thead", {}, h("tr", {}, h("th", {}, "Folder"), h("th", { title: "Opened, not changed" }, "Read"),
      h("th", { title: "Files that were there, changed" }, "Changed"), h("th", {}, "Made"), h("th", {}, "Deleted"),
      h("th", { title: "Files it made or changed that are there now" }, "Left there"))),
    h("tbody", {}, rows));
}

function keepsResult(job, reload) {
  const r = job.result, rec = r.records, t = r.totals;
  const dismiss = h("button", { class: "small" }, "Dismiss this result");
  dismiss.addEventListener("click", async () => {
    try { await api("POST", "/api/tools/keeps/dismiss"); await reload(); } catch (e) { toast(e.message, "error"); }
  });
  return [
    h("p", {}, h("b", {}, r.app), ` was watched for ${fmtMinutes(r.seconds)}. It read ${plural(t.opened, "file")}, changed `
      + `${t.written}, made ${t.created} and deleted ${t.deleted}`
      + (r.system.length ? `, besides ${r.system.reduce((n, s) => n + s.files, 0)} of the system's own (programs, libraries, settings).` : ".")),
    !r.files ? h("div", { class: "warnbox" }, `${r.app} opened no file of yours or of its own. If a copy of it was already `
      + "running (a window elsewhere, or one in the background), it handed its work to that copy, which wasn't watched: "
      + "close it everywhere and watch it again. What that copy wrote shows below, under your other programs.") : null,
    h("h4", {}, "Who recorded what you opened"),
    rec.names === 0 ? h("p", { class: "small muted" }, "It opened none of your own files (outside programs' data folders), "
        + "so there was nothing to look for.")
      : rec.found.length ? [
        h("p", { class: "small" }, `${plural(rec.found.length, "file")} written during the watch `
          + `${rec.found.length > 1 ? "hold" : "holds"} the names of your files it opened (${rec.names} looked for). These `
          + "are where a record of what you opened is kept:"),
        h("ul", { class: "named" }, rec.found.map(f => h("li", {}, h("code", {}, f.path), ` — ${f.type}, written by `
          + `${f.who ? `another program (${f.who})` : "the app itself"}: ${plural(f.names, "name")}`)))]
      : h("p", { class: "small" }, `No file written during the watch holds the names of the ${plural(rec.names, "file")} of `
        + "yours it opened, as plain text. A compressed or encrypted store could still hold them."),
    rec.skipped ? h("div", { class: "small muted" }, `${plural(rec.skipped, "file")} too large or too many to read `
      + `${rec.skipped > 1 ? "were" : "was"} not searched.`) : null,
    r.regular.length || r.regular_yours ? [h("h4", {}, "Files it writes to all the time"),
      r.regular.length ? h("ul", { class: "named" }, r.regular.map(f => h("li", {}, h("code", {}, f.path), ` — ${f.type}, `
        + `${fmtSize(f.size)}, written in ${plural(f.minutes, "different minute")} (${plural(f.writes, "write")})`))) : null,
      r.regular_yours ? h("p", { class: "small muted" }, `${r.regular.length ? "Besides these, " : ""}`
        + `${plural(r.regular_yours, "file")} of your own, saved again and again: counted, not named, since they are `
        + "your documents.") : null] : null,
    r.sensitive.length ? [h("h4", {}, "Sensitive places it opened"),
      h("p", { class: "small muted" }, "An app opening its own profile is expected; anything else here deserves a second look."),
      h("ul", { class: "named" }, r.sensitive.map(x => h("li", {}, `${x.what}: ${plural(x.opened, "file")} read`
        + (x.written ? `, ${x.written} changed` : ""))))] : null,
    h("h4", {}, "Where it read and wrote"),
    h("p", { class: "small muted" }, `Your own files are counted, never listed: ${r.yours.opened} read, ${r.yours.changed} changed.`),
    r.places.length ? placesTable(r) : h("p", { class: "small muted" }, "Nothing outside the system's own folders."),
    r.places_left_out ? h("div", { class: "small muted" }, `${r.places_left_out} more folders aren't shown.`) : null,
    r.others || r.others_changes ? h("details", { class: "small" }, h("summary", {}, "What your other programs wrote "
        + `meanwhile (${[r.others ? plural(r.others, "file") : "", r.others_changes ? plural(r.others_changes, "change")
          : ""].filter(Boolean).join(", ")})`),
      h("p", { class: "muted" }, "An app that hands its work to a background program of its own, or to a copy that was "
        + "already running, shows here; so does everything else that was running. Counted per folder (in your own "
        + "folders and on other disks, changes rather than files):"),
      h("ul", { class: "named" }, (r.others_places || []).map(o => h("li", {}, h("code", {}, o.folder || "other folders"),
        ` — ${[o.files ? plural(o.files, "file") : "", o.changes ? plural(o.changes, "change") : ""].filter(Boolean)
          .join(", ")}, by ${o.who}`)))) : null,
    r.gone.length ? h("details", { class: "small" }, h("summary", {}, "By programs that ended before they could be identified"),
      h("ul", { class: "named" }, r.gone.map(g => h("li", {}, h("code", {}, g.folder), `: ${plural(g.events, "event")}`)))) : null,
    h("details", { class: "small" }, h("summary", {}, "How complete this is"),
      h("ul", {},
        h("li", {}, `${r.events} events seen on ${r.watched.join(", ")}; ${r.foreign} by other accounts or the system, not kept.`),
        r.not_watched.length ? h("li", {}, "Not watched: " + r.not_watched.map(([m, why]) => `${m} (${why})`).join("; ") + ".") : null,
        r.overflow ? h("li", {}, "The computer was too busy for every event to be recorded: some of what happened is missing.") : null,
        r.unresolved ? h("li", {}, `${r.unresolved} couldn't be tied to a file (its folder was gone by then).`) : null,
        r.folded ? h("li", {}, `${r.folded} files past the first 60,000 weren't kept one by one.`) : null,
        r.by_date ? h("li", {}, `${plural(r.by_date, "file")} of its own it only opened changed meanwhile, as `
          + `${r.by_date > 1 ? "their dates say" : "its date says"}: written through memory, as databases do, which `
          + "isn't seen as it happens. Counted as changed.") : null,
        r.others_left ? h("li", {}, `${plural(r.others_left, "change")} by your other programs, past the first 30,000 `
          + "files, were counted per folder, not file by file: files among them weren't searched for the names of what "
          + "you opened.") : null,
        r.limits.map(x => h("li", {}, x)))),
    h("div", { class: "orow" }, dismiss, h("span", { class: "small muted" }, "It is gone when you dismiss it or quit; nothing was saved."))];
}

async function openTrim() {
  let data;
  try { data = await api("GET", "/api/tools/trim"); } catch (e) { toast(e.message, "error"); return; }
  const body = h("div", { class: "trim" });
  let timer = null, closed = false;
  const m = modal({ title: "TRIM test", wide: true, body, buttons: [{ label: "Close", kind: "primary",
    onclick: (close) => { closed = true; clearTimeout(timer); close(); } }] });
  const overlay = m.box.parentElement;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) { closed = true; clearTimeout(timer); } });
  const reload = async () => {
    try { data = await api("GET", "/api/tools/trim"); render(); } catch (e) { toast(e.message, "error"); }
  };
  const follow = () => {
    clearTimeout(timer);
    if (!closed) timer = setTimeout(reload, 2000);
  };
  const render = () => {
    const job = data.job;
    S.adminActive = !!data.admin_active; renderTop();
    if (job && (job.state === "asking" || job.state === "running")) { fill(body, trimProgress(job)); follow(); return; }
    if (job && job.state === "done" && job.result) { fill(body, trimResult(job.result, reload)); return; }
    fill(body, trimStart(data, job, async (mount, btn) => {
      btn.disabled = true;
      btn.textContent = S.adminActive ? "Starting…" : "Waiting for authorization…";
      try { await api("POST", "/api/tools/trim/start", { mount }); await reload(); }
      catch (e) { toast(e.message, "error", 10000); btn.disabled = false; btn.textContent = "Start the test"; }
    }));
  };
  render();
}

function trimStart(data, job, start) {
  const usable = data.targets.filter(t => !t.blocked && !t.known);
  let chosen = usable[0]?.mount;
  const rows = data.targets.map(t => {
    const ok = !t.blocked && !t.known;
    const radio = h("input", { type: "radio", name: "trim-target", checked: t.mount === chosen, disabled: !ok,
      onchange: () => { chosen = t.mount; } });
    return h("div", { class: "trim-target" },
      h("label", { class: "check" }, radio, h("b", {}, t.mount), h("span", { class: "small muted" },
        ` ${t.fstype}${t.size ? `, ${fmtSize(t.size)}` : ""}${t.encrypted ? ", encrypted" : ""}`)),
      t.known ? h("div", { class: "notebox info small" }, h("b", {}, "No test needed: "), t.known) : null,
      t.guide ? trimGuideButton(t.guide) : null,
      t.blocked ? h("div", { class: "small muted" }, t.blocked) : null,
      ok ? h("div", { class: "small muted" }, `Reading it takes roughly ${t.minutes[0]}–${t.minutes[1]} minutes per pass `
        + "(faster on NVMe drives), for two or three passes.") : null,
      t.notes.map(n => h("div", { class: "notebox risk small" }, n)));
  });
  const btn = h("button", { class: "primary", disabled: !usable.length }, "Start the test");
  btn.addEventListener("click", () => chosen && start(chosen, btn));
  return [
    job && job.state !== "done" ? h("div", { class: `warnbox${job.state === "failed" ? " bad" : ""}` },
      job.state === "stopped" ? `The last test stopped: ${job.error || "Stopped."} Its files were removed.`
        : `The last test failed: ${job.error}`) : null,
    data.leftovers.length ? h("div", { class: "warnbox" }, `A test folder from before couldn't be removed: `
      + `${data.leftovers.join(", ")}. It holds nothing of yours; you can delete it.`) : null,
    h("p", {}, "When you delete a file, an SSD should drop its data once the disk is trimmed. This test checks that it "
      + "really does: it writes " + fmtSize(data.test_bytes) + " of test files, reads the whole disk to find them, deletes "
      + "them, trims the disk (as the weekly fstrim timer does), and reads the whole disk again to see whether any of them "
      + "can still be read back. It also counts whether its deleted files' names stay on the disk."),
    h("div", { class: "small" }, "To see which names of your own deleted files the disk holds, and clear them, use ",
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); openNames(); } }, "Deleted file names"), "."),
    h("div", { class: "small" }, h("b", {}, "What a pass means: "), "nobody can read deleted data back by plugging the "
      + "drive in, even with your encryption key, because the drive's controller has dropped it. It doesn't protect "
      + "against someone examining the flash chips themselves, if they also have your key, or at all if the disk isn't "
      + "encrypted."),
    h("ul", { class: "small" },
      h("li", {}, h("b", {}, "It takes a long time. "), "Each pass reads the whole disk. You can keep working (the disk is "
        + "slower meanwhile), close this window, and stop the test at any time; its files are removed either way."),
      h("li", {}, h("b", {}, "Your other files: "), "the test only writes its own files through the filesystem, never to the "
        + "disk directly. Reading the disk reads everything on it, but only the test's own blocks are counted: nothing else "
        + "is kept or shown."),
      h("li", {}, h("b", {}, "TRIM itself "), "is routine (most systems run it weekly), but some drives have had faulty TRIM "
        + "firmware (Linux blocks the ones known): as always, have a backup."),
      h("li", {}, "Needs administrator access, to read the disk and trim it, for as long as the test runs.")),
    h("h4", {}, "Filesystem to test"),
    rows,
    h("div", { class: "orow" }, btn)];
}

// the check whose guide turns TRIM on (enc.trim_off), from the tool
function trimGuideButton(id) {
  const spec = S.state.catalogue.find(s => s.id === id);
  return spec ? h("div", { class: "orow" }, h("button", { class: "small primary", onclick: () => openGuide(spec) }, "Turn on TRIM…"),
    h("span", { class: "small muted" }, "A guide for this machine.")) : null;
}

function trimProgress(job) {
  const now = job.now;
  const stop = h("button", { class: "small", disabled: job.stopping }, job.stopping ? "Stopping…" : "Stop");
  stop.addEventListener("click", async () => {
    stop.disabled = true; stop.textContent = "Stopping…";
    try { await api("POST", "/api/tools/trim/stop"); } catch (e) { toast(e.message, "error"); }
  });
  const about = (s) => s < 60 ? "under a minute" : `about ${fmtMinutes(s)}`;
  let remaining = 0, ifNeeded = 0;
  const rows = (job.steps || []).map(st => {
    let right = "", bar = null;
    if (st.state === "done") {
      right = `took ${fmtMinutes(Math.max(1, st.finished - st.started))}`;
    } else if (st.state === "skipped") {
      right = "not needed";
    } else if (st.state === "running") {
      const elapsed = now - st.started;
      const frac = st.total ? Math.min(st.done / st.total, 1) : null;
      // its own pace once it has shown some, else the estimate (from the pass before, or the disk's size)
      const left = frac != null && frac > 0.02 ? elapsed / frac - elapsed
        : st.estimate != null ? Math.max(0, st.estimate - elapsed) : null;
      const what = st.id === "wait" ? fmtMinutes(st.total) : st.total ? fmtSize(st.total) : "";
      right = [frac != null ? `${Math.round(frac * 100)}% of ${what}` : `${fmtMinutes(elapsed)} so far`,
        left != null ? `${about(left)} left` : ""].filter(Boolean).join(", ");
      if (frac != null) bar = h("div", { class: "obar" }, h("div", { style: `width: ${Math.round(frac * 100)}%` }));
      if (left != null) remaining += left;
    } else if (st.estimate != null) {
      right = about(st.estimate) + (st.optional ? ", if needed" : "");
      if (st.optional) ifNeeded += st.estimate; else remaining += st.estimate;
    } else if (st.optional) {
      right = "if needed";
    }
    return h("div", { class: `trim-step ${st.state}` },
      h("div", { class: "trim-step-row" },
        h("span", { class: "trim-step-mark" }, st.state === "running" ? h("span", { class: "spinner on" })
          : st.state === "done" ? "✓" : st.state === "skipped" ? "–" : ""),
        h("span", { class: st.state === "running" ? "" : "muted" }, st.label),
        h("span", { class: "small muted trim-step-right" }, right)),
      bar);
  });
  const started = job.steps?.some(s => s.state !== "pending");
  return h("div", { class: "trim-progress" },
    job.state === "asking" || !started ? h("div", { class: "orow" }, h("span", { class: "spinner on" }),
      h("b", {}, job.state === "asking" ? "Waiting for authorization…" : job.phase || "Starting")) : null,
    rows.length ? h("div", { class: "trim-steps" }, rows) : null,
    started ? h("div", { class: "small" }, h("b", {}, `${about(remaining)} left`),
      ifNeeded ? h("span", { class: "muted" }, `, plus ${about(ifNeeded)} if the last pass is needed`) : null,
      h("span", { class: "muted" }, ". Estimates come from the disk's size until a pass has been read, then from how "
        + "fast this disk read.")) : null,
    h("div", { class: "small muted" }, `Testing ${job.mount}. Started ${job.started ? fmtMinutes(now - job.started) + " ago" : "just now"}. `
      + "You can close this window: the test goes on, and opening it again shows where it is."),
    h("div", { class: "orow" }, stop));
}

function trimResult(r, reload) {
  const again = async () => { try { await api("POST", "/api/tools/trim/dismiss"); await reload(); } catch (e) { toast(e.message, "error"); } };
  return h("div", { class: `verdict ${TRIM_CLASS[r.verdict] || "warn"}` },
    h("div", { class: "vtitle" }, r.headline),
    r.lines.length ? h("ul", { class: "small" }, r.lines.map(l => h("li", {}, h("span", { class: "muted" }, l.label + ": "), l.value))) : null,
    r.explanation.map(p => h("p", { class: "small" }, p)),
    r.commands?.length ? commandBlock(r.commands) : null,
    r.guide ? trimGuideButton(r.guide) : null,
    r.names_mount ? h("div", { class: "orow" }, h("button", { class: "small", onclick: () => openNames(r.names_mount) },
      "Look at your deleted file names…"), h("span", { class: "small muted" }, "Which names of your own deleted files this disk "
      + "holds, and clearing them: the Deleted file names tool.")) : null,
    h("details", { class: "vdetails" }, h("summary", { class: "small" }, "What was tested"),
      h("ul", { class: "small" }, r.environment.map(e => h("li", {}, h("span", { class: "muted" }, e.label + ": "), e.value))),
      r.offsets.length ? h("div", { class: "small" }, h("b", {}, "Blocks still readable "), "(test block: offset on the device): ",
        r.offsets.map(([i, o]) => `${i}: ${o}`).join(", ")) : null),
    h("p", { class: "muted small" }, "This result stays here while the app is open and is gone when it closes: copy it if you want to keep it."),
    h("div", { class: "orow" },
      h("button", { class: "small", onclick: (e) => copyText(r.text, e.target) }, "Copy as text"),
      h("button", { class: "small", onclick: again }, "Test again…")));
}

// ------------------------------------------------------------------ Deleted file names

// Which names of deleted files the disk still holds: listed when asked, shown once, never saved; closing
// the tool forgets them (the server hands the list over once, and the helper drops its copy). On ext4 the
// user can then clear the journal, where the names are on a current kernel, and clean folders whose own
// records hold names (fillers, or a rebuild for a large one); on btrfs, trim and look again.
const METHOD = { rebuild: "rebuild", fillers: "fillers" };

function checkChip(id, close) {
  const spec = S.state.catalogue.find(s => s.id === id);
  if (!spec) return null;
  const r = S.report?.results?.[id];
  return h("span", { class: "chip", title: r?.summary || spec.title, onclick: () => { close(); reveal(id); } }, spec.title);
}

async function openNames(mount = null) {
  let data;
  try { data = await api("GET", "/api/tools/names"); } catch (e) { toast(e.message, "error"); return; }
  const body = h("div", { class: "trim names" });
  let timer = null, closed = false, chosen = null;
  const forget = () => { closed = true; clearTimeout(timer); api("POST", "/api/tools/names/forget").catch(() => {}); };
  const m = modal({ title: "Deleted file names", wide: true, body, buttons: [{ label: "Close", kind: "primary",
    onclick: (close) => { forget(); close(); } }] });
  const overlay = m.box.parentElement;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) forget(); });
  const closeAll = () => { forget(); m.close(); };
  const usable = data.targets.filter(t => !t.blocked);
  chosen = (usable.find(t => t.mount === mount) || usable[0])?.mount;

  const start = async (trimFirst = false) => {
    try { await api("POST", "/api/tools/names/start", { mount: chosen, trim_first: trimFirst }); poll(); }
    catch (e) { toast(e.message, "error"); }
  };
  const poll = async () => {
    if (closed) return;
    let r;
    try { r = await api("GET", "/api/tools/names/job"); } catch (e) { fill(body, h("div", { class: "warnbox bad" }, e.message)); return; }
    const job = r.job;
    if (!job) { fill(body, h("div", { class: "warnbox" }, "Nothing to show: it was stopped.")); return; }
    S.adminActive = true; renderTop();
    if (job.state === "asking" || job.state === "running") {
      const frac = job.total ? Math.min(job.done / job.total, 1) : 0;
      const stop = h("button", { class: "small", onclick: (e) => {
        e.target.disabled = true; e.target.textContent = "Stopping…";
        api("POST", "/api/tools/names/forget").catch(() => {});
      } }, "Stop");
      fill(body, h("div", { class: "trim-progress" },
        h("div", { class: "orow" }, h("span", { class: "spinner on" }), h("b", {}, job.state === "asking" ? "Waiting for authorization…" : job.phase || "Working"),
          job.total ? h("span", { class: "small muted" }, `${Math.round(frac * 100)}%`) : null),
        job.total ? h("div", { class: "obar" }, h("div", { style: `width: ${Math.round(frac * 100)}%` })) : null,
        h("div", { class: "orow" }, stop)));
      timer = setTimeout(poll, 1000);
      return;
    }
    if (job.state !== "done") { fill(body, h("div", { class: "warnbox bad" }, job.error || "It stopped."), startView()); return; }
    fill(body, namesList(job.result, job.trimmed, { start, closeAll }));
  };

  const startView = () => {
    const t = data.targets.find(x => x.mount === chosen);
    const rows = data.targets.map(x => {
      const radio = h("input", { type: "radio", name: "names-target", checked: x.mount === chosen, disabled: !!x.blocked,
        onchange: () => { chosen = x.mount; fill(body, startView()); } });
      return h("div", { class: "trim-target" },
        h("label", { class: "check" }, radio, h("b", {}, x.mount), h("span", { class: "small muted" },
          ` ${x.fstype}${x.size ? `, ${fmtSize(x.size)}` : ""}${x.encrypted ? ", encrypted" : ""}`
          + (x.scope === "home" ? ": your folders under your home" : ": every folder you can open on it"))),
        x.blocked ? h("div", { class: "small muted" }, x.blocked) : null,
        !x.blocked && x.fstype === "btrfs" ? h("div", { class: "small muted" }, `On btrfs this reads the whole disk, `
          + `roughly ${x.minutes[0]}–${x.minutes[1]} minutes (faster on NVMe drives): freed copies of the folders' records can be anywhere in free space.`) : null,
        !x.blocked && x.fstype === "ext4" ? h("div", { class: "small muted" }, "On ext4 it reads the folders' own records and "
          + "the journal: a few seconds on an SSD, up to a minute on a hard disk. Kernels since Linux 5.13 overwrite a name in "
          + "its folder as the file is deleted, so the journal is where the names are.") : null);
    });
    const go = h("button", { class: "primary", disabled: !chosen || data.busy }, "Find them");
    go.addEventListener("click", () => { go.disabled = true; go.textContent = data.admin_active ? "Starting…" : "Waiting for authorization…"; start(); });
    return [
      h("p", {}, "When you delete a file, its name often stays on the disk: on ext4 in the journal (and, under older kernels, "
        + "in the folder's own records), on btrfs in old copies of the records. This lists the names of deleted files that can still be read, and clears them where it safely can."),
      h("div", { class: "notebox small" }, h("b", {}, "Who could read them: "), "someone with administrator access to this unlocked "
        + "computer, or with the disk and its encryption key, and they can read your live files too: deleted names are the least of it. "
        + "Encryption and a short automatic lock do more than any clean-up here.",
        h("div", { class: "related" }, checkChip("enc.fde_missing", closeAll), checkChip("auth.screen_lock", closeAll))),
      h("p", { class: "small muted" }, "Names also live outside the filesystem (recent files, thumbnails, search indexes, shell history, the trash, "
        + "backups, a sync service's history): the scan's other checks cover those."),
      h("h4", {}, "Filesystem"),
      rows,
      t?.trim_passed ? h("div", { class: "small muted" }, "The TRIM test passed on this drive earlier in this session.") : null,
      h("p", { class: "small muted" }, "The list is shown here only: it isn't saved, sent or added to any report, and it is gone when you close "
        + "this window. Needs administrator access."),
      data.busy ? h("div", { class: "warnbox" }, "The TRIM test is running: wait until it has finished.") : null,
      h("div", { class: "orow" }, go)];
  };
  fill(body, data.targets.length ? startView()
    : h("div", { class: "warnbox" }, "There is no ext4 or btrfs filesystem here whose names can be listed."));
}

function namesList(names, trimmed, { start, closeAll }) {
  const hidden = h("input", { type: "checkbox" });
  const picked = new Set();
  const out = h("div", { class: "trim" });
  const j = names.journal?.state === "read" ? names.journal : null;
  const clearJournal = j?.clearable ? (after) => openJournalClear(names, after) : null;
  const cleanBtn = h("button", { class: "primary", disabled: true }, "Clean the chosen folders…");
  cleanBtn.addEventListener("click", () => openNamesPlan(names.mount, [...picked], () => start(), [], clearJournal));
  // ext4's journal: the names only it holds, the records in it that are no folder of the user's, and clearing it
  const journalBox = () => {
    if (!j || !(j.names || j.orphans || j.fast_commit)) return null;
    return h("div", { class: "notebox small" }, h("b", {}, "In the journal: "),
      j.names ? `${plural(j.names, "name")} of these ${j.names === 1 ? "is" : "are"} in the journal only (the folders marked so below). ` : null,
      j.orphans ? `It also holds ${plural(j.orphans, "record")} of folders that ${names.scope === "home" ? "are gone or aren't yours" : "are gone or that you can't open"} `
        + "(other accounts', the system's): their names aren't shown here. " : null,
      j.clearable ? "Clearing the journal removes all of them at once, whoever's they are."
        : "This kernel can't clear the journal (Linux 5.14 and later can): the names go by themselves as the journal wraps, "
          + "in minutes to hours on a busy system and days on an idle one.",
      h("div", { class: "orow" },
        j.clearable ? h("button", { class: "primary small", onclick: () => clearJournal(() => start()) }, "Clear the journal…") : null,
        j.orphans ? h("button", { class: "small", onclick: () => openJournalOthers(names, j) }, "Show those names…") : null));
  };
  const refreshBtn = () => {
    cleanBtn.disabled = !picked.size;
    cleanBtn.textContent = picked.size ? `Clean ${plural(picked.size, "folder")}…` : "Clean the chosen folders…";
  };
  const folderView = (f) => {
    const r = f.remedy;
    const box = r && r.method !== "none" ? h("input", { type: "checkbox", checked: picked.has(f.rel),
      onchange: (e) => { e.target.checked ? picked.add(f.rel) : picked.delete(f.rel); refreshBtn(); } }) : null;
    const count = f.names.length + f.hashes.length;
    return h("div", { class: "names-folder" },
      h("div", { class: "orow" }, box ? h("label", { class: "check small" }, box, h("b", {}, f.path)) : h("b", { class: "small" }, f.path),
        h("span", { class: "small muted" }, plural(count, "name")
          + (f.journal_only && f.journal_only < count ? `, ${f.journal_only} in the journal only` : "")),
        f.gone ? h("span", { class: "badge", title: r?.why }, "deleted folder") : null,
        r?.journal && !f.gone ? h("span", { class: "badge", title: r.why }, "in the journal") : null,
        r && r.method !== "none" ? h("span", { class: `badge method-${r.method}`, title: r.why }, METHOD[r.method]) : null),
      f.notes.map(n => h("div", { class: "notebox small" }, n)),
      f.names.length ? h("ul", { class: "small" }, f.names.map(n => h("li", {}, n))) : null,
      f.hashes.length ? h("details", { class: "small hashes" },
        h("summary", {}, `${plural(f.hashes.length, "name")} made from a hash`),
        h("p", {}, f.browser_cache
          ? "These are a browser's cache entries, each named after a hash of the address it holds (and a tag). A hash can't be "
            + "turned back into the address, but anyone with an address in mind can hash it the same way and see whether your "
            + "browser fetched it. Keeping the browser's cache in memory stops them reaching the disk."
          : "Programs name these after a hash of something (often a cache key). A hash can't be turned back, but anyone who can "
            + "guess the original can hash it the same way and check."),
        f.browser_cache ? featureLink("br.disk_cache", "Keep the cache in memory…") : null,
        h("ul", {}, f.hashes.map(n => h("li", {}, n)))) : null,
      r && r.method === "none" && !r.journal ? h("div", { class: "small muted" }, r.why) : null);
  };
  const show = () => {
    const folders = names.folders.filter(f => hidden.checked || !f.hidden);
    const shown = folders.reduce((n, f) => n + f.names.length + f.hashes.length, 0);
    const hiddenCount = names.folders.filter(f => f.hidden).reduce((n, f) => n + f.names.length + f.hashes.length, 0);
    const text = folders.map(f => `${f.path}\n` + [...f.names, ...f.hashes].map(n => `  ${n}`).join("\n")).join("\n");
    const ext4 = names.fstype === "ext4";
    const canTrim = !["hdd", "layer"].includes(names.no_trim);
    const cleanable = names.folders.some(f => f.remedy && f.remedy.method !== "none");   // names in a folder's own records
    fill(out,
      h("p", { class: "small" }, names.count
        ? `${plural(names.count, "name")} of deleted files can still be read from ${names.mount}, ${names.scope === "home" ? "in folders of yours" : `in folders you can open on ${names.root}`}.`
        : `No names of deleted files were found ${names.scope === "home" ? "in your folders" : `in the folders you can open on ${names.root}`}`
          + (j ? ", in their own records or in the journal." : ".")),
      trimmed != null ? h("div", { class: "small muted" }, `Trimmed ${fmtSize(trimmed)} of free space first.`) : null,
      names.facts.map(x => h("p", { class: "small" }, x)),
      names.truncated ? h("div", { class: "small muted" }, "Only part of it is shown: there were too many folders or names.") : null,
      names.unreadable ? h("div", { class: "warnbox" }, `The drive couldn't read ${fmtSize(names.unreadable)} of the disk: it answered with errors there, `
        + "which usually means failing sectors. Those parts were skipped, so names in them are missing from this list. Back the drive up and check its health.") : null,
      journalBox(),
      names.count ? h("label", { class: "check small" }, hidden, `Include hidden folders, such as caches and settings (${plural(hiddenCount, "name")})`) : null,
      folders.length ? h("div", { class: "names-list" }, folders.map(folderView)) : null,
      // what can be done for names in the folders' own records
      ext4 && cleanable ? h("div", { class: "small" }, "Tick the folders to clean. ", h("b", {}, "Fillers"), " take the deleted names' places "
        + "in a folder's own records: it stays the same folder, so a sync client or backup that isn't running meanwhile sees "
        + "nothing of it. A large folder gets a ", h("b", {}, "rebuild"), " instead: everything moves into a new folder and the old "
        + "one is removed, its records becoming free space for TRIM. Programs watching a folder are named first. Synced "
        + "folders are left to their service.") : null,
      ext4 && cleanable ? h("div", { class: "orow" }, cleanBtn) : null,
      !ext4 && names.count && canTrim ? h("div", { class: "orow" },
        h("button", { class: "primary", onclick: (e) => { e.target.disabled = true; start(true); } }, "Trim now and check again"),
        h("span", { class: "small muted" }, "The old copies are free space: trimming them is the whole clean-up. Never a balance, "
          + "which moves records and leaves more old copies behind.")) : null,
      !ext4 && names.count ? h("p", { class: "small muted" }, "What stays: names in snapshots, and stale entries inside records still in "
        + "use, until that folder changes again.") : null,
      names.guide && names.count ? trimGuideButton(names.guide) : null,
      ext4 && names.commands.length ? h("details", { class: "small" }, h("summary", {}, "Every folder at once (from a live USB)"),
        h("p", {}, "e2fsck -fD compacts every folder on the filesystem, dropping what deleted entries left. It needs the filesystem "
          + "unmounted, so start the computer from a live USB and run (the app doesn't do this):"),
        commandBlock(names.commands)) : null,
      h("p", { class: "muted small" }, "This list isn't saved anywhere: closing this window forgets it. Copy it if you want to keep it."),
      shown ? clipboardKept("The list of deleted file names") : null,
      h("div", { class: "orow" }, shown ? h("button", { class: "small", onclick: (e) => copyText(text, e.target) }, "Copy the list") : null,
        h("button", { class: "small", onclick: () => start() }, "List again")));
    refreshBtn();
  };
  hidden.addEventListener("change", show);
  show();
  return out;
}

// Clear ext4's journal: what it is and does, what it doesn't reach, the line that makes the same call; then the
// kernel does it (one call through the helper), and `after` runs (the list again, or the check after a clean-up).
function openJournalClear(names, after) {
  const body = h("div", { class: "trim" },
    h("p", {}, "The journal is where ext4 writes every change to a folder first, so that a crash can't leave it half made. "
      + "The copies stay there, names and all, until the journal has wrapped round and written over them."),
    h("h4", {}, "What it does"),
    h("ol", { class: "small" },
      h("li", {}, `Has the kernel write everything the journal of ${names.mount} holds to its place on the disk, then overwrite the `
        + "whole journal with zeros. This is ext4's own function for it, used as administrator.")),
    h("h4", {}, "Worth knowing"),
    h("ul", { class: "small" },
      h("li", {}, `It clears the journal of the whole filesystem: every folder's names in it and every account's, not only yours.`),
      h("li", {}, "Nothing is lost. The journal only holds what would be replayed after a crash, and all of it is written out "
        + "first. The filesystem stays in use meanwhile; it takes about a second on an SSD, longer on a hard disk."),
      h("li", {}, "It clears what is there now: files deleted afterwards leave their names in the journal again."),
      h("li", {}, "What it doesn't reach: the flash chips themselves, which can keep an old copy until the drive reuses the "
        + "space (" + (names.encrypted ? "this disk is encrypted, which is what protects those" : "only disk encryption protects those, and this disk isn't encrypted")
        + "); snapshots (LVM); and names recorded elsewhere: recent files, thumbnails, search indexes, shell history, the "
        + "trash, backups."),
      h("li", {}, "Nothing is kept: it isn't in History, and there is nothing to undo.")),
    h("details", { class: "small" }, h("summary", {}, "The same from a terminal"),
      h("p", {}, "No program on the system does this, so it is a line of Python making the same call to the kernel "
        + "(EXT4_IOC_CHECKPOINT with its zero-out flag, Linux 5.14 and later):"),
      commandBlock([names.journal.command])));
  modal({ title: "Clear the journal", wide: true, body, buttons: [
    { label: "Cancel" },
    { label: "Clear the journal", kind: "primary", onclick: async (close, el) => {
      el.disabled = true; el.textContent = "Clearing…";
      try {
        const r = await api("POST", "/api/tools/names/journal/clear");
        toast(`The journal of ${names.mount} was cleared${r.seconds >= 1 ? ` (${Math.round(r.seconds)} s)` : ""}.`, "ok");
        close(); after();
      } catch (e) { toast(e.message, "error", 10000); el.disabled = false; el.textContent = "Clear the journal"; }
    } }] });
}

// The names in the journal's records of folders that are no folder of the user's: never in the list, and shown
// here only once the user has read whose they can be and asked for them.
function openJournalOthers(names, j) {
  const body = h("div", { class: "trim" },
    h("p", {}, `The journal holds ${plural(j.orphans, "record")} of folders the app can't tie to a folder of yours: folders that `
      + "are gone, other accounts' folders, the system's."
      + (j.checksums ? "" : " On this filesystem, which keeps no checksums on its folders' records, that is every folder's.")),
    h("div", { class: "warnbox" }, "With administrator access you can read them, and so can this app. They can include other "
      + "people's file names. Many are of files that still exist: without the folder, the app can't tell which were deleted."),
    h("p", { class: "small muted" }, "They are shown here only, never saved, and are gone when you close this window."));
  const m = modal({ title: "Names in the journal that aren't tied to your folders", wide: true, body, buttons: [
    { label: "Close" },
    { label: "Show them", kind: "primary", onclick: async (close, el) => {
      el.disabled = true; el.textContent = "Reading…";
      let r;
      try { r = await api("POST", "/api/tools/names/journal/others"); }
      catch (e) { toast(e.message, "error", 10000); el.disabled = false; el.textContent = "Show them"; return; }
      el.remove();
      const all = [...r.names, ...r.hashes];
      fill(body,
        h("p", { class: "small" }, all.length ? `${plural(all.length, "name")} in ${plural(r.records, "record")} of the journal, `
          + "of files deleted and of files still there:" : "None can be read any more: the journal has moved on, or was cleared."),
        r.truncated ? h("div", { class: "small muted" }, "Only part of it is shown: there were too many.") : null,
        r.names.length ? h("ul", { class: "small names-list" }, r.names.map(n => h("li", {}, n))) : null,
        r.hashes.length ? h("details", { class: "small hashes" }, h("summary", {}, `${plural(r.hashes.length, "name")} made from a hash`),
          h("ul", {}, r.hashes.map(n => h("li", {}, n)))) : null,
        j.clearable ? h("p", { class: "small" }, "Clear the journal, in the list behind this, removes them all.") : null,
        all.length ? clipboardKept("This list") : null,
        all.length ? h("div", { class: "orow" }, h("button", { class: "small", onclick: (e) => copyText(all.join("\n"), e.target) }, "Copy the list")) : null);
    } }] });
  return m;
}

// a check's guide, from a tool (br.disk_cache)
function featureLink(id, label) {
  const spec = S.state.catalogue.find(s => s.id === id);
  return spec ? h("div", { class: "orow" }, h("button", { class: "small", onclick: () => openGuide(spec) }, label)) : null;
}

async function openNamesPlan(mount, folders, relist, rebuild = [], clearJournal = null) {
  let r;
  try { r = await api("POST", "/api/tools/names/plan", { mount, folders, rebuild }); } catch (e) { toast(e.message, "error"); return; }
  const plan = r.plan;
  const body = h("div", { class: "trim" });
  const ok = plan.folders.filter(f => !f.blockers.length);
  const synced = h("input", { type: "checkbox" });
  let goBtn, timer = null, closed = false;
  const m = modal({ title: "Clean folders", wide: true, body, buttons: [
    { label: "Cancel", onclick: (close) => { closed = true; clearTimeout(timer); close(); } },
    { label: ok.length ? `Clean ${plural(ok.length, "folder")}` : "Nothing to clean", kind: "primary", disabled: !ok.length || plan.ask_synced,
      ref: (el) => { goBtn = el; }, onclick: (close, el) => go(el) }] });
  synced.addEventListener("change", () => { goBtn.disabled = !synced.checked; });
  fill(body,
    h("ul", { class: "small" }, plan.folders.map(f => h("li", {}, h("b", {}, f.path), " ",
      f.blockers.length ? h("span", { class: "errmsg" }, "Not now: " + f.blockers.join(" ")) : h("span", { class: "muted" }, `(${METHOD[f.method]}) ${f.why}`)))),
    plan.steps.length ? [h("h4", {}, "What it does"), h("ol", { class: "small" }, plan.steps.map(x => h("li", {}, x)))] : null,
    plan.side_effects.length ? [h("h4", {}, "Worth knowing"), h("ul", { class: "small" }, plan.side_effects.map(x => h("li", {}, x)))] : null,
    plan.ask_synced ? h("label", { class: "check confirm" }, synced, "None of these folders is synced by an online service (such as Dropbox, "
      + "Nextcloud, Google Drive or OneDrive). Its own history keeps what was deleted, and anything done here would be uploaded.") : null,
    plan.needs_root && !r.admin_active ? h("p", { class: "muted small" }, "Asks for administrator access (your password), to read the "
      + "folders' records and trim, unless it is already granted.") : null);

  const follow = async () => {
    if (closed) return;
    let j;
    try { j = (await api("GET", "/api/tools/names/clean")).job; } catch (e) { fill(body, h("div", { class: "warnbox bad" }, e.message)); return; }
    if (!j) { fill(body, h("div", { class: "warnbox" }, "Nothing to show.")); return; }
    if (j.state === "asking" || j.state === "running") {
      fill(body, h("div", { class: "trim-progress" },
        j.state === "asking" ? h("div", { class: "orow" }, h("span", { class: "spinner on" }), h("b", {}, "Waiting for authorization…")) : null,
        h("div", { class: "trim-steps" }, (j.steps || []).map(st => h("div", { class: `trim-step ${st.state}` },
          h("div", { class: "trim-step-row" },
            h("span", { class: "trim-step-mark" }, st.state === "running" ? h("span", { class: "spinner on" }) : st.state === "done" ? "✓" : ""),
            h("span", { class: st.state === "running" ? "" : "muted" }, st.label),
            h("span", { class: "small muted trim-step-right" }, st.state === "done" && st.started ? `took ${fmtMinutes(Math.max(1, st.finished - st.started))}` : "")))))));
      timer = setTimeout(follow, 1000);
      return;
    }
    goBtn.remove();
    if (j.state !== "done") { fill(body, h("div", { class: "warnbox bad" }, j.error || "It stopped.")); return; }
    fill(body, cleanResult(j.result, folders, mount, relist, m.close, clearJournal));
  };
  async function go(el) {
    el.disabled = true;
    el.textContent = S.adminActive ? "Working…" : "Waiting for authorization…";
    try {
      await api("POST", "/api/tools/names/clean", { mount, folders: ok.map(f => f.rel), rebuild, not_synced: true });
      S.adminActive = true; renderTop();
      follow();
    } catch (e) { toast(e.message, "error", 10000); el.disabled = false; el.textContent = `Clean ${plural(ok.length, "folder")}`; }
  }
}

const CLEAN_CLASS = { done: "ok", partly: "warn", failed: "bad", skipped: "" };

function cleanResult(res, folders, mount, relist, close, clearJournal = null) {
  const out = h("div", { class: "trim" });
  const treated = res.folders.filter(f => f.state === "done" || f.state === "partly").map(f => f.rel);
  const check = async () => render((await api("POST", "/api/tools/names/check", { mount, folders: treated })).result);
  const render = (r) => fill(out,
    h("ul", { class: "small clean-result" }, r.folders.map(f => h("li", { class: `st-${f.state}` },
      h("b", {}, f.path), " ", f.text,
      f.commands?.length ? commandBlock(f.commands) : null,
      f.rebuild_offer ? h("div", { class: "orow" }, h("button", { class: "small", onclick: () => { close();
        openNamesPlan(mount, [f.rel], relist, [f.rel], clearJournal); } }, "Rebuild instead…")) : null,
      f.left?.length ? h("details", {}, h("summary", {}, "Which names"), h("ul", {}, f.left.map(n => h("li", {}, n)))) : null))),
    r.explanation.map(x => h("p", { class: "small" }, x)),
    h("p", { class: "muted small" }, "Nothing of this is kept: it is gone when you close this window."),
    h("div", { class: "orow" },
      clearJournal && r.folders.some(f => f.journal) ? h("button", { class: "primary small", onclick: () =>
        clearJournal(() => check().catch(err => toast(err.message, "error"))) }, "Clear the journal…") : null,
      treated.length ? h("button", { class: "small", onclick: async (e) => {
        e.target.disabled = true;
        try { await check(); }
        catch (err) { toast(err.message, "error"); e.target.disabled = false; }
      } }, "Check again") : null,
      h("button", { class: "small", onclick: () => { close(); relist(); } }, "List the names again")));
  render(res);
  return out;
}

// ------------------------------------------------------------------ scan

function renderTop() {
  const r = S.report;
  if (r) {
    const d = new Date(r.started * 1000);
    $("#scan-info").textContent = r.restored
      ? `Last scan: ${d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })} (saved)`
      : `Scanned at ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} in ${(r.duration_ms / 1000).toFixed(1)} s`;
  }
  const priv = $("#priv-badge");
  const idle = S.state?.admin_idle_minutes || 5;
  priv.textContent = S.adminActive ? "Administrator" : "Unprivileged";
  priv.className = `badge ${S.adminActive ? "privileged" : "unprivileged"}`;
  priv.title = S.adminActive ? `Administrator access is held for this session: a root helper is running. It ends after ${idle} idle minutes, or now with Drop.`
    : "Checks that need administrator access report that they couldn't check; fixes that need it ask when applied";
  $("#drop-admin").classList.toggle("hidden", !S.adminActive);
  const chip = $("#presentation-chip");
  const lapsed = (S.presentation?.lapsed || []).length > 0;
  chip.classList.toggle("hidden", !S.presentation?.on);
  chip.textContent = lapsed ? "Presentation mode · Do Not Disturb ended" : "Presentation mode · Turn off";
  chip.title = lapsed ? PRESENTATION_LAPSED + " Click to turn it on again."
    : "Notification banners and clipboard history are off for screen sharing. Click to put them back.";
  $("#export-btn").classList.toggle("hidden", !r);
  const stale = !!S.state?.helper_stale;
  $("#helper-note").classList.toggle("hidden", !S.state || (S.state.helper_installed && !stale));
  $("#helper-note").textContent = stale ? "helper out of date" : "helper not installed";
  $("#helper-note").title = stale ? "The installed administrator helper is from another version of the app"
    : "The administrator helper isn't installed root-owned";
  $("#scan-btn").disabled = S.scanning;
  $("#online-btn").disabled = S.scanning || jobBusy();
  $("#online-btn").title = jobRunning() ? "Online tests are running (see the bar above the checks)"
    : jobBusy() ? "The stopped test is still finishing in the background"
    : "Tests that contact other machines: you see who each one contacts before anything runs";
  $("#scan-btn").textContent = S.scanning ? "Scanning…" : (r ? "Scan again" : "Scan");
}

function renderAll() {
  renderTop();
  renderContext();
  renderChecks();
}

async function scan() {
  if (S.scanning) return;
  S.scanning = true;
  renderTop();
  setStatus("Scanning (read-only)…", "busy");
  const admin = $("#admin").checked;
  if (admin) setStatus("Waiting for administrator authorization…", "busy");
  try {
    S.report = await api("POST", "/api/scan", { admin });
    S.adminActive = !!S.report.admin_active;
    S.show = "findings";                           // the report starts with what needs attention
    S.band = null;
    const unknown = S.state.context_keys.filter(k => S.report.context.values[k]?.value === null);
    const declined = S.report.admin?.requested && !S.report.admin.granted;
    const parts = [declined ? `Scanned without administrator access (${S.report.admin.message})` : "Scan finished. Nothing was changed."];
    if (S.report.admin?.dropped) parts.push("Administrator access was dropped again: nothing found needs it to fix.");
    if (unknown.length) parts.push(`Couldn't determine: ${unknown.map(k => (CONTEXT_LABEL[k] || k).toLowerCase()).join(", ")}.`);
    const ch = S.report.changes;
    const fresh = ch ? newOfKind(newShown(ch.new), "finding") : [];
    if (fresh.length) parts.push(`${plural(fresh.length, "new finding")} since the last scan.`);
    const again = (ch?.unchecked || []).filter(u => uncheckedNow(u.id) && !acceptedHidden(u.id)).length;
    if (again) parts.push(`${again} ${again > 1 ? "problems" : "problem"} from an earlier scan couldn't be checked this time: not resolved.`);
    for (const [id, items] of Object.entries(ch?.new_items || {}))
      parts.push(`${items.length} new in ${(S.state.catalogue.find(sp => sp.id === id)?.title || id).toLowerCase()}.`);
    setStatus(parts.join(" "), declined ? "warned" : "done");
  } catch (e) {
    setStatus(`Scan failed: ${e.message}`, "failed");
    toast(`Scan failed: ${e.message}`, "error");
  } finally {
    S.scanning = false;
    renderAll();
  }
}

// ------------------------------------------------------------------ online tests

async function openOnline() {
  let data;
  try { data = await api("GET", "/api/online"); } catch (e) { toast(e.message, "error"); return; }
  const boxes = new Map();
  const secs = h("select", {}, [15, 30, 60, 120, 300].map(n =>
    h("option", { value: n, selected: n === data.observe_seconds }, `${n} s`)));
  const admin = h("input", { type: "checkbox", checked: data.admin_active, disabled: data.admin_active });
  const gains = data.tests.filter(t => t.with_admin);
  const testRow = (t) => {
    const cb = h("input", { type: "checkbox", checked: t.default });
    boxes.set(t.id, cb);
    return h("label", { class: "otest" }, cb, h("div", {},
      h("b", {}, t.title), isDev() ? [" ", h("span", { class: "muted small" }, t.id)] : null,
      h("div", { class: "hosts" }, "Contacts: ", t.hosts.length ? t.hosts.join(", ") : "nobody"),
      h("div", { class: "ctext" }, h("b", {}, t.default ? "Ticked by default: " : "Not ticked by default: "), t.default_why),
      t.with_admin ? h("div", { class: "ctext admin" }, h("b", {}, "With administrator access: "), t.with_admin) : null));
  };
  // grouped by how far each test reaches; ticked groups first
  const GROUPS = [
    ["nobody", "Contact nobody", "Ticked by default. They only look at this machine and the network traffic it sends."],
    ["own", "Contact only your own DNS resolver, router or server, or well-known sites", "Ticked by default."],
    ["third", "Use a third-party service, or download a lot", "Not ticked by default: run them when you need them."],
  ];
  const list = h("div", { class: "otests" }, GROUPS.map(([g, title, sub]) => {
    const tests = data.tests.filter(t => t.group === g);
    return tests.length ? h("div", { class: "ogroup" },
      h("div", { class: "ohead" }, h("b", {}, title), h("span", { class: "muted small" }, sub)),
      tests.map(testRow)) : null;
  }));
  const body = [
    h("p", {}, "These tests contact other machines, which a scan never does. Each server contacted sees your IP "
      + "address and what the test asks it; nothing else about this machine is sent, and results stay here."),
    h("p", { class: "muted small" }, "Ticked by default: tests that contact nobody, only your own DNS resolver or "
      + "router, or well-known sites. Not ticked: tests that use a third-party test service (worth running with a "
      + "VPN connected) or download a lot."),
    !S.report ? h("div", { class: "warnbox" }, "Scan first: the online tests build on the scan's results.") : null,
    data.settings_error ? h("div", { class: "warnbox bad" }, data.settings_error) : null,
    data.proxy_vars?.length ? h("div", { class: "warnbox bad" }, `Your proxy settings (${data.proxy_vars.join(", ")}) are not `
      + "used: these tests connect directly, so the hosts named below see this computer's own address, not the proxy's. "
      + "If the proxy is what hides your address, don't run them from here.") : null,
    h("label", { class: "check oadmin" }, admin, data.admin_active
      ? `Administrator access is active: used by ${gains.map(t => `“${t.title}”`).join(" and ")}.`
      : `Use administrator access (asks for your password). Only ${gains.length} of these tests use it, `
        + `${gains.map(t => `“${t.title}”`).join(" and ")}; the rest run the same either way.`),
    h("div", { class: "orow" }, h("button", { class: "small ghost", onclick: () => boxes.forEach(b => { b.checked = true; }) }, "Select all"),
      h("button", { class: "small ghost", onclick: () => boxes.forEach((b, id) => { b.checked = data.tests.find(t => t.id === id).default; }) }, "Defaults"),
      h("button", { class: "small ghost", onclick: () => boxes.forEach(b => { b.checked = false; }) }, "None"),
      h("span", { class: "spacer" }), h("span", { class: "muted" }, "Watch traffic for"), secs),
    list,
    h("p", { class: "muted small" }, `Endpoints can be changed in ${data.settings_path}.`),
  ];
  modal({ title: "Online tests", wide: true, body, buttons: [
    { label: "Cancel" },
    { label: "Run selected", kind: "primary", disabled: !S.report || !!data.settings_error, onclick: (close) => {
      const ids = [...boxes].filter(([, b]) => b.checked).map(([id]) => id);
      if (!ids.length) { toast("Choose at least one test.", "error"); return; }
      close();
      runOnline(ids, +secs.value, admin.checked && !data.admin_active);
    } },
  ] });
}

async function runOnline(ids, seconds, askAdmin) {
  try {
    const r = await api("POST", "/api/online/run", { ids, observe_seconds: seconds, admin: askAdmin });
    S.jobHidden = false;
    onJob(r.job);
    pollJob();
  } catch (e) {
    toast(e.message, "error");
  }
}

// how long each test usually takes, to say when one is taking longer than that
function expectedSeconds(id, job) {
  if (id === "tel.observed_traffic") return job.observe_seconds + 15;
  if (id === "kern.updates_refreshed") return 300;
  return 30;
}

const fmtDur = (s) => { s = Math.max(0, Math.round(s)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
const jobRunning = () => S.job && ["starting", "asking", "running"].includes(S.job.state);
// running, or a test stopped with "Stop now" is still ending in the background
const jobBusy = () => jobRunning() || !!S.job?.winding_down;

function onJob(job) {
  const before = S.job ? Object.keys(S.job.results).length : 0;
  S.job = job;
  if (!job) return;
  S.jobClock = Date.now() / 1000 - job.now;
  if (S.report) Object.assign(S.report.results, job.results);
  if (Object.keys(job.results).length !== before) renderChecks();
  renderOnlineStrip();
  renderTop();
}

let pollTimer = null, tickTimer = null;

async function pollJob() {
  clearTimeout(pollTimer);
  clearInterval(tickTimer);
  tickTimer = setInterval(renderOnlineStrip, 1000);         // the timers move between polls
  let finished = false;
  const step = async () => {
    try {
      const r = await api("GET", "/api/online/status");
      S.jobLost = 0;
      S.adminActive = !!r.admin_active;
      onJob(r.job);
    } catch {
      S.jobLost++;
      renderOnlineStrip();
    }
    if (!jobRunning() && S.job && S.jobLost === 0 && !finished) {
      finished = true;
      clearInterval(tickTimer);
      await finishJob();
    }
    if (jobRunning() || (jobBusy() && S.jobLost < 3)) pollTimer = setTimeout(step, 1000);
    else clearInterval(tickTimer);
  };
  await step();
}

async function finishJob() {
  const job = S.job;
  try {                                                     // notes the tests added to other checks
    const fresh = await api("GET", "/api/state");
    if (fresh.report) S.report = fresh.report;
  } catch { /* keep what we have */ }
  if (job.admin_message) toast(`Ran without administrator access: ${job.admin_message}`, "error", 10000);
  const found = jobFindings(job);
  const n = Object.keys(job.results).length;
  if (job.state === "done") setStatus(`Online tests done: ${plural(n, "test")}, ${plural(found, "finding")}.`, found ? "warned" : "done");
  else if (job.state === "stopped") setStatus(`Online tests stopped after ${n} of ${job.total}.`, "warned");
  else setStatus(`Online tests failed: ${job.error}`, "failed");
  renderAll();
}

function renderOnlineStrip() {
  const el = $("#online-strip");
  const job = S.job;
  if (!job || (S.jobHidden && !jobRunning())) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  const now = Date.now() / 1000 - S.jobClock;
  const results = Object.values(job.results);
  const done = results.length;
  const found = jobFindings(job);
  let frac = done / job.total, line, kind = jobRunning() ? "busy" : job.state;
  const extra = [];
  if (S.jobLost >= 3) {
    kind = "failed";
    line = "Lost contact with the app's server: the online tests may have stopped. Results so far are kept.";
  } else if (job.state === "starting") {
    line = "Starting the online tests…";
  } else if (job.state === "asking") {
    line = "Waiting for administrator authorization (see the password prompt)…";
  } else if (job.state === "running") {
    const cur = job.current;
    line = `Online tests: ${done} of ${job.total} done`;
    if (cur) {
      const el2 = now - cur.started;
      let what = `Now: “${cur.title}”, ${fmtDur(el2)}`;
      if (cur.id === "tel.observed_traffic") {
        what = `Now: watching traffic, ${Math.min(Math.round(el2), job.observe_seconds)} of ${job.observe_seconds} s`;
        frac = (done + Math.min(el2 / job.observe_seconds, 1)) / job.total;
      } else if (cur.id === "kern.updates_refreshed") {
        what += " (downloading package lists can take a few minutes)";
      }
      if (el2 > expectedSeconds(cur.id, job)) what += " — taking longer than usual";
      extra.push(what);
    }
    extra.push(`elapsed ${fmtDur(now - (job.started || job.created))}`);
    if (job.stopping) extra.push("stopping after this test");
  } else {
    const when = new Date(job.finished * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const took = fmtDur(job.finished - (job.started || job.created));
    line = job.state === "done" ? `Online tests finished at ${when}: ${plural(done, "test")}, ${plural(found, "finding")}, in ${took}.`
      : job.state === "stopped" ? `Online tests stopped at ${when}, after ${done} of ${job.total}.`
      : `Online tests failed at ${when}: ${job.error}${done ? ` (${plural(done, "result")} kept)` : ""}`;
    if (job.cancelled) extra.push(`“${job.cancelled}” was cancelled and its result discarded`
      + (job.winding_down ? "; it is still finishing in the background" : ""));
  }
  el.className = `ostrip ${kind}`;
  fill(el,
    h("div", { class: "orow" },
      jobRunning() && S.jobLost < 3 ? h("span", { class: "spinner on" }) : null,
      h("b", {}, line), extra.length ? h("span", { class: "muted" }, extra.join(" · ")) : null,
      h("span", { class: "spacer" }),
      jobRunning() && job.state === "running" && !job.stopping
        ? h("button", { class: "small", onclick: () => stopJob(false), title: "The test running now finishes and its result is kept; the rest don't run" }, "Stop after this test") : null,
      jobRunning() ? h("button", { class: "small danger", onclick: () => stopJob(true),
        title: "Cancels the test running now and discards its result; results of tests already finished are kept" }, "Stop now") : null,
      !jobRunning() && done ? h("button", { class: "small", onclick: () => setSource(S.source === "online" ? "all" : "online") },
        S.source === "online" ? "Show all results" : "Show only online results") : null,
      !jobRunning() ? h("button", { class: "small ghost", title: "Hide this bar (the results stay)", onclick: () => { S.jobHidden = true; renderOnlineStrip(); } }, "Hide") : null),
    jobRunning() ? h("div", { class: "obar" }, h("div", { style: `width: ${Math.round(Math.min(frac, 1) * 100)}%` })) : null);
}

async function stopJob(now) {
  try { onJob((await api("POST", "/api/online/stop", { now })).job); } catch (e) { toast(e.message, "error"); }
}

async function dropAdmin() {
  try { await api("POST", "/api/admin/drop"); } catch (e) { toast(e.message, "error"); }
  S.adminActive = false;
  renderTop();
  setStatus("Administrator access dropped. The helper has exited.", "done");
}

async function quit() {
  try { await api("POST", "/api/quit"); } catch { /* already gone */ }
  document.body.replaceChildren(h("div", { class: "quit-note" }, "DA Privacy Kit has quit. You can close this tab."));
}

/* Dark by default; "light" is the only other theme, kept in this browser's storage. */
const THEME_KEY = "daps-theme";
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const b = $("#theme-btn");
  if (b) { b.textContent = theme === "light" ? "Dark" : "Light"; b.title = `Switch to the ${theme === "light" ? "dark" : "light"} theme (remembered)`; }
}
function savedTheme() {
  try { return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark"; } catch { return "dark"; }
}
function toggleTheme() {
  const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(theme);
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* no storage */ }
}

async function init() {
  S.token = sessionToken();
  applyTheme(savedTheme());
  $("#theme-btn").addEventListener("click", toggleTheme);
  try {
    S.state = await api("GET", "/api/state");
  } catch (e) {
    document.body.replaceChildren(h("div", { class: "quit-note" },
      e.status === 403 ? "This page needs the link DA Privacy Kit printed when it started (it works once, in the tab it opens in). Start it again for a new one."
      : `Couldn't start: ${e.message}`));
    return;
  }
  S.report = S.state.report;
  S.adminActive = !!S.state.admin_active;
  S.presentation = S.state.presentation;
  $("#presentation-chip").addEventListener("click", () => (S.presentation?.lapsed || []).length ? presentationRenew()
    : presentationOff());
  if ((S.presentation?.lapsed || []).length) {
    toast(PRESENTATION_LAPSED, "error", 20000, { label: "Turn it on again", onclick: () => presentationRenew() });
  }
  $("#quit-btn").classList.toggle("hidden", !S.state.can_quit);
  $("#drop-admin").addEventListener("click", dropAdmin);
  $("#scan-btn").addEventListener("click", scan);
  $("#quit-btn").addEventListener("click", quit);
  $("#history-btn").addEventListener("click", openHistory);
  $("#online-btn").addEventListener("click", openOnline);
  $("#reads-btn").addEventListener("click", openReads);
  $("#tools-btn").addEventListener("click", openTools);
  $("#export-btn").addEventListener("click", () => openExport());
  $("#helper-note").addEventListener("click", openHelperNote);
  document.querySelectorAll("#source button").forEach(b => b.addEventListener("click", () => setSource(b.dataset.source)));
  document.querySelectorAll("#show button").forEach(b => b.addEventListener("click", () => setShow(b.dataset.show)));
  $("#filter").addEventListener("input", renderChecks);
  $("#show-na").addEventListener("change", renderChecks);
  if (S.report) S.show = "findings";
  try { $("#admin").checked = localStorage.getItem("daps-admin") === "1"; } catch { /* no storage */ }
  $("#admin").addEventListener("change", () => {
    try { localStorage.setItem("daps-admin", $("#admin").checked ? "1" : "0"); } catch { /* no storage */ }
  });
  if (S.report?.restored) {
    const left = (S.report.not_kept || []).length
      ? " Names and addresses aren't kept between runs (what starts at login, saved Wi-Fi networks' names, the online tests' addresses): scan again to see them." : "";
    setStatus(`Showing the saved results of the last scan, ${new Date(S.report.started * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}. `
      + "Scan again for the current state; nothing is read until you do." + left);
  } else if (!S.report) {
    setStatus("Read-only: a scan never changes anything, and nothing leaves this machine. “What a scan reads” lists exactly what it looks at.");
  }
  $("#brand").addEventListener("click", () => openWelcome());
  $("#brand").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openWelcome(); } });
  renderAll();
  const ot = S.state.open_tool;                 // started from a file manager's right-click entry (--tool)
  if (ot?.tool === "verify") openVerify(null, ot.paths[0] || "");
  else if (ot?.tool === "metadata") openMetadata(null, ot.paths);
  if (S.state.welcome?.show) openWelcome();           // last, so it is on top of anything opened
  try {                                         // online tests still running from before a reload
    const r = await api("GET", "/api/online/status");
    if (r.job) { S.jobHidden = !["starting", "asking", "running"].includes(r.job.state); onJob(r.job); }
    if (jobBusy()) pollJob();
  } catch { /* none */ }
}

init();
