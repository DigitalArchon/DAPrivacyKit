// The page's script against a canned API (fixture-state.json, made from the Python fixtures):
// init, the report's summary, the kinds, accepted findings, details, and the export
// dialogs. Run with `node tests/web/test_app.mjs` (needs jsdom on NODE_PATH); pytest runs it too.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// jsdom from tests/web/node_modules (npm install jsdom there), or DAPRIVACYSCANNER_NODE_PATH
const { JSDOM } = createRequire(import.meta.url)(join(process.env.DAPRIVACYSCANNER_NODE_PATH || join(here, "node_modules"), "jsdom"));
const web = join(here, "..", "..", "src", "daprivacyscanner", "web");
const fixture = JSON.parse(readFileSync(join(here, "fixture-state.json"), "utf8"));
const checkTitleOf = (id) => fixture.state.catalogue.find(sp => sp.id === id)?.title || id;
const html = readFileSync(join(web, "index.html"), "utf8").replace(/<script[^>]*><\/script>/, "");
const js = readFileSync(join(web, "app.js"), "utf8");

// a set-up that lasts (tier feature): listed in the Tools panel, never among the checks
fixture.state.catalogue.push({ id: "desk.file_manager_actions", title: "Verify and Remove metadata in the file manager's right-click menu",
  category: "desktop", severity: 1, scope: "user", tier: "feature", detect: [], fix: "", remedy: "Set up… adds them.",
  modifiers: [], applies_to: [], why: "", related: [], verify: "", contacts: [], kind: "info" });
fixture.state.report.results["desk.file_manager_actions"] = { id: "desk.file_manager_actions", status: "warn",
  effective_severity: 1, base_severity: 1, evidence: [], fixable: true, summary: "Not set up in Nemo.", partial: false,
  uncertain_on: [], findings: {}, error: "", duration_ms: 1, kind: "info", severity_reason: "", needs_admin: false,
  how_to: false, is_finding: false, is_hygiene: false,
  notes: [{ kind: "risk", title: "Allow mode", text: "What you don't answer for is let through.", related: [] },
          { kind: "info", title: "Nobody is asked", text: "Its window isn't running.", related: [] }] };

const calls = [];
let acceptAt = null;
const routes = {
  "GET /api/state": () => fixture.state,
  "GET /api/online/status": () => ({ job: null, admin_active: false }),
  "POST /api/scan": () => ({ ...fixture.state.report, admin_active: false }),
  // the server records the severity the finding has now; acceptAt pretends it was lower then
  "POST /api/accept": (body) => ({ accepted: body.accept ? { ...fixture.state.accepted, [body.check_id]: {
    note: body.note, when: 1790000000, severity: acceptAt ?? results[body.check_id].effective_severity,
    severity_reason: "" } } : {} }),
  "GET /api/report": () => "DA Privacy Kit report, now (redacted)\nline",
  "GET /api/undo": () => ({ entries: [] }),
  "GET /api/export": () => "DA Privacy Kit: everything it keeps, exported now\n== Changes made by DA Privacy Kit (0)",
  // a guide with an input: the plan follows the size it was built with
  "POST /api/fix/desk.ephemeral_folder/plan": (body) => {
    planBodies.push(body);
    const size = body?.params?.size_mb ?? 500;
    const plan = { id: "p1", check_id: "desk.ephemeral_folder", title: "Set it up", blockers: [], side_effects: [],
      needs_root: true, irreversible_files: 0,
      steps: [{ kind: "root", text: `mount ${size} MB`, reversible: true, irreversible: false, needs_root: true }] };
    return { guide: { check_id: "desk.ephemeral_folder", title: "A folder in memory", intro: "", steps: [
      { title: "Set up ~/Ephemeral", text: "", commands: [], side_effects: [], done: false,
        parts: [["What it is", "A folder in memory."], ["What it isn't", "A backup."]],
        inputs: [{ name: "size_mb", label: "Size", kind: "number", value: size, default: 500, help: "", min: 50, max: 4000,
                   unit: "MB", choices: [] },
                 { name: "noexec", label: "Don't let programs run from it (noexec)", kind: "bool", value: true,
                   default: true, help: "Safer.", min: null, max: null, unit: "", choices: [] }],
        options: [{ label: "Set it up", detail: "", recommended: true, plan, dry_run: "" }] }] }, dry_run: "" };
  },
};
const planBodies = [];
const toolBodies = {};
let metaJob = null, metaPolls = 0, outboxOn = true, outboxPermanent = false;
const metaSummary = (path, rel, groups, cleanable = true) => ({ path, name: rel.split("/").pop(), rel, root: null, tool: "exiftool",
  error: "", supported: true, cleanable, count: groups.reduce((n, g) => n + g[1], 0),
  groups: groups.map(([id, count, value]) => ({ id, title: id === "location" ? "Where it was made" : id, count,
    sample: value ? [{ key: id === "location" ? "GPS:GPSLatitude" : "IFD0:Model", value, member: "" }] : [] })) });
const metaFiles = () => [metaSummary("/home/a/photo.jpg", "photo.jpg", [["location", 2, "47 N"], ["software", 1, "GIMP"]]),
  ...(toolBodies.read?.paths?.includes("/home/a/Documents") ? [
    metaSummary("/home/a/Documents/a.jpg", "a.jpg", [["device", 1, "Pixel 8"]]),
    metaSummary("/home/a/Documents/Trip/b.jpg", "Trip/b.jpg", []),
    metaSummary("/home/a/Documents/notes.xyz", "notes.xyz", [], false)] : [])];
let ramOpen = false;
const ramdisk = () => ({ path: "~/RAMDisk", full_path: "/home/a/RAMDisk", open: ramOpen, size: ramOpen ? "1024M" : "",
  noexec: true, noswap: true, used: ramOpen ? 2048 : 0, total: ramOpen ? 1073741824 : 0, files: ramOpen ? 2 : 0, other: "",
  leftover: false, notes: [], max_mb: 4000, default_mb: 1024, commands: {
    open: ["chmod 500 /home/a/RAMDisk", "mount -t tmpfs -o nosuid,nodev,noexec,size=1024M,mode=0700,uid=1000,gid=1000,noswap tmpfs /home/a/RAMDisk"],
    open_exec: ["chmod 500 /home/a/RAMDisk", "mount -t tmpfs -o nosuid,nodev,size=1024M,mode=0700,uid=1000,gid=1000,noswap tmpfs /home/a/RAMDisk"],
    close: ["umount /home/a/RAMDisk"] } });
let browserJob = null, browserStarted = null, browserStartError = null, browserDue = false, torProgress = 45,
    browserUnchecked = false, sandboxDown = false, kdeWayland = false, waylandUnasked = false;
const browserState = () => ({ platform: "linux-x86_64", min_mb: 1024, can_pick: true, picker: "zenity", admin_active: true, job: browserJob,
  ramdisk: { ...ramdisk(), noexec: !ramOpen ? true : toolBodies.open?.noexec !== false }, mat2: true,
  sandbox: { available: !sandboxDown, why: sandboxDown ? "bubblewrap can't set up a sandbox here (setting up uid map: Permission denied)." : "",
             apparmor: sandboxDown, landlock: false, display: kdeWayland ? "wayland" : "x11",
             wayland_context: kdeWayland, wayland_risky: waylandUnasked ? null : kdeWayland ? [{ global: "ext_data_control_manager_v1",
               what: "read and change the clipboard in the background" }] : [], sound: true, gpu: true, python: true, wlroots: false, desktop: [],
             xephyr: { available: true, install: "sudo apt install xserver-xephyr" },
             pasta: { available: false, why: "pasta isn't installed (the passt package).", install: "sudo apt install passt" } },
  risks: { swap: toolBodies.swap?.off ? { on_disk: [], used_mb: 0, paused: ["/dev/sda3"], off_commands: [], on_commands: ["sudo swapon /dev/sda3"] }
                                       : { on_disk: ["/dev/sda3"], used_mb: 102, paused: [], off_commands: ["sudo swapoff /dev/sda3"],
                                           on_commands: ["sudo swapon /dev/sda3"] },
           thumbnails: { in_memory: false, folder: "~/.cache/thumbnails" },
           crash_dumps: { kept: true, start: ["echo 0 > /proc/self/coredump_filter", "prlimit --pid $$ --core=1:1"] },
           indexing: { baloo: toolBodies.baloo_off ? null : { on: true, contents: true, covers: true, index: true }, localsearch: null },
           hibernation: true, opensnitch: { log_level: 2, log: "/var/log/opensnitchd.log", database: "/home/a/opensnitch.sqlite" },
           memory: { total_mb: 8000, available_mb: 2500, browser_mb: 2048 } },
  browsers: [{ id: "tor", name: "Tor Browser", about: "Tor.", hosts: ["aus1.torproject.org", "dist.torproject.org"], tor: true, security: "safest",
               network: "tor", bridges: { mode: "none", count: 0, builtin: ["obfs4", "snowflake", "meek"] },
               connection: browserStarted ? (torProgress < 100 ? { state: "connecting", progress: torProgress, summary: "Asking for relay descriptors", problem: "" }
                                                         : { state: "connected", progress: 100, summary: "Done", problem: "" }) : null,
               start_error: browserStartError,
               release: { version: "15.0.24", signed: 1790687273, source: "download", unpacked: 1790800000,
                          check_from: 1790886400, check_due: browserDue, host: "aus1.torproject.org",
                          unchecked: browserUnchecked, signed_days: 2, stale: false },
               available: true, folder: "~/RAMDisk/tor-browser", installed: browserJob?.state === "done", running: !!browserStarted,
               uploads_folder: "~/RAMDisk/tor-browser/Browser/To upload", downloads_folder: "~/RAMDisk/tor-browser/Browser/Downloads",
               uploads: [], downloads: [{ name: "report.pdf", size: 2048, mtime: 1, warnings: ["can fetch things from the internet"],
                                          kind: "document", what: "a PDF", viewable: true },
                                        { name: "photo.jpg", size: 4096, mtime: 1, kind: "program", what: "a Linux program",
                                          viewable: false, warnings: ["it is a Linux program, though its name says jpg file"] }],
               downloads_other: 1,
               outbox: { folder: "~/TempBrowser/Outbox for Tor Browser", on: outboxOn, waiting: 1, originals: 1,
                         not_cleaned: ["notes.xyz"], permanent: outboxPermanent, watched: true, mat2: true,
                         recent: [{ what: "cleaned", name: "IMG_1.jpg", detail: "IMG_1.jpg", when: 1 },
                                  { what: "not_cleaned", name: "notes.xyz", detail: "its format isn't supported", when: 1 }] } },
             { id: "mullvad", name: "Mullvad Browser", about: "Mullvad.", hosts: ["cdn.mullvad.net"], available: true, security: "standard",
               folder: "~/RAMDisk/mullvad-browser", installed: false, running: false }] });
Object.assign(routes, {
  "GET /api/tools/browser": () => browserState(),
  "POST /api/tools/browser/get": (body) => { toolBodies.browser = body;
    browserJob = { state: "running", name: "Tor Browser", phase: "Downloading the archive from dist.torproject.org",
                   done: 50e6, total: 100e6, stopping: false }; return { job: browserJob }; },
  "POST /api/tools/browser/start": (body) => { browserStarted = body.browser; toolBodies.start = body;
    return { ...browserState(), started: { sandboxed: body.sandbox, display: "x11", landlock: true } }; },
  "POST /api/tools/browser/view": (body) => { (toolBodies.view = toolBodies.view || []).push(body);
    return { viewer: { app: "Document Viewer", command: "/usr/bin/xreader /home/user/report.pdf", flatpak: null, notes: [] },
             display: "x11" }; },
  "POST /api/tools/browser/swap": (body) => { toolBodies.swap = body;
    return { ...browserState(), swap: { off: ["/dev/sda3"], failed: [] }, admin_active: true }; },
  "POST /api/tools/browser/bridges": (body) => { toolBodies.bridges = body; return browserState(); },
  "POST /api/tools/browser/upload": (body) => { toolBodies.upload = body; return { ...browserState(), added: [{ name: "photo.jpg", cleaned: true }], errors: [] }; },
  "POST /api/tools/browser/save": (body) => { toolBodies.save = body; return { ...browserState(), saved: "/home/a/Documents/report.pdf" }; },
  "POST /api/tools/browser/outbox": (body) => { toolBodies.outbox = body; outboxOn = body.on; return browserState(); },
  "POST /api/tools/browser/dismiss": () => { browserJob = null; return { job: null }; },
  "GET /api/tools": () => ({ tools: [
      { id: "verify", group: "files", short: "s", title: "Verify a download", text: "t", button: "Verify a file…" },
      { id: "metadata", group: "files", short: "s", title: "Remove metadata", text: "t", button: "Choose files…" },
      { id: "ramdisk", group: "memory", short: "s", title: "RAM disk", text: "t", button: "Open…" },
      { id: "browser", group: "memory", short: "s", title: "Tor or Mullvad Browser in memory", text: "t", button: "Set up…" },
      { id: "trial", group: "apps", short: "s", title: "Try an app", text: "y", button: "Try something…" },
      { id: "keeps", group: "apps", short: "s", title: "What does this app keep?", text: "k", button: "Choose an app…" },
      { id: "trim", group: "drives", short: "s", title: "TRIM test", text: "t", button: "Test…" },
      { id: "names", group: "drives", short: "s", title: "Deleted file names", text: "n", button: "Look…" },
      { id: "handover", group: "drives", short: "s", title: "Before you hand over a drive", text: "h", button: "Choose a drive…" },
      { id: "retire", group: "drives", short: "s", title: "Retire a drive", text: "r", button: "Choose a drive…" },
      { id: "travel", group: "everyday", short: "s", title: "Before you travel", text: "t", button: "Open the checklist…" },
      { id: "presentation", group: "everyday", short: "s", title: "Presentation mode", text: "p", button: "Turn on…" },
      { id: "inuse", group: "everyday", short: "s", title: "Camera and microphone", text: "c", button: "Show…" }],
    groups: [{ id: "files", title: "Your files" }, { id: "memory", title: "Private browsing and memory" },
             { id: "apps", title: "Apps" }, { id: "drives", title: "Disks and drives" }, { id: "everyday", title: "Everyday" }],
    browser_disk: false,
    features: ["desk.file_manager_actions"], can_pick: true, downloads_dir: "~/Downloads",
    downloads: [{ path: "/home/a/Downloads/linuxmint-22.3-cinnamon-64bit.iso", name: "linuxmint-22.3-cinnamon-64bit.iso", size: 3e9, mtime: 1 }],
    verify: { gpgv: true, sqv: false, install: null },
    metadata: { mat2: { installed: true, install: "sudo apt install mat2" }, exiftool: { installed: false, install: "x" } },
    ramdisk: ramdisk(), admin_active: false }),
  "POST /api/tools/pick": (body) => ({ paths: [body?.folder ? "/home/a/Documents" : "/home/a/Downloads/photo.jpg"] }),
  "POST /api/tools/verify": (body) => { toolBodies.verify = body; return { verdict: { path: body.path, name: "linuxmint-22.3-cinnamon-64bit.iso",
    size: 3e9, level: "verified", title: "Verified: made by Linux Mint", text: "It is signed through the checksum list sha256sum.txt.",
    hashes: { sha256: "ab".repeat(32) }, signatures: [], lists: [{ path: "~/Downloads/sha256sum.txt", name: "sha256sum.txt", clearsigned: false,
      signature: { path: "/home/a/Downloads/sha256sum.txt.gpg", over: "x", kind: "openpgp", status: "good",
        fingerprint: "27DEB15644C6B3CF3BD7D291300F846BA25BAE09", fingerprint_grouped: "27DE B156 44C6 B3CF 3BD7  D291 300F 846B A25B AE09",
        issuer: "", project: "Linux Mint", project_signs: "ISOs", key_name: "Linux Mint ISO Signing Key", source: "list",
        expired: false, signed_at: 1, detail: "" },
      entries: [{ algo: "sha256", algo_title: "SHA-256", digest: "ab".repeat(32), name: "linuxmint-22.3-cinnamon-64bit.iso", matches: true }] }],
    pasted: null, steps: [], notes: [], project_hint: null } }; },
  "POST /api/tools/metadata/show": (body) => { toolBodies.show = body; return { files: [{ path: body.paths[0], name: "photo.jpg",
    tool: "mat2", error: "", supported: true, count: 2, groups: [
      { id: "location", title: "Where it was made", items: [{ key: "GPSLatitude", value: "47 N", member: "" }] },
      { id: "software", title: "Software that made or edited it", items: [{ key: "Software", value: "GIMP", member: "" }] }] }] }; },
  // the job runs for one poll, then is done
  "POST /api/tools/metadata/read": (body) => { toolBodies.read = body; metaJob = { kind: "read", state: "running", phase: "Reading",
    done: 0, total: 0, current: "", paths: body.paths, hidden: body.hidden, selection: null, result: null, error: "" };
    metaPolls = 0; return { job: metaJob }; },
  "POST /api/tools/metadata/clean": (body) => { toolBodies.clean = body; metaJob = { kind: "clean", state: "running", phase: "Making clean copies",
    done: 1, total: 3, current: "a.jpg", paths: body.paths, hidden: body.hidden, selection: null, result: null, error: "" };
    metaPolls = 0; return { job: metaJob }; },
  "GET /api/tools/metadata/job": () => {
    if (metaJob?.state === "running" && ++metaPolls > 1) metaJob = metaJob.kind === "read" ? { ...metaJob, state: "done",
      selection: { files: metaFiles().length, folders: toolBodies.read.paths.includes("/home/a/Documents") ? ["~/Documents"] : [],
                   skipped: { hidden: 2 }, truncated: false, limit: 5000 }, result: { files: metaFiles() } }
      : { ...metaJob, state: "done", result: { cleaned: 1, failed: 1, folders: metaFiles().length > 1
          ? [{ folder: "~/Documents", output: "~/Documents (cleaned)", output_path: "/home/a/Documents (cleaned)" }] : [],
        results: [{ path: "/home/a/photo.jpg", name: "photo.jpg", rel: "photo.jpg", root: null, ok: true,
          output: "~/photo.cleaned.jpg", output_name: "photo.cleaned.jpg", message: "",
          remaining: { path: "/home/a/photo.cleaned.jpg", name: "photo.cleaned.jpg", rel: "photo.jpg", tool: "mat2", error: "",
                       supported: true, cleanable: true, count: 0, groups: [] } },
          { path: "/home/a/Documents/notes.xyz", name: "notes.xyz", rel: "notes.xyz", root: "/home/a/Documents", ok: false,
            output: null, output_name: null, message: "notes.xyz's format (x) is not supported", remaining: null }] } };
    return { job: metaJob };
  },
  "POST /api/tools/metadata/stop": () => ({ job: metaJob }),
  "POST /api/tools/metadata/open": (body) => { toolBodies.metaOpen = body; return { ok: true }; },
  "POST /api/tools/ramdisk/open": (body) => { toolBodies.open = body; ramOpen = true; return { ramdisk: ramdisk(), admin_active: true }; },
  "POST /api/tools/ramdisk/close": () => { ramOpen = false; return { ramdisk: ramdisk(), wiped: { files: 2, bytes: 2048, failed: [] }, admin_active: true }; },
  "GET /api/tools/trim": () => ({ targets: [
      { mount: "/", fstype: "ext4", size: 1e12, free: 5e11, folder: "~/.local/share/daprivacyscanner/trim-test", blocked: "",
        known: "", notes: [], trim: "weekly", encrypted: true, vm: false, minutes: [10, 35], environment: [] },
      { mount: "/home", fstype: "xfs", size: 1e12, free: 0, folder: null, blocked: "Only ext4 and btrfs can be tested; /home is xfs.",
        known: "", notes: [], trim: null, encrypted: false, vm: false, minutes: [10, 35], environment: [] }],
    leftovers: [], test_bytes: 268439040, job: trimJob, admin_active: !!trimJob }),
  "POST /api/tools/trim/start": (body) => { toolBodies.trim = body; trimJob = { state: "running", mount: body.mount,
    phase: "Reading the whole disk to find the test files", scan: "baseline", done: 25e10, total: 1e12, phase_started: 100,
    now: 160, started: 90, stopping: false, result: null, error: "",
    steps: [{ id: "begin", label: "Asking the drive about itself", optional: false, state: "done", started: 90, finished: 95, done: 0, total: 0, estimate: null },
      { id: "write", label: "Writing the test files", optional: false, state: "done", started: 95, finished: 100, done: 0, total: 0, estimate: null },
      { id: "baseline", label: "Reading the whole disk to find the test files", optional: false, state: "running", started: 100, finished: null, done: 25e10, total: 1e12, estimate: 1200 },
      { id: "trim", label: "Deleting the test files and trimming", optional: false, state: "pending", started: null, finished: null, done: 0, total: 0, estimate: null },
      { id: "after", label: "Reading the whole disk again after the trim", optional: false, state: "pending", started: null, finished: null, done: 0, total: 0, estimate: 1200 },
      { id: "wait", label: "Waiting a few minutes: drives can finish trimming in the background", optional: true, state: "pending", started: null, finished: null, done: 0, total: 0, estimate: 180 },
      { id: "later", label: "Reading the whole disk a last time", optional: true, state: "pending", started: null, finished: null, done: 0, total: 0, estimate: 1200 },
      { id: "remove", label: "Removing the test folder", optional: false, state: "pending", started: null, finished: null, done: 0, total: 0, estimate: null }] };
    return { job: trimJob }; },
  "POST /api/tools/trim/stop": () => { trimJob.stopping = true; return { job: trimJob }; },
  "POST /api/tools/trim/dismiss": () => { trimJob = null; return { job: null }; },
  "GET /api/tools/names": () => ({ targets: [
      { mount: "/", fstype: "ext4", size: 1e12, scope: "home", blocked: "", encrypted: true, trim: "weekly", no_trim: "",
        guide: "", minutes: [10, 35], source: "/dev/nvme0n1p2", trim_passed: true },
      { mount: "/mnt/old", fstype: "xfs", size: 1e12, scope: "mount", blocked: "Only ext4 and btrfs can be tested; /mnt/old is xfs.",
        encrypted: false, trim: null, no_trim: "", guide: "", minutes: [10, 35], source: "/dev/sdb1", trim_passed: null }],
    admin_active: false, busy: false }),
  "POST /api/tools/names/start": (body) => { namesCalls.push("start:" + body.mount); return { job: { state: "running" } }; },
  "GET /api/tools/names/job": () => ({ job: { state: "done", trimmed: null, result: { count: 9, truncated: false, fstype: "ext4",
    mount: "/", scope: "home", root: "~", unreadable: 0, trim: "weekly", no_trim: "", guide: "", encrypted: true, trim_passed: true,
    facts: ["ext4 keeps a deleted file's name in its folder's own records until a new entry reuses the space."],
    commands: ["sudo e2fsck -fD /dev/nvme0n1p2"],
    journal: { state: "read", bytes: 1073741824, names: 3, orphans: 139, clearable: true, fast_commit: false, checksums: true,
      command: "sudo python3 -c 'import fcntl, os, struct; fcntl.ioctl(os.open(\"/\", os.O_RDONLY), 0x4004662B, struct.pack(\"I\", 2))'" },
    folders: [
    { path: "~/Documents", rel: "Documents", names: ["secret-plan.odt", "<b>tax</b>.pdf"], hashes: [], browser_cache: false, notes: [],
      hidden: false, gone: false, journal_only: 1, remedy: { method: "rebuild", why: "Rebuilt: every entry is moved into a new folder." } },
    { path: "~/Notes", rel: "Notes", names: ["diary.txt"], hashes: [], browser_cache: false, notes: [], hidden: false, gone: false,
      journal_only: 1, remedy: { method: "none", journal: true, why: "These names are in the journal only: clearing the journal removes them." } },
    { path: "~/Notes/Project X", rel: "Notes/Project X", names: ["offer.pdf"], hashes: [], browser_cache: false, notes: [], hidden: false,
      gone: true, journal_only: 1, remedy: { method: "none", journal: true, why: "This folder is gone." } },
    { path: "~/Dropbox", rel: "Dropbox", names: ["contract.pdf"], hashes: [], browser_cache: false, notes: [], hidden: false,
      remedy: { method: "none", synced: "Dropbox", why: "Dropbox keeps this folder: delete them permanently there." } },
    { path: "~/.cache/mozilla/x/cache2/entries", rel: ".cache/mozilla/x/cache2/entries", names: [],
      hashes: ["0000000000000000000000000000000000000001", "0000000000000000000000000000000000000002",
               "0000000000000000000000000000000000000003", "0000000000000000000000000000000000000004", "0000000000000000000000000000000000000005"],
      browser_cache: true, notes: [], hidden: true, remedy: { method: "rebuild", why: "Rebuilt." } },
    { path: "~/.cache/app", rel: ".cache/app", names: ["tmp-1234"], hashes: [], browser_cache: false, notes: [], hidden: true,
      remedy: { method: "rebuild", why: "Rebuilt." } }] } } }),
  "POST /api/tools/names/forget": () => { namesCalls.push("forget"); return { job: null }; },
  "POST /api/tools/names/journal/clear": () => { namesCalls.push("journal-clear"); return { cleared: true, seconds: 0.6 }; },
  "POST /api/tools/names/journal/others": () => { namesCalls.push("journal-others");
    return { names: ["someone-elses.txt", "<i>x</i>.conf"], hashes: [], truncated: false, records: 139 }; },
  "POST /api/tools/names/plan": (body) => { namesCalls.push("plan:" + body.folders.join(",") + (body.rebuild?.length ? ":rebuild=" + body.rebuild.join(",") : ""));
    return { admin_active: false, plan: {
    mount: "/", folders: body.folders.map(rel => ({ rel, path: "~/" + rel, method: "rebuild", why: "Rebuilt.", blockers: [], entries: 3,
      indexed: false, synced: "" })), steps: ["Rebuild ~/Documents: make a new folder beside it.", "Trim the free space of /."],
    side_effects: ["A rebuilt folder is a new folder at the same place."], needs_root: true, trims: true, ask_synced: true } }; },
  "POST /api/tools/names/clean": (body) => { namesCalls.push("clean:" + body.folders.join(",") + ":" + body.not_synced);
    return { job: { state: "running", steps: [] } }; },
  "GET /api/tools/names/clean": () => ({ job: { state: "done", steps: [], result: { mount: "/", trimmed: 4096, journal: "read",
    folders: [{ path: "~/Documents", rel: "Documents", method: "rebuild", state: "partly", left: ["secret-plan.odt"],
      text: "Rebuilt (3 entries moved). 1 of its 2 deleted names can still be read: in the journal." }],
    explanation: ["The journal keeps copies of folders' records until it wraps."] } } }),
  "POST /api/tools/names/check": (body) => { namesCalls.push("check:" + body.folders.join(",")); return { result: { mount: "/",
    trimmed: null, journal: "read", folders: [{ path: "~/Documents", rel: "Documents", method: "check", state: "done",
      text: "None of its deleted names can be read any more." }], explanation: [] } }; },
});
const namesCalls = [];
let trimJob = null;
const TOOL_COUNT = routes["GET /api/tools"]().tools.length;
let inuseCalls = 0;
const travelIds = Object.keys(fixture.state.report.results).filter(id => !id.startsWith("desk.file_manager")).slice(0, 3);
routes["GET /api/tools/travel"] = () => ({ intro: "A laptop that travels.", advice: ["Power it off."],
  items: [...travelIds.map(id => ({ id, why: `Why ${id} matters.` })), { id: "no.such_check", why: "x" }],
  ramdisk: { open: true, files: 2 } });
const handoverCalls = [];
routes["GET /api/tools/handover"] = () => ({ drives: [
  { mount: "/media/a/STICK", device: "/dev/sdb1", fstype: "vfat", label: "STICK", transport: "usb", readonly: false, blocked: "" },
  { mount: "/media/a/OLD", device: "/dev/sdc1", fstype: "exfat", label: "OLD", transport: "usb", readonly: true,
    blocked: "It is mounted read-only, so nothing on it can be deleted." }] });
routes["POST /api/tools/handover/plan"] = (body) => { handoverCalls.push("plan:" + body.mount); return { plan_id: "p1",
  drive: { mount: "/media/a/STICK", label: "STICK" }, files: 3, bytes: 3000, truncated: false, in_use: [],
  media: ["/media/a/STICK/img.jpg"], media_count: 1, steps: [],
  groups: [{ id: "own_trash", title: "Your trash on this drive", text: "Files you deleted.", count: 2, bytes: 2000,
             folders: [".Trash-1000"], files: [".Trash-1000/files/<b>x</b>.jpg", ".Trash-1000/info/x.trashinfo"], more: 0 },
           { id: "views", title: "Folder view settings", text: "Dolphin.", count: 1, bytes: 1000, folders: [],
             files: ["Photos/.directory"], more: 0 }] }; };
routes["POST /api/tools/handover/clean"] = (body) => { handoverCalls.push(`clean:${body.plan_id}:${body.confirm}`);
  return { deleted: 3, skipped: 0, lines: [] }; };
const retireCalls = [];
const retireFacts = {};
routes["GET /api/tools/retire"] = () => ({ admin_active: false, facts: retireFacts, drives: [
  { name: "nvme0n1", path: "/dev/nvme0n1", model: "Samsung 990", serial: "S1", size: 1e12, kind: "nvme", kind_title: "NVMe SSD",
    system: ["/"], mounted: [], open_crypt: [], luks: [], plain: [], smr: false, blocked: "This drive holds the running system (/)." },
  { name: "sdb", path: "/dev/sdb", model: "WDC WD40EFAX", serial: "WD-1", size: 4e12, kind: "hdd", kind_title: "Hard disk",
    system: [], mounted: [], open_crypt: [], luks: ["/dev/sdb1"], plain: [], smr: true, blocked: "" }] });
routes["POST /api/tools/retire/facts"] = (body) => { retireCalls.push("facts:" + body.disk);
  retireFacts[body.disk] = { source: "smartctl --identify", notes: [], nvme: null,
    ata: { supported: true, frozen: true, enhanced: true, erase_minutes: 470, enhanced_minutes: 480, sanitize: { supported: false } } };
  return { facts: retireFacts[body.disk], admin_active: true }; };
routes["POST /api/tools/retire/guide"] = (body) => { retireCalls.push(`guide:${body.disk}:${body.typed}:${body.from_start}`);
  return { guide: { check_id: "tool.retire", title: "Erase /dev/sdb", intro: "Every command below erases /dev/sdb.", advice: true,
    steps: [{ title: "Overwrite it once with zeros", text: "One full pass.", options: [], inputs: [], done: false, side_effects: [],
              commands: ["sudo dd if=/dev/zero of=/dev/sdb bs=16M oflag=direct status=progress"] }] } }; };
let presOn = false;
const presCalls = [];
routes["GET /api/tools/presentation"] = () => ({ on: presOn, since: presOn ? 1790000000 : null, desktop: "GNOME", changed: [], undo: [],
  plan: [{ what: "Notification banners off (Do Not Disturb)", text: "gsettings set org.gnome.desktop.notifications show-banners false" }],
  notes: ["Programs that show messages inside their own window aren't covered."] });
routes["POST /api/tools/presentation/on"] = () => { presCalls.push("on"); presOn = true; return { on: true, since: 1790000000 }; };
routes["POST /api/tools/presentation/renew"] = () => { presCalls.push("renew"); return { on: true, since: 1790000000, lapsed: [] }; };
routes["POST /api/tools/presentation/off"] = () => { presCalls.push("off"); presOn = false;
  return { on: false, since: null, messages: ["back"], kept: ["Notification banners were changed meanwhile, so they are left as they are now."], failed: [] }; };
// Try an app: a trial prepared, started, ended and discarded
let trialNow = null;
const trialCalls = [];
const trialStatus = { available: true, why: "", apparmor: false, python: true, display: "x11", wayland_context: null, wayland_risky: null,
  pasta: { available: false, why: "pasta isn't installed", install: "sudo apt install passt", lan_blocked: false },
  xephyr: { available: true, install: "" }, sound: true, gpu: true, flatpak: true,
  places: [{ id: "memory", words: "In memory", folder: "/run/user/1000/daprivacyscanner-trial", free: 3e9, noexec: false },
           { id: "disk", words: "On the disk", folder: "/home/a/.cache/daprivacyscanner-trial", free: 4e11, noexec: false }] };
const trialResultData = { seconds: 95, failed: false, output: [], missed: 0, network: "observed", decoys_planted: 34,
  decoys: [{ path: "~/.ssh/id_ed25519", what: "an SSH private key", listed: 0, opened: 2, changed: 0, first: 1 },
           { path: "~/.gnupg", what: "the folder ~/.gnupg", listed: 1, opened: 0, changed: 0, first: 2 }],
  left: { files: 3, bytes: 5000, folders: 2 },
  hosts: { hosts: [{ host: "telemetry.example.net", named_by: "dns", addresses: 1, ports: ["443"], connections: 2, sent: 4000, received: 900 }],
           looked_up: ["unused.example.org"], packets: 60, left_out: 0, broken: 0 },
  summary: { seconds: 95, files: 3, totals: { opened: 0, written: 0, created: 3, deleted: 0, ran: 0 },
    kinds: { app: "Programs' own data", yours: "Your files", temp: "Temporary files", media: "Other disks", system: "The system" },
    places: [{ kind: "app", folder: "~/.config/Tool", opened: 0, written: 0, created: 3, deleted: 0, left: 3, bytes: 5000,
               files: [{ name: "~/.config/Tool/id.json", did: "created, written" }] }],
    places_left_out: 0, regular: [], sensitive: [], yours: { opened: 0, changed: 0 } } };
const trialBase = () => ({ id: "0a1b", kind: "archive", name: "tool.tar.gz", what: "an archive", where: "memory", command: "",
  candidates: [{ rel: "tool/bin/run.sh", what: "a script", label: "" }, { rel: "tool/main.py", what: "a script", label: "" }],
  options: {}, how: {}, started: null, ended: null, exit: null, stopped: false, live: null, result: null, now: 1790000100,
  notes: ["It is unpacked inside a sandbox."] });
routes["GET /api/tools/trial"] = () => ({ status: trialStatus, can_pick: true, trial: trialNow,
  apps: [{ id: "foo.desktop", name: "Foo", kind: "native", comment: "", command: "foo", terminal: false }] });
routes["POST /api/tools/trial/prepare"] = (body) => { trialCalls.push(`prepare:${body.path || body.app}:${body.where}`);
  trialNow = { ...trialBase(), state: "ready" }; return { trial: trialNow }; };
routes["POST /api/tools/trial/start"] = (body) => { trialCalls.push("start:" + JSON.stringify(body));
  trialNow = { ...trialBase(), state: "running", started: 1790000000, command: "/app/tool/main.py",
    how: { engine: "bubblewrap", engine_name: "bubblewrap", network: body.network, display: "x11", nested: body.nested, gpu: body.gpu,
           sound: body.sound, decoys: 34, whole: "bwrap --die-with-parent … /app/tool/main.py" },
    live: { files: 3, written: 3, decoys: 1, overflow: 0, hosts: null,
            decoys_seen: [{ path: "~/.ssh/id_ed25519", what: "an SSH private key", listed: 0, opened: 1, changed: 0, first: 1 }] } };
  return { trial: trialNow }; };
routes["GET /api/tools/trial/status"] = () => ({ trial: trialNow });
routes["POST /api/tools/trial/stop"] = () => { trialCalls.push("stop");
  trialNow = { ...trialNow, state: "ended", stopped: true, exit: -15, live: null, result: trialResultData,
               how: { ...trialNow.how, network: "observed" } };
  return { trial: trialNow }; };
routes["POST /api/tools/trial/discard"] = () => { trialCalls.push("discard"); trialNow = null; return { trial: null }; };

// What does this app keep?: the watch, then its result (counts; the user's own files never named)
let keepsJob = null;
const keepsCalls = [];
const keepsResult = { app: "Foo", seconds: 1260, files: 9, totals: { opened: 4, written: 2, created: 3, deleted: 1, ran: 0 },
  kinds: { app: "Programs' own data", yours: "Your files", temp: "Temporary files", media: "Other disks", system: "The system" },
  places: [{ kind: "app", folder: "~/.config/Foo", opened: 1, written: 2, created: 0, deleted: 0, left: 2, bytes: 4096 },
           { kind: "app", folder: "~/.cache/Foo", opened: 0, written: 0, created: 3, deleted: 1, left: 2, bytes: 90000 },
           { kind: "yours", folder: "~/Documents", opened: 3, written: 0, created: 0, deleted: 0, left: 0, bytes: 0 }],
  places_left_out: 0, regular: [{ path: "~/.config/Foo/history.db", writes: 40, minutes: 12, type: "an SQLite database", size: 8192 }],
  sensitive: [{ what: "SSH keys and settings", opened: 1, written: 0 }], yours: { opened: 3, changed: 0 },
  records: { found: [{ path: "~/.cache/thumbnails/large/0a.png", who: "tumblerd", names: 2, type: "a PNG picture" },
                     { path: "~/.config/Foo/recent.conf", who: "", names: 3, type: "a text file" }], searched: 12, skipped: 0, names: 3 },
  others: 4, system: [{ folder: "/usr/lib", files: 200 }], gone: [{ folder: "~/.cache", events: 2 }], folded: 0, events: 5000,
  foreign: 40, overflow: 0, unresolved: 0, others_left: 0, watched: ["/"], not_watched: [["/mnt/x", "this kind of filesystem can't be watched"]],
  limits: ["It sees this app's own processes."] };
routes["GET /api/tools/keeps"] = () => ({ unavailable: null, warning: "This needs administrator access from the moment you start until you end it.",
  limits: ["It sees this app's own processes."], admin_active: !!keepsJob && keepsJob.state === "running",
  apps: [{ id: "foo.desktop", name: "Foo", kind: "native", comment: "Edits things", command: "foo", terminal: false },
         { id: "org.x.Bar.desktop", name: "Bar", kind: "flatpak", comment: "", command: "flatpak run org.x.Bar", terminal: false }],
  job: keepsJob && { ...keepsJob, now: 1790000600 } });
routes["POST /api/tools/keeps/start"] = (body) => { keepsCalls.push("start:" + body.app);
  keepsJob = { state: "running", app: "Foo", started: 1790000000, counts: { files: 7, others: 2, events: 900, overflow: 0 }, alive: 3,
               closed: false, absent: false, not_watched: [], stopping: false, error: "" };
  return { job: keepsJob }; };
routes["POST /api/tools/keeps/stop"] = () => { keepsCalls.push("stop"); keepsJob = { state: "done", app: "Foo", result: keepsResult, stopping: false };
  return { job: keepsJob }; };
routes["POST /api/tools/keeps/dismiss"] = () => { keepsCalls.push("dismiss"); keepsJob = null; return { job: null }; };
routes["GET /api/tools/inuse"] = () => { inuseCalls++; return { server: "pipewire", session: "wayland", using: ["Firefox"],
  devices: [{ kind: "camera", name: "Integrated Camera", nodes: ["/dev/video0"], holders: [], via_server: [] },
            { kind: "microphone", name: "PCH", nodes: ["/dev/snd/pcmC0D0c"], holders: [], via_server: ["pipewire"] }],
  streams: [{ app: "Firefox", binary: "firefox", pid: 1, what: "microphone", what_title: "a microphone",
              source: "Built-in Audio", state: "running", active: true, via: "pipewire" }],
  notes: ["Only your own programs are listed."] }; };
const helperBodies = [];
routes["POST /api/helper/install"] = (body) => { helperBodies.push(body);
  return { ok: true, removed: [], helper_installed: false, helper_stale: false }; };
const dom = new JSDOM(html, { url: "http://127.0.0.1:1/", runScripts: "dangerously", pretendToBeVisual: true });
const { window } = dom;
window.fetch = async (path, opts = {}) => {
  const key = `${opts.method || "GET"} ${path.split("?")[0]}`;
  calls.push(key);
  if (opts.headers?.["X-Token"] !== "t0ken") throw new Error("missing X-Token on " + key);
  if (opts.credentials !== "omit") throw new Error("cookies would be sent on " + key);
  const handler = routes[key];
  if (!handler) return { ok: false, status: 404, statusText: "no route " + key, json: async () => ({}) };
  const data = handler(opts.body ? JSON.parse(opts.body) : undefined);
  return { ok: true, status: 200, json: async () => data, text: async () => (typeof data === "string" ? data : JSON.stringify(data)) };
};
window.scrollTo = () => {};
window.HTMLElement.prototype.scrollIntoView = function () {};
window.URL.createObjectURL = () => "blob:x";
window.document.body.dataset.token = "t0ken";            // as the server hands the session token over, once
// as a classic script, so the page's functions are globals the test can call (the file is strict)
const script = window.document.createElement("script");
script.textContent = js;
window.document.body.append(script);
const tick = () => new Promise(r => setTimeout(r, 20));
await tick(); await tick();

let failures = 0;
const check = (cond, what) => { if (!cond) { failures++; console.error("FAIL:", what); } else console.log("ok:", what); };
const $ = (s) => window.document.querySelector(s);
const $$ = (s) => [...window.document.querySelectorAll(s)];
const text = (s) => $(s)?.textContent || "";

check(calls.includes("GET /api/state"), "init asked for the state");
check(window.document.body.dataset.token === undefined && window.sessionStorage.getItem("daps-token") === "t0ken",
      "the session token is taken off the page and kept in this tab's session storage");
const results = fixture.state.report.results;
const nFindings = Object.keys(results).filter(id => results[id].is_finding && !fixture.state.accepted[id]).length;
const unchecked = Object.keys(results).filter(id => ["unknown", "error"].includes(results[id].status) && results[id].effective_severity > 0);
const findingRows = () => $$("#checks-list .citem").filter(e => !unchecked.includes(e.id.slice(2)));
check(findingRows().length === nFindings, `the findings are listed after init with a report (${nFindings})`);
{ // what couldn't be checked comes first, by severity, in the Findings view too
  const rows = $$("#checks-list .citem");
  const first = rows.slice(0, unchecked.length).map(e => e.id.slice(2));
  check(unchecked.length > 0 && $("#checks-list .cat-head")?.id === "unchecked", "the first section is Couldn't check");
  check(first.length === unchecked.length && first.every(id => unchecked.includes(id)), "it lists everything that couldn't be checked");
  const sevs = first.map(id => results[id].effective_severity);
  check(sevs.every((x, i) => !i || sevs[i - 1] >= x), "sorted by the severity a problem would have");
  check($(".report .unchecked-count")?.textContent.startsWith(`${unchecked.length} couldn't be checked · highest severity ${Math.max(...sevs)}`),
        "the summary counts them, with the highest severity at stake: " + text(".report .unchecked-count"));
  check(!$$(".unchecked-why button").length, "no administrator button when none needs it");
  const S = window.eval("S");
  S.report.results[first[0]].needs_admin = true;
  window.renderChecks(); await tick();
  check($$(".unchecked-why button").some(b => b.textContent === "Scan with administrator access")
        && text(".unchecked-why").includes("1 of them needs administrator access"),
        "checks that only need administrator access get a button: " + text(".unchecked-why"));
  delete S.report.results[first[0]].needs_admin;
  window.renderChecks(); await tick();
  check($(`#c-${first[0].replace(".", "\\.")} .sev-stake`) !== null, "their number is outlined: what is at stake");
}
check(text("#scan-info").startsWith("Scanned at"), "the top bar shows when the scan ran");
check(text(".report .headline").match(/^\d+ findings$/), "the headline counts findings: " + text(".report .headline"));
check($$(".report .band").some(b => b.textContent.includes("hygiene")), "hygiene items are counted apart");
check(!$$("#checks-list .citem.band-na").length, "not-applicable rows hidden by default");
check(window.document.documentElement.dataset.theme === "dark", "dark theme by default");
$("#theme-btn").click();
check(window.document.documentElement.dataset.theme === "light" && text("#theme-btn") === "Dark", "the header button switches to light");
check(window.localStorage.getItem("daps-theme") === "light", "the theme choice is remembered");
$("#theme-btn").click();
check(window.document.documentElement.dataset.theme === "dark", "and back to dark");

// a scan, then the findings view is what is shown
await window.scan(); await tick();
{ // what changed since the last scan: chips, never "[object HTMLSpanElement]"
  const S = window.eval("S");
  const id = Object.keys(results).find(k => results[k].is_finding && !fixture.state.accepted[k]);
  // resolved: a check that passes now (one found again since, a fix reverted, isn't listed as resolved)
  const gone = Object.keys(results).find(k => results[k].status === "pass");
  S.report.changes = { previous: 1790000000, new: [id], resolved: [gone, "tel.location"], changed: [{ id, from: 2, to: 5 }] };
  window.renderChecks(); await tick();
  check(!text(".report .changes").includes("[object") && $$(".report .changes .chip").length === 3,
        "what changed shows its findings as chips: " + text(".report .changes"));
  const titled = (cid) => fixture.state.catalogue.find(sp => sp.id === cid).title;
  check(text(".report .changes").includes(titled(gone)) && !text(".report .changes").includes(titled("tel.location")) && text(".report .changes").includes(`${titled(id)}: severity 2 → 5`)
        && !$$(".report .changes .chip").some(c => c.textContent === id), "the chips name each check by its title, not its id");
  // fixed since the scan: the new finding's chip goes; one whose severity changed is resolved now
  const id2 = Object.keys(results).find(k => k !== id && results[k].is_finding && !fixture.state.accepted[k]);
  S.report.changes = { previous: 1790000000, new: [id], resolved: [], changed: [{ id: id2, from: 2, to: 5 }] };
  const [r1, r2] = [S.report.results[id], S.report.results[id2]];
  window.takeRecheck({ result: { ...r1, status: "pass" }, rechecked: { [id2]: { ...r2, status: "pass" } } }); await tick();
  check(!$$(".report .changes .chip.new").length && !text(".report .changes").includes("severity 2 → 5")
        && $$(".report .changes .chip.resolved").map(c => c.textContent).join() === titled(id2),
        "a finding fixed since the scan is no longer listed as new: " + text(".report .changes"));
  S.report.results[id] = r1; S.report.results[id2] = r2;
  { // "new findings" are findings: hygiene and information are new under their own names, set-ups not at all
    const kindOf = (k) => fixture.state.catalogue.find(sp => sp.id === k);
    const active = (k) => ["fail", "warn"].includes(S.report.results[k].status) && S.report.results[k].effective_severity > 0;
    const hyg = Object.keys(results).find(k => kindOf(k)?.kind === "hygiene" && kindOf(k).tier !== "feature");
    const feat = fixture.state.catalogue.find(sp => sp.tier === "feature").id;
    const [h0, f0] = [S.report.results[hyg], S.report.results[feat]];
    S.report.results[hyg] = { ...h0, status: "fail", effective_severity: 2, is_hygiene: true };
    S.report.results[feat] = { ...(f0 || h0), id: feat, kind: "info", status: "fail", effective_severity: 2 };
    S.report.changes = { previous: 1790000000, new: [id, hyg, feat], resolved: [], changed: [] };
    window.renderChecks(); await tick();
    const line = text(".report .changes");
    check(active(id) && line.includes("1 new finding") && !line.includes("new findings") && line.includes("1 new hygiene")
          && $$(".report .changes .chip.new").map(c => c.textContent).join() === [titled(id), titled(hyg)].join(),
          "only findings are counted as new findings: " + line);
    S.report.results[hyg] = h0;
    if (f0) S.report.results[feat] = f0; else delete S.report.results[feat];
  }
  { // nothing the user accepted is in what changed since the last scan: new, resolved, changed or not checked again
    const acc0 = S.state.accepted;
    S.report.changes = { previous: 1790000000, new: [id], resolved: [gone], changed: [{ id: id2, from: 2, to: 5 }] };
    window.renderChecks(); await tick();
    check($$(".report .changes .chip").length === 3, "(three changes while nothing is accepted): " + text(".report .changes"));
    const sev = (k) => S.report.results[k].effective_severity;
    S.state.accepted = { ...acc0, [id]: { severity: sev(id), when: 1, note: "" }, [gone]: { severity: sev(gone), when: 1, note: "" },
                         [id2]: { severity: sev(id2), when: 1, note: "" } };
    window.renderChecks(); await tick();
    check(!$$(".report .changes .chip").length && text(".report .changes").includes("nothing changed"),
          "accepted findings are left out of what changed: " + text(".report .changes"));
    S.state.accepted = { ...acc0, [id2]: { severity: sev(id2) - 1, when: 1, note: "" } };
    window.renderChecks(); await tick();
    check($$(".report .changes .chip").some(c => c.textContent.includes(titled(id2))),
          "one whose severity rose above the one it was accepted at is shown again there too");
    S.state.accepted = acc0;
  }
  { // the footer counts the whole report, as the headline does, whichever source is listed; a chip shows its row
    const footer = () => text("#checks-count");
    window.setSource("all"); await tick();
    const all = footer();
    window.setSource("online"); await tick();
    check(footer() === all && all.includes(text(".report .headline").replace(/s$/, "")),
          "the footer's count doesn't change with the source listed: " + footer() + " / " + all);
    S.report.changes = { previous: 1790000000, new: [id], resolved: [], changed: [] };
    window.renderChecks(); await tick();
    check(!$(`#c-${id.replace(".", "\\.")}`), "(a scan's row isn't listed among the online results)");
    $(".report .changes .chip.new").click(); await tick();
    check($(`#c-${id.replace(".", "\\.")}`) && S.source === "all", "a chip shows its row whatever source was listed");
    S.open.delete(id);
    // the online tests' count leaves out a finding the user accepted, as the headline does
    const job = { results: { a: { status: "fail", effective_severity: 5, kind: "finding" },
                             b: { status: "warn", effective_severity: 3, kind: "finding" },
                             c: { status: "pass", effective_severity: 3, kind: "finding" } } };
    const acc0 = S.state.accepted;
    S.state.accepted = { ...acc0, b: { severity: 3, when: 1, note: "" } };
    check(window.eval("jobFindings")(job) === 1, "an accepted finding isn't counted among the online tests' findings");
    job.results.b.effective_severity = 4;
    check(window.eval("jobFindings")(job) === 2, "unless its severity rose since");
    S.state.accepted = acc0;
    window.setShow("findings"); await tick();
  }
  // a problem at the last scan that this one couldn't check (no administrator access): never resolved
  S.report.changes = { previous: 1790000000, new: [], resolved: [id], changed: [{ id: id2, from: 2, to: 5 }],
                       unchecked: [{ id, status: "fail", severity: 7, checked: 1790000000 }] };
  S.report.results[id] = { ...r1, status: "unknown", is_finding: false, needs_admin: true };
  S.report.results[id2] = { ...r2, status: "unknown", is_finding: false, needs_admin: true };
  window.renderChecks(); await tick();
  check(!$$(".report .changes .chip.resolved").length
        && $$(".report .changes .chip.unchecked").map(c => c.textContent).join() === titled(id)
        && text(".report .changes").includes("1 not checked again"),
        "a problem that couldn't be checked this time isn't resolved: " + text(".report .changes"));
  check($(`#c-${id.replace(".", "\\.")} .was-problem`)?.textContent.includes("Problem, severity 7, when it was last checked"),
        "and its row says what it was when last checked");
  S.report.results[id] = r1; S.report.results[id2] = r2;
  // an inventory's new entries (what starts at login): a chip, a note in the details, a tag on the evidence line
  S.report.changes = { previous: 1790000000, new: [], resolved: [], changed: [],
                       new_items: { "tel.location": ["~/.config/autostart/x.desktop"] } };
  const ev0 = S.report.results["tel.location"].evidence;
  S.report.results["tel.location"].evidence = [...ev0, { kind: "value", label: "~/.config/autostart/x.desktop", value: "starts x" }];
  window.renderChecks(); await tick();
  check($$(".report .changes .chip.new").some(c => c.textContent.startsWith("1 new in ")),
        "new entries since the last scan are a chip: " + text(".report .changes"));
  const shown = S.show;
  window.setShow("all"); window.toggle("tel.location"); await tick();
  check(text("#c-tel\\.location .details").includes("New since the last scan (1)"), "the details name the new entries");
  check($$("#c-tel\\.location .evidence .newtag").length === 1, "and tag the evidence line");
  window.toggle("tel.location"); window.setShow(shown); await tick();
  S.report.results["tel.location"].evidence = ev0;
  delete S.report.changes;
  window.renderChecks(); await tick();
}
{ // a fix the user made, undone since: a banner above everything, and the row says so
  const S = window.eval("S");
  const id = Object.keys(results).find(k => results[k].is_finding && !fixture.state.accepted[k]);
  S.report.undone = [{ entry_id: "e1", check_id: id, title: "A fix", applied: 1790000000, undone_since: 1790500000,
                       severity: results[id].effective_severity, changed_back: ["some.schema key is true again (the fix set false)"] }];
  window.renderChecks(); await tick();
  const banner = $("#checks-list > section.undone");
  check(banner && $("#checks-list").firstElementChild === banner, "an undone fix is the first thing on the page");
  check(text("section.undone h2") === "⚠ A fix you made has been undone", "its heading says so: " + text("section.undone h2"));
  check(text("section.undone").includes("Changed back: some.schema key is true again"), "it says what was changed back");
  check($(`#c-${id.replace(".", "\\.")} .badge.undone`) !== null, "the finding's row is marked");
  delete S.report.undone;
  window.renderChecks(); await tick();
  check(!$("section.undone"), "and the banner goes once nothing is undone");
}
check(calls.includes("POST /api/scan"), "scan called the API");
check($("#show button.on").dataset.show === "findings", "after a scan, only findings are shown");
const shownIds = findingRows().map(e => e.id.slice(2));
check(shownIds.every(id => results[id]?.is_finding && !fixture.state.accepted[id]), "every row shown is an unaccepted finding");
check(!shownIds.includes("enc.partial_fde"), "the accepted finding is not among the findings");

// accepted view
window.setShow("accepted"); await tick();
check($$("#checks-list .citem").map(e => e.id.slice(2)).includes("enc.partial_fde"), "the accepted finding is under Accepted");
check(text("#c-enc\\.partial_fde .badge.accepted") === "accepted", "it carries the accepted badge");

// hygiene and info views
window.setShow("hygiene"); await tick();
check($$("#checks-list .citem").every(e => results[e.id.slice(2)]?.is_hygiene), "the Hygiene view lists hygiene items only");
check($$("#checks-list .badge.kind-hygiene").length > 0, "hygiene rows carry their kind badge");

// details: evidence, accept control, no dev-only sections
window.setShow("all"); window.toggle("tel.location"); await tick();
check(text("#c-tel\\.location .details").includes("Evidence"), "details show the evidence");
check(text("#c-tel\\.location .accept-row button") === "Accept the risk…", "a finding's details end with Accept the risk…");
check(!text("#c-tel\\.location .details").includes("Detection hints"), "detection hints are hidden outside developer mode");
check(text("#c-tel\\.location .sevcol .status") === "Problem", "the status is above the severity, on the left");
check($("#c-tel\\.location .badge.st-fail") === null, "and no longer on the right");
{ // a pass: grey number, however high, and it leads with what was found
  const passId = Object.keys(results).find(id => results[id].status === "pass" && results[id].effective_severity >= 6 && results[id].summary);
  window.reveal(passId); await tick();
  const row = `#c-${passId.replace(".", "\\.")}`;
  check($(`${row} .sev-off`) !== null && !$(row).className.match(/band-(critical|high|medium)/), "a passed check's number is grey, with no coloured edge");
  check(text(`${row} .t`) === results[passId].summary && text(`${row} .sevcol .status`) === "Pass" && text(`${row} .sub`).startsWith(window.eval("S").state.catalogue.find(c => c.id === passId).title), "a pass leads with its result, then the check's name");
}
check($("#c-tel\\.location .accept-row input") === null, "the reason field is hidden until asked for");
$("#c-tel\\.location .accept-row button").click(); await tick();
check(text("#c-tel\\.location .accept-row p").includes("no longer counted"), "opening it explains what accepting does");
$("#c-tel\\.location .accept-row input").value = "test machine";
$("#c-tel\\.location .accept-row button.primary").click(); await tick();
check(calls.includes("POST /api/accept"), "accepting calls the API");
check($("#c-tel\\.location") === null, "an accepted finding is hidden from All");
window.setShow("accepted"); await tick();
check($("#c-tel\\.location .badge.accepted") !== null, "it is listed under Accepted, marked accepted");
check(text("#c-tel\\.location .accept-row").includes("stays hidden unless its severity rises"), "the details say when it comes back");
check(text("#c-tel\\.location .accept-row").includes("test machine") && text("#c-tel\\.location .accept-row button") === "Un-accept", "the details show the reason and offer Un-accept");
check(text("#c-tel\\.location .badges .unaccept") === "Un-accept", "the row itself offers Un-accept");
check($$("#toasts .toast button").some(b => b.textContent === "Undo"), "a toast offers Undo");
$("#c-tel\\.location .badges .unaccept").click(); await tick();
check($("#c-tel\\.location") === null, "un-accepting takes it out of Accepted");
window.setShow("all"); await tick();
check($("#c-tel\\.location") !== null && $("#c-tel\\.location .badge.accepted") === null, "and shows it again, unmarked");

// accepted at a lower severity than it has now: shown again, saying why
const loc = results["tel.location"];
acceptAt = loc.effective_severity - 1;
await window.setAccepted(window.eval("S").state.catalogue.find(s => s.id === "tel.location"), true, "fine then"); await tick();
acceptAt = null;
window.setShow("findings"); await tick();
check($("#c-tel\\.location .badge.resurfaced") !== null, "a finding whose severity rose since it was accepted is shown again");
check(text("#c-tel\\.location .accept-row .warnbox").includes(`rose from ${loc.effective_severity - 1} to ${loc.effective_severity}`), "with the reason");
check(text("#c-tel\\.location .accept-row").includes(`Accept it at severity ${loc.effective_severity}`), "and an offer to accept it at the new severity");

// unknown status wording
const unknownRow = Object.keys(results).find(id => results[id].status === "unknown");
if (unknownRow) { window.reveal(unknownRow); await tick(); check($(`#c-${unknownRow.replace(".", "\\.")} .sevcol .status`)?.title === "Couldn't check", "unknown results say Couldn't check"); }

// export dialog
await window.openExport(); await tick();
check(text(".modal .export pre").startsWith("DA Privacy Kit report"), "the export dialog shows the report text");
check(calls.includes("GET /api/report"), "export fetched the report");
$$(".modal .buttons button").at(-1).click();

// export everything (from History, or picked in the dialog)
await window.openExport("everything"); await tick();
check(calls.includes("GET /api/export") && text(".modal .export pre").includes("Changes made"), "Export everything fetches /api/export");
check(text(".modal .export").includes("how to undo it by hand"), "and says what it is for");
$$(".modal .buttons button").at(-1).click();

// a guide with inputs: changing one builds the guide again with it
await window.openGuide({ id: "desk.ephemeral_folder", tier: "feature" }); await tick();
check($$(".modal .ginput input").length === 2, "the guide shows its inputs");
check(text(".modal .steps code") === "mount 500 MB", "the dry run is built with the default");
check($$(".modal .gparts dt").map(e => e.textContent).join("|") === "What it is|What it isn't"
      && text(".modal .gparts dd") === "A folder in memory.", "a step's explanation is shown in its sections");
const sizeInput = $(".modal .ginput input[type=number]");
sizeInput.value = "750";
sizeInput.dispatchEvent(new window.Event("change")); await tick(); await tick();
check(planBodies.at(-1)?.params?.size_mb === 750, "a changed input is sent with the next plan request");
check(text(".modal .steps code") === "mount 750 MB", "and the dry run shown follows it");
$$(".modal .buttons button").at(-1).click();

// applying a step shows what it did at once; the guide is built again behind it, and a slow answer says why
// (OpenSnitch, restarted by its own steps, holds the window's next connection to the app with a question)
{ const plain = routes["POST /api/fix/desk.ephemeral_folder/plan"];
  await window.openGuide({ id: "desk.ephemeral_folder", tier: "feature" }); await tick();
  let release;
  routes["POST /api/fix/desk.ephemeral_folder/plan"] = (body) => new Promise(r => { release = () => r(plain(body)); });
  routes["POST /api/fix/apply"] = () => ({ ok: true, entry: { id: "u1", check_id: "desk.ephemeral_folder", title: "Set it up",
    applied: 1790000000, state: "applied", can_revert: true, needs_root: true, via_text: "", steps: [] } });
  $(".modal .gactions button").click(); await tick(); await tick();
  check($$(".modal").at(-1).querySelector("h2")?.textContent === "Done: Set it up", "what the step did is shown before the guide is built again");
  check(text(".modal .gactions button") === "Applied" && text(".modal .gactions div").includes("Updating the guide"),
        "the step says it was applied and that the guide is being updated");
  await new Promise(r => setTimeout(r, 4100));
  check(text(".modal .gactions div").includes("127.0.0.1"), "a slow update says a firewall may be asking about the app's own connection");
  release(); await tick(); await tick();
  check(!text(".modal .gactions div").includes("Updating"), "and the guide is shown again once it answers");
  routes["POST /api/fix/desk.ephemeral_folder/plan"] = plain;
  delete routes["POST /api/fix/apply"];
  while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); } }

// History offers to remove an installed helper, after confirming
window.eval("S").state.helper_installed = true;
await window.openHistory(); await tick();
check(text(".modal .helperrow").includes("installed root-owned"), "History says the helper is installed");
$(".modal .helperrow button").click(); await tick();
check(text(".modal:last-of-type").includes("can still be reverted from History") || $$(".modal").some(m => m.textContent.includes("can still be reverted from History")),
      "removing it asks first, saying the changes stay revertible");
$$(".modal button").find(b => b.textContent === "Remove it").click(); await tick(); await tick();
check(helperBodies.at(-1)?.uninstall === true, "and then asks the server to remove it");
check(!$(".modal .helperrow") && !window.eval("S").state.helper_installed, "the row goes once it is removed");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
window.eval("S").state.helper_installed = false;
await window.openHistory(); await tick();
check(!$(".modal .helperrow"), "no row when the helper isn't installed");
$$(".modal .buttons button").at(-1).click(); await tick();

// History shows exactly what each step did: the commands it ran, the files and lines it wrote, how to undo it
routes["GET /api/undo"] = () => ({ entries: [{ id: "e1", check_id: "net.dns_unencrypted", title: "DNS over TLS",
  applied: 1790000000, state: "applied", undone_since: null, can_revert: true, needs_root: true, steps: [
    { text: "Write /etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf with DNSOverTLS=yes", reversible: true,
      reverted: false, as_root: true, commands: ["systemctl try-restart systemd-resolved.service"],
      files: ["/etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf"], lines: [], undo: "Revert it in the app", revert_ran: [] },
    { text: "~/.config/environment.d/telemetry.conf (Add DOTNET_CLI_TELEMETRY_OPTOUT=1)", reversible: true, reverted: false,
      as_root: false, commands: [], files: [], lines: ["+ DOTNET_CLI_TELEMETRY_OPTOUT=1"], undo: "rm /home/a/x.conf", revert_ran: [] },
    { text: "Deleted 3 files of thumbnails in ~/.cache/thumbnails", reversible: false, reverted: false, as_root: false,
      commands: [], files: [], lines: [], undo: "", revert_ran: [] }],
  via_text: "From the guide “Encrypted DNS”, step 2 (Turn it on), the option “DNS over TLS”" },
  { id: "e0", check_id: "tel.location", title: "Turn off location services", applied: 1789000000, state: "failed",
    undone_since: null, can_revert: false, needs_root: false, via_text: "Applied as an Easy fix",
    error: "gsettings get org.gnome.system.location enabled failed: no dconf",
    failed_step: "gsettings set org.gnome.system.location enabled false", steps: [
      { text: "Add B (~/env.conf)", reversible: true, reverted: true, as_root: false, commands: [], files: [], lines: ["+ B=2"],
        undo: "", revert_ran: ["cp /home/a/.local/state/daprivacyscanner/backups/e0/x-env.conf /home/a/env.conf"] }] }] });
await window.openHistory(); await tick();
const details = $$(".modal .history details.stepdetail");
check(details.length === 3, "each step that did something exact has its details, a deletion none: " + details.length);
{ const entries = $$(".modal .history .entry");
  check(entries[0].textContent.includes("From the guide “Encrypted DNS”, step 2 (Turn it on), the option “DNS over TLS”"),
        "an entry says where the change came from");
  check(entries[1].textContent.includes("Failed: gsettings get org.gnome.system.location enabled failed: no dconf (at: gsettings set")
        && entries[1].textContent.includes("The steps that had run were put back")
        && entries[1].querySelector(".badge.state-failed") && entries[1].querySelector(".step.reverted")
        && details[2].textContent.includes("Putting it back did:") && details[2].textContent.includes("cp /home/a/"),
        "a failed attempt says what failed, and shows what was put back: " + entries[1].textContent.slice(0, 200)); }
check(details[0].textContent.includes("Ran, as root:") && details[0].textContent.includes("systemctl try-restart systemd-resolved.service")
      && details[0].textContent.includes("Files written, as root:") && details[0].textContent.includes("60-daprivacyscanner-dot.conf"),
      "a root step names the commands the helper ran and the files it wrote");
check(details[1].querySelector("pre.changed .add")?.textContent.includes("DOTNET_CLI_TELEMETRY_OPTOUT=1")
      && details[1].textContent.includes("To undo it by hand:") && details[1].textContent.includes("rm /home/a/x.conf"),
      "a file step shows the lines it wrote and how to undo it by hand");
check(details[0].querySelectorAll(".cmd button").length >= 1, "the commands can be copied");
$$(".modal .buttons button").at(-1).click(); await tick();
routes["GET /api/undo"] = () => ({ entries: [] });

// a plan's step names what a root change runs after it, and the lines it writes
{ const li = window.stepLine({ text: "Write /etc/x.conf", reversible: true, irreversible: false, needs_root: true,
    commands: ["systemctl try-reload-or-restart NetworkManager.service"], lines: ["+ [connectivity]", "+ enabled=false"] });
  check(li.textContent.includes("Also runs, as root:") && li.textContent.includes("NetworkManager.service")
        && li.querySelectorAll("pre.changed .add").length === 2, "a plan step shows the commands and lines: " + li.textContent); }

// reads dialog
window.openReads(); await tick();
check($$(".modal .reads .read").length === fixture.state.reads.length, "the reads panel lists every item");
$$(".modal .buttons button").at(-1).click();

// context pane and helper note
check($$("#context-list .ctx").length === fixture.state.context_keys.length, "the context pane shows every key");
check(!$("#helper-note").classList.contains("hidden") === !fixture.state.helper_installed, "the helper note matches the state");

// ------------------------------------------------------------------ the Tools panel
window.setShow("all"); await tick();
check($("#c-desk\\.file_manager_actions") === null, "set-ups (features) aren't listed among the checks");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
$("#tools-btn").click(); await tick(); await tick();
check($$(".modal .toolcard").length === TOOL_COUNT, "the Tools panel shows every tool");
check($$(".modal .toolgroup h4").map(e => e.textContent).join("|") === "Your files|Private browsing and memory|Apps|Disks and drives|Everyday",
      "in four groups, each with its heading");
check($$(".modal .toolgroup .toolcard").every(c => c.querySelector(".toolicon svg path, .toolicon svg circle, .toolicon svg rect"))
      && new Set($$(".modal .toolgroup .toolicon svg").map(s => s.innerHTML)).size === TOOL_COUNT,
      "every tile has an icon of its own");
check($$(".modal .toolgroup .toolcard").every(c => c.querySelector("details.toolmore summary")?.textContent === "More about it"),
      "each tile gives a one-line summary, the full text behind More about it");
check($(".modal .group-drives .toolgrid").classList.contains("cols-2") && $(".modal .group-everyday .toolgrid").classList.contains("cols-3"),
      "four tiles go in rows of two, three in one row");
check(!$$(".modal .toolstate").length, "nothing open or missing: no tile shows a state");
{ const r = routes["GET /api/tools"];
  routes["GET /api/tools"] = () => ({ ...r(), browser_disk: true, verify: { gpgv: false, sqv: false, install: "sudo apt install gpgv" },
    metadata: { mat2: { installed: false, install: "sudo apt install mat2" }, exiftool: { installed: true, install: "x" } },
    ramdisk: { ...ramdisk(), open: true, size: "512m" } });
  while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
  await window.openTools(); await tick(); await tick();
  const state = (id) => $(`.modal #tool-${id} .toolstate`);
  check(state("verify")?.textContent === "Needs gpgv" && state("verify").title.includes("sudo apt install gpgv"),
        "a tool missing its program says so on its tile, with the command as its tooltip");
  check(state("metadata")?.textContent === "Needs mat2 to clean", "Remove metadata says it can show but not clean without mat2");
  check(state("ramdisk")?.textContent === "Open · 512m" && state("browser")?.textContent === "~/TempBrowser open",
        "the RAM disks say when they are open");
  routes["GET /api/tools"] = r;
  while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
  $("#tools-btn").click(); await tick(); await tick(); }
check(text(".modal .feature").includes("Not set up in Nemo.") && $(".modal .feature button")?.textContent === "Set up…",
      "and each set-up with its state from the scan and a Set up… button");
check(text(".modal .feature .notebox.risk").includes("Allow mode") && !text(".modal .feature").includes("Nobody is asked"),
      "a set-up's risks stay in view with it; its other notes don't");

// Verify a download: a recent download runs it, and the verdict says who made it
$$(".modal .toolcard button").find(b => b.textContent === "Verify a file…").click(); await tick(); await tick();
$$(".modal .recent button").at(0).click(); await tick(); await tick();
check(toolBodies.verify?.path === "/home/a/Downloads/linuxmint-22.3-cinnamon-64bit.iso" && toolBodies.verify.use_keyring === true,
      "choosing a recent download verifies it");
check(text(".modal .verdict.ok .vtitle") === "Verified: made by Linux Mint", "the verdict is shown, marked verified");
check(text(".modal .verdict .fpr").includes("27DE B156"), "with the signer's fingerprint grouped for comparing");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// Remove metadata: what a file carries, then a clean copy beside it
const waitMeta = async () => { for (let i = 0; i < 40 && metaJob?.state === "running"; i++) await new Promise(r => setTimeout(r, 100));
  await tick(); await tick(); };
await window.openMetadata(null, ["/home/a/photo.jpg"]); await tick(); await waitMeta();
check(toolBodies.read?.paths?.[0] === "/home/a/photo.jpg" && toolBodies.read.hidden === false, "files given (--tool metadata) are read at once");
check(toolBodies.show?.paths?.[0] === "/home/a/photo.jpg" && $(".modal .metagroup.warn h4")?.textContent === "Where it was made",
      "one file is shown whole, location highlighted");
check($$(".modal .meta-filters").length === 0, "a single file needs no filters");
$$(".modal button").find(b => b.textContent === "Make clean copies of 1 ticked file").click(); await tick(); await waitMeta();
check(toolBodies.clean.files?.[0] === "/home/a/photo.jpg" && toolBodies.clean.lightweight === false, "the ticked file is cleaned");
check(text(".modal .meta-slot").includes("photo.cleaned.jpg") && text(".modal .meta-slot").includes("couldn't be cleaned"),
      "the result names the copy, and what couldn't be cleaned");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// a folder too: several files, filtered, ticked, in a list
await window.openMetadata(null, []); await tick(); await tick();
check($$(".modal .meta-item code").map(c => c.textContent).join() === "/home/a/photo.jpg", "opened again, it shows the last run's files");
$$(".modal button").find(b => b.textContent === "Add a folder…").click(); await tick(); await tick();
check($$(".modal .meta-item code").length === 2, "a folder is added beside the file, not run into its name");
$$(".modal button").find(b => b.textContent === "Show what they carry").click(); await tick(); await waitMeta();
check(JSON.stringify(toolBodies.read.paths) === JSON.stringify(["/home/a/photo.jpg", "/home/a/Documents"]), "both are read, as a list");
check($$(".modal .meta-list .meta-row").length === 4 && text(".modal .meta-slot").includes("in ~/Documents, subfolders included")
      && text(".modal .meta-slot").includes("Left out: 2 hidden"), "every file is listed, with what was left out");
check($$(".modal .meta-row input[type=checkbox]").at(-1).disabled, "a file mat2 can't clean can't be ticked");
$$(".modal .meta-filters .chip").find(b => b.textContent.startsWith("Where it was made")).click(); await tick();
check($$(".modal .meta-list .meta-row").length === 1, "filters narrow the list");
$$(".modal button").find(b => b.textContent === "Untick these").click(); await tick();
check($$(".modal button").some(b => b.textContent === "Make clean copies of 2 ticked files"), "ticks follow");
$$(".modal .meta-filters .chip")[0].click(); await tick();
$(".modal .meta-list details").open = true; await tick(); await tick();
check(text(".modal .meta-detail").includes("47 N") || text(".modal .meta-detail").includes("Pixel 8"), "a row opens on what it carries");
$$(".modal button").find(b => b.textContent === "Make clean copies of 2 ticked files").click(); await tick(); await waitMeta();
check(JSON.stringify(toolBodies.clean.files.sort()) === JSON.stringify(["/home/a/Documents/Trip/b.jpg", "/home/a/Documents/a.jpg"]),
      "only the ticked files are cleaned");
check(text(".modal .meta-slot").includes("~/Documents (cleaned)"), "the cleaned folder is named");
$$(".modal .meta-slot button").find(b => b.textContent === "Open the folder").click(); await tick();
check(toolBodies.metaOpen?.folder === "/home/a/Documents (cleaned)", "and can be opened");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// the RAM disk: opened with the chosen size, closed after a confirmation
await window.openTools(); await tick(); await tick();
const sizeBox = $(".modal .ramdisk input[type=number]");
check(text(".modal .ramdisk").includes("Opening runs, as root:") && text(".modal .ramdisk").includes("size=1024M"),
      "before opening it, the panel shows the commands opening runs");
sizeBox.value = "512";
sizeBox.dispatchEvent(new window.Event("input"));
check(text(".modal .ramdisk").includes("nosuid,nodev,noexec,size=512M"), "they follow the size chosen");
$(".modal .ramdisk input[type=checkbox]").click();
check(text(".modal .ramdisk").includes("nosuid,nodev,size=512M"), "and the programs box");
$(".modal .ramdisk input[type=checkbox]").click();
$$(".modal .ramdisk button").find(b => b.textContent === "Open").click(); await tick(); await tick(); await tick();
check(toolBodies.open?.size_mb === 512 && toolBodies.open.noexec === true, "opening sends the size and noexec");
check($$(".modal .ramdisk button").some(b => b.textContent === "Close and overwrite…"), "once open, it offers to close and overwrite");
$$(".modal .ramdisk button").find(b => b.textContent === "Close and overwrite…").click(); await tick();
check($$(".modal").some(m => m.textContent.includes("What this doesn't reach")), "closing first says what it doesn't reach");
check($$(".modal").some(m => m.textContent.includes("closing runs, as root:") && m.textContent.includes("umount /home/a/RAMDisk")),
      "and the command closing runs");
$$(".modal button").find(b => b.textContent === "Close and overwrite").click(); await tick(); await tick(); await tick();
check($$("#toasts .toast").some(t => t.textContent.includes("2 files (2 kB) overwritten and deleted")), "and then says what was overwritten");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// Tor or Mullvad Browser in the RAM disk: an executable RAM disk first, the hosts named before downloading
const clipSaved = window.eval("S").report.results["desk.clipboard_history"];
window.eval("S").report.results["desk.clipboard_history"] = { ...(clipSaved || {}), id: "desk.clipboard_history",
  status: "fail", summary: "Clipboard history is saved to disk by Klipper.", fixable: true, effective_severity: 3 };
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("open the browser's RAM disk, ~/TempBrowser"), "it asks for its own RAM disk first");
check(text(".modal .browser-tool").includes("separate from the RAM disk tool's ~/RAMDisk")
      && text(".modal .browser-tool").includes("Quitting the browser doesn't close ~/TempBrowser"),
      "it says the browser's RAM disk is its own, and when it closes");
check($$(".modal .browser-tool .toolcard button").every(b => b.disabled), "nothing can be downloaded before that");
$$(".modal .browser-tool button").find(b => b.textContent === "Open the RAM disk").click(); await tick(); await tick(); await tick();
check(toolBodies.open?.noexec === false && toolBodies.open.size_mb === 1536 && toolBodies.open.disk === "browser",
      "it opens its own RAM disk, executable: " + JSON.stringify(toolBodies.open));
$$(".modal .browser-tool .toolcard button").find(b => b.textContent === "Download…").click(); await tick();
check($$(".modal").at(-1).textContent.includes("aus1.torproject.org and dist.torproject.org"), "the hosts are named before downloading");
$$(".modal").at(-1).querySelectorAll(".buttons button")[1].click(); await tick(); await tick(); await tick();
check(toolBodies.browser?.browser === "tor" && text(".modal .browser-tool").includes("50.0 MB of 100.0 MB"), "the download shows its progress");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
// Mullvad Browser's card offers to set it up for Mullvad VPN, on by default; the choice goes with the download
browserJob = null;
await window.openBrowserTool(); await tick(); await tick();
{ const card = $$(".modal .browser-tool .toolcard").find(c => c.textContent.includes("Mullvad Browser"));
  const box = card.querySelector(".vpnsetup input");
  check(box?.checked && card.textContent.includes("no page loads until you turn the proxy off in the extension"),
        "Mullvad Browser's card offers the Mullvad VPN set-up, ticked, saying what it costs without the VPN");
  check(!$$(".modal .browser-tool .toolcard").find(c => c.textContent.includes("Tor Browser")).querySelector(".vpnsetup"),
        "Tor Browser's card doesn't");
  box.checked = false; box.dispatchEvent(new window.Event("change"));
  [...card.querySelectorAll("button")].find(b => b.textContent === "Download…").click(); await tick();
  check($$(".modal").at(-1).textContent.includes("It isn't set up for Mullvad VPN"), "the download dialog says what was chosen");
  $$(".modal").at(-1).querySelectorAll(".buttons button")[1].click(); await tick(); await tick();
  check(toolBodies.browser?.browser === "mullvad" && toolBodies.browser.vpn === false, "and the choice is sent with it: "
        + JSON.stringify(toolBodies.browser));
  window.eval("browserSetup").vpn = true;
  const note = window.mullvadVpnNote({ set: true, city: "Zurich", server: "ch-zrh-wg-001" }).textContent;
  check(note.includes("needs it connected") && note.includes("Zurich (ch-zrh-wg-001)") && note.includes("turn its proxy off")
        && note.includes("DNS over HTTPS"), "a copy set up for it says so, and how to undo each part");
  check(window.mullvadVpnNote({ set: false, why: "Made for 15." }).textContent.includes("Not set up for Mullvad VPN: Made for 15."),
        "one that couldn't be says why"); }
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
browserJob = { state: "done", name: "Tor Browser", version: "15.0.24", stopping: false,
               verdict: { title: "Verified: made by Tor Browser Developers", signer: "Tor Browser Developers",
                          fingerprint: "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290" } };
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("EF6E 286D DA85"), "a finished job names the key that signed it");
check(text(".modal .browser-tool").includes("It is for one session, or a few over a day")
      && text(".modal .browser-tool").includes("more than 24 hours after setting it up")
      && text(".modal .browser-tool").includes("It never updates itself"),
      "how it is meant to be used is said up front, the update check after a day included");
check(text(".modal .browser-tool").includes("Version 15.0.24, set up") && text(".modal .browser-tool").includes("starting it first checks for a newer version"),
      "the card says when it was set up, and from when a start checks for a newer version");
check(text(".modal .browser-tool .browser-files").includes("open them in your file manager like any other"),
      "it says the two folders can be used like any other, from the file manager");
check(text(".modal .browser-tool").includes("It runs in a sandbox") && text(".modal .browser-tool").includes("This is an X11 session")
      && $$(".modal .browser-tool button").some(b => b.textContent === "How to use Wayland…"),
      "it says the browser runs in a sandbox, and that X11 doesn't keep programs apart");
check(text(".modal .browser-tool").includes("It starts at the Safest security level, set by the app")
      && text(".modal .browser-tool").includes("It starts at the Standard security level"),
      "each card says the security level it starts at, and that the app set Tor Browser's");
check($$(".modal .browser-tool label").some(l => l.textContent.includes("Give it a display of its own (Xephyr)"))
      && text(".modal .browser-tool").includes("copy and paste between it and your other windows doesn't work")
      && text(".modal .browser-tool").includes("Not the other way round: that window is still a window of this X11 session"),
      "on X11 it offers a display of its own, with what that costs, and what it doesn't protect: the browser from other programs");
check(text(".modal .browser-tool").includes("Tor Browser has no network of its own")
      && text(".modal .browser-tool .notebox.danger").includes("Install passt before you use Mullvad Browser here")
      && text(".modal .browser-tool .notebox.danger").includes("hardware (MAC) addresses")
      && text(".modal .browser-tool .notebox.danger").includes("sudo apt install passt"),
      "it says what each browser's network is, and, prominently, why and how to give Mullvad Browser its own");
check(text(".modal .browser-tool").includes("This kernel doesn't have Landlock's scopes")
      && $$(".modal .browser-tool button").some(b => b.textContent === "How to get a kernel with it…"),
      "without Landlock it says so, with the way to a kernel that has it");
check(text(".modal .browser-tool").includes("Mullvad VPN") && text(".modal .browser-tool").includes("A trustworthy VPN underneath"),
      "it says what a VPN adds to each browser");
const bridgeSelect = $(".modal .browser-tool .toolcard select");
check(bridgeSelect && [...bridgeSelect.options].map(o => o.value).join() === "none,obfs4,snowflake,meek,custom",
      "Tor Browser's bridges are chosen in the panel");
bridgeSelect.value = "custom"; bridgeSelect.dispatchEvent(new window.Event("change"));
$(".modal .browser-tool .toolcard textarea").value = "obfs4 192.0.2.1:443 AB cert=x iat-mode=0";
$$(".modal .browser-tool .toolcard button").find(b => b.textContent === "Save").click(); await tick(); await tick();
check(toolBodies.bridges?.mode === "custom" && toolBodies.bridges.lines.startsWith("obfs4 192.0.2.1"),
      "bridges pasted are sent: " + JSON.stringify(toolBodies.bridges));
check(text(".modal .browser-tool .browser-files").includes("Its name goes with it"), "it says a file's name is uploaded too");
check(text(".modal .browser-tool .browser-files").includes("Choosing a file with zenity")
      && text(".modal .browser-tool .browser-files").includes("adds it to your desktop's recent files list")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Stop keeping recent files…"),
      "the file chooser outside the window says it records the file in the recent files list (tested)");
check(text(".modal .browser-tool").includes("Before you start: swap reaches the disk here")
      && text(".modal .browser-tool").includes("sudo swapoff /dev/sda3") && text(".modal .browser-tool").includes("sudo swapon /dev/sda3")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Make swap safe for good…"),
      "swap on the disk is named first, with the commands its buttons run and the lasting fix");
check(text(".modal .browser-tool").includes("Without swap, when memory runs out the system ends a program")
      && $$(".modal .browser-tool .warnbox").some(w => w.textContent.includes("That is more than is free now")),
      "turning swap off says what it costs, and warns when the browser and its RAM disk won't fit in what is free");
check(text(".modal .browser-tool").includes("Unless you allow it below, it has no graphics card: pages draw with the processor"),
      "the sandbox says what it doesn't hide, and that pages draw without the graphics card");
check(text(".modal .browser-tool").includes("this computer can hibernate")
      && text(".modal .browser-tool").includes("though it is kept out of swap")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Hibernation…"),
      "the panel says hibernation writes the browser's memory and ~/TempBrowser to the disk, with its guide");
check(text(".modal .browser-tool").includes("OpenSnitch keeps a record on the disk")
      && text(".modal .browser-tool").includes("at log level 2") && text(".modal .browser-tool").includes("/home/a/opensnitch.sqlite"),
      "and that OpenSnitch's log and connection list record the browser's sites");
check(text(".modal .browser-tool .browser-files").includes("use View offline… for that"),
      "and that opening a download from the file manager keeps it in recent files: View offline… instead");
check(text(".modal .browser-tool").includes("this computer keeps crash dumps on the disk")
      && text(".modal .browser-tool").includes("echo 0 > /proc/self/coredump_filter")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Stop keeping crash dumps…"),
      "crash dumps kept on the disk are named, with what the start does and the way to stop them");
check(text(".modal .browser-tool").includes("clipboard history is saved to the disk")
      && text(".modal .browser-tool").includes("saved to disk by Klipper"),
      "a clipboard history kept on the disk (as of the last scan) is named, with its fix");
window.eval("S").report.results["desk.clipboard_history"] = clipSaved;
check(text(".modal .browser-tool").includes("Before you start: file search is on here (KDE's file search (Baloo))")
      && text(".modal .browser-tool").includes("Baloo indexes ~/TempBrowser too")
      && text(".modal .browser-tool").includes("Baloo can't be trusted to forget")
      && $$(".modal .browser-tool button").some(b => b.textContent === "File search…"),
      "file search is named, with what it would keep of the browser's files, and that Baloo isn't trusted to forget");
routes["POST /api/fix/desk.indexers/plan"] = () => ({ guide: { check_id: "desk.indexers", title: "File search", intro: "", steps: [
  { title: "Baloo", text: "", commands: [], side_effects: [], done: false, inputs: [], options: [
    { label: "Turn indexing off and delete the index", detail: "", recommended: true, key: "baloo_off", dry_run: "",
      plan: { id: "off", check_id: "desk.indexers", title: "off", blockers: [], side_effects: [], needs_root: false, irreversible_files: 0,
              steps: [{ kind: "kconfig", text: "kwriteconfig6 --file baloofilerc --group Basic Settings --key Indexing-Enabled --notify false",
                        reversible: true, irreversible: false, needs_root: false }] } }] }] }, dry_run: "" });
routes["POST /api/fix/apply"] = (body) => { toolBodies.applied = body; toolBodies.baloo_off = true; return { ok: true,
  entry: { id: "u9", check_id: "desk.indexers", title: "Turn indexing off and delete the index", applied: 1790000000, state: "applied",
    can_revert: true, needs_root: false, via_text: "From the guide “File search”, step 1 (Baloo)", steps: [
      { text: "baloofilerc [Basic Settings] Indexing-Enabled: (default) → false", reversible: true, reverted: false, as_root: false,
        commands: ["kwriteconfig6 --file baloofilerc --group 'Basic Settings' --key Indexing-Enabled --notify false"],
        files: [], lines: [], undo: "kwriteconfig6 --file baloofilerc --group 'Basic Settings' --key Indexing-Enabled --notify --delete",
        revert_ran: [] }] } }; };
$$(".modal .browser-tool button").find(b => b.textContent === "Turn Baloo off and delete its index…").click(); await tick(); await tick();
check($$(".modal").at(-1).textContent.includes("Indexing-Enabled --notify false"), "turning Baloo off shows its dry run first");
$$(".modal").at(-1).querySelectorAll(".buttons button")[1].click(); await tick(); await tick(); await tick();
check(toolBodies.applied?.plan_id === "off" && !text(".modal .browser-tool").includes("file search is on here"),
      "then applies just that option, and the panel's box goes: " + JSON.stringify(toolBodies.applied));
{ const done = $$(".modal").at(-1);
  check(done.querySelector("h2")?.textContent === "Done: Turn indexing off and delete the index"
        && done.textContent.includes("From the guide “File search”, step 1 (Baloo)")
        && done.querySelector("details.stepdetail")?.open
        && done.textContent.includes("kwriteconfig6 --file baloofilerc --group 'Basic Settings' --key Indexing-Enabled --notify false")
        && done.textContent.includes("To undo it by hand:")
        && [...done.querySelectorAll(".buttons button")].some(b => b.textContent === "Open History"),
        "then says exactly what it did, the commands open, with the way to History: " + done.textContent.slice(0, 120));
  [...done.querySelectorAll(".buttons button")].at(-1).click(); await tick(); }
{
  const soundBox = $$(".modal .browser-tool label").find(l => l.textContent.includes("Allow sound"))?.querySelector("input");
  const note = () => $(".modal .browser-tool .sound-risks");
  check(soundBox && note()?.hidden, "the sound risks are shown once sound is ticked");
  soundBox.checked = true; soundBox.dispatchEvent(new window.Event("change"));
  check(!note().hidden && note().textContent.includes("reveals your real address")
        && note().textContent.includes("your user name and this computer's name"), "ticking sound shows what it gives away");
  soundBox.checked = false; soundBox.dispatchEvent(new window.Event("change"));
  const gpuBox = $$(".modal .browser-tool label").find(l => l.textContent.includes("Allow the graphics card"))?.querySelector("input");
  const gpuNote = () => $(".modal .browser-tool .gpu-risks");
  check(gpuBox && !gpuBox.checked && !gpuBox.disabled && gpuNote()?.hidden, "the graphics card is off until ticked");
  gpuBox.checked = true; gpuBox.dispatchEvent(new window.Event("change"));
  check(!gpuNote().hidden && gpuNote().textContent.includes("get out of the sandbox"), "ticking it says what it costs");
  gpuBox.checked = false; gpuBox.dispatchEvent(new window.Event("change"));
}
check(text(".modal .browser-tool").includes("thumbnails are kept on the disk (~/.cache/thumbnails)")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Keep thumbnails in memory…"),
      "thumbnails on the disk are named, with the way to keep them in memory");
$$(".modal .browser-tool button").find(b => b.textContent === "Turn swap off for this session").click(); await tick(); await tick(); await tick();
check(toolBodies.swap?.off === true && text(".modal .browser-tool").includes("Swap is off for this session")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Turn swap back on"),
      "Turn swap off… turns it off, then offers to turn it back on: " + JSON.stringify(toolBodies.swap));
delete toolBodies.swap;
check(text(".modal .browser-tool").includes("Outbox: ~/TempBrowser/Outbox for Tor Browser")
      && text(".modal .browser-tool").includes("IMG_1.jpg → To upload") && text(".modal .browser-tool").includes("In Not cleaned: notes.xyz")
      && text(".modal .browser-tool").includes("1 file waiting"), "the TempOutbox shows what it did and what waits");
$$(".modal .browser-tool button").find(b => b.textContent === "Turn it off").click(); await tick(); await tick();
check(toolBodies.outbox?.on === false && $$(".modal .browser-tool button").some(b => b.textContent === "Turn on the Outbox for Tor Browser"),
      "it can be turned off, and on again");
$$(".modal .browser-tool button").find(b => b.textContent === "Turn on the Outbox for Tor Browser").click(); await tick(); await tick();
check(toolBodies.outbox?.on === true, "turned on again");
outboxOn = false; outboxPermanent = true;
$$(".modal .browser-tool button").find(b => b.textContent === "Refresh").click(); await tick(); await tick();
check(text(".modal .browser-tool").includes("You have the Outbox set up (~/Outbox)")
      && $$(".modal .browser-tool button").some(b => b.textContent === "Open ~/Outbox/Cleaned"),
      "with the permanent Outbox set up, the panel says to use that one");
outboxOn = true; outboxPermanent = false;
$$(".modal .browser-tool button").find(b => b.textContent === "Add a file to upload…").click(); await tick(); await tick(); await tick();
check(toolBodies.upload?.browser === "tor" && toolBodies.upload.clean === true && toolBodies.upload.paths[0] === "/home/a/Downloads/photo.jpg",
      "a file to upload is copied in, its metadata removed: " + JSON.stringify(toolBodies.upload));
check(text(".modal .browser-tool .browser-files").includes("a Linux program")
      && $$(".modal .browser-tool .browser-files button").filter(b => b.textContent === "View offline…").length === 1,
      "a program named like a picture is named for what it is, and only the document can be viewed offline");
$$(".modal .browser-tool .browser-files button").find(b => b.textContent === "View offline…").click(); await tick(); await tick(); await tick();
check($$(".modal").at(-1).textContent.includes("Document Viewer") && $$(".modal").at(-1).textContent.includes("/usr/bin/xreader /home/user/report.pdf")
      && $$(".modal").at(-1).textContent.includes("with no network"),
      "View offline… names the viewer and the command before opening");
$$(".modal").at(-1).querySelectorAll(".buttons button")[1].click(); await tick(); await tick(); await tick();
check(toolBodies.view?.length === 2 && toolBodies.view[1].open === true && toolBodies.view[1].name === "report.pdf",
      "then it opens it: " + JSON.stringify(toolBodies.view));
$$(".modal .browser-tool .browser-files button").find(b => b.textContent === "Save…").click(); await tick();
check($$(".modal").at(-1).textContent.includes("can fetch things from the internet"), "a risky download is named before it is saved");
$$(".modal").at(-1).querySelectorAll(".buttons button")[1].click(); await tick(); await tick(); await tick();
check(toolBodies.save?.name === "report.pdf" && toolBodies.save.folder === "/home/a/Documents", "then it is saved where the user chose: " + JSON.stringify(toolBodies.save));
$$(".modal .browser-tool button").find(b => b.textContent === "Start Tor Browser").click(); await tick(); await tick(); await tick();
check(browserStarted === "tor" && $$(".modal .browser-tool .badge").some(b => b.textContent === "running"), "Start runs it, then it shows as running");
check(toolBodies.start?.sandbox === true && toolBodies.start.sound === false && toolBodies.start.nested === false
      && toolBodies.start.gpu === false,
      "in the sandbox, without sound, a display of its own or the graphics card unless asked: " + JSON.stringify(toolBodies.start));
check(text(".modal .browser-tool").includes("Tor connecting 45%"), "while it runs, the panel shows how far Tor has got");
torProgress = 100; await new Promise(r => setTimeout(r, 2300));
check(text(".modal .browser-tool").includes("Tor connected"), "and follows it: Tor connected, without reopening the panel");
browserStarted = null; await new Promise(r => setTimeout(r, 2300));
check($$(".modal .browser-tool button").some(b => b.textContent === "Start Tor Browser") && !text(".modal .browser-tool").includes("Tor connected"),
      "once the browser has ended, it can be started again");
torProgress = 45; browserStarted = "tor";
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
browserDue = true; browserStarted = null; delete toolBodies.start;
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("Set up more than a day ago: starting it first asks aus1.torproject.org"),
      "a copy set up more than a day ago says its next start checks for a newer version");
check(!text(".modal .browser-tool").includes("couldn't be checked"), "a copy checked against the index says nothing of it");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
browserUnchecked = true;
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("Whether this is the latest version couldn't be checked: aus1.torproject.org couldn't be reached")
      && text(".modal .browser-tool").includes("2 days before it was set up"),
      "one accepted where the index was blocked says so, and how recent its signature was");
browserUnchecked = false;
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
sandboxDown = true;
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("Keeping it sandboxed on Ubuntu")
      && text(".modal .browser-tool").includes("profile bwrap /usr/bin/bwrap flags=(unconfined)")
      && text(".modal .browser-tool").includes("sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0")
      && !text(".modal .browser-tool").includes("Installing bubblewrap"),
      "where AppArmor stops the sandbox, the ways round it are given, each with its cost, before unticking it");
sandboxDown = false;
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
kdeWayland = true;
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("This desktop still offers the sandboxed browser more than its own windows")
      && text(".modal .browser-tool").includes("read and change the clipboard in the background")
      && text(".modal .browser-tool").includes("Don't copy passwords"),
      "where the desktop still offers a marked connection the clipboard (KDE), the panel says so, from the desktop's answer");
kdeWayland = false;
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
kdeWayland = true; waylandUnasked = true;
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal .browser-tool").includes("couldn't be asked") && text(".modal .browser-tool").includes("isn't known")
      && !text(".modal .browser-tool").includes("marks the browser's connection as a sandbox's: it gets only its own windows"),
      "a compositor that couldn't be asked is said to be unknown, never taken for one that keeps the browser to its windows");
kdeWayland = false; waylandUnasked = false;
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
await window.openBrowserTool(); await tick(); await tick();
$$(".modal .browser-tool button").find(b => b.textContent === "Start Tor Browser").click(); await tick();
check($$(".modal").at(-1).textContent.includes("asks aus1.torproject.org which version is the latest") && !toolBodies.start,
      "starting it names the host before anything is asked");
$$(".modal").at(-1).querySelectorAll(".buttons button")[1].click(); await tick(); await tick(); await tick();
check(toolBodies.start?.browser === "tor", "then it starts (the check is the server's)");
check(toolBodies.start?.expect?.network === "tor" && toolBodies.start.expect.lan_blocked === true
      && toolBodies.start.expect.wayland_context === false,
      "the start carries what the panel showed of the sandbox, for the server to hold it to");
browserDue = false;
browserStartError = "Tor Browser stopped with an error: tor didn't start: [err] no route";
browserStarted = null;
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
await window.openBrowserTool(); await tick(); await tick();
check(text(".modal").includes("tor didn't start: [err] no route"), "a start that failed later says why");
browserStartError = null;
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
ramOpen = false; browserJob = null; browserStarted = null; delete toolBodies.open;

// the TRIM test: what it does and costs before it starts, then its progress, then the result to copy
await window.openTrim(); await tick(); await tick();
check(text(".modal .trim").includes("What a pass means") && text(".modal .trim").includes("roughly 10–35 minutes per pass"),
      "before starting, it says what a pass means and how long it takes");
check($$(".modal .trim-target input")[1].disabled && text(".modal .trim").includes("/home is xfs"),
      "a filesystem it can't test is shown, and why");
$$(".modal .trim button").find(b => b.textContent === "Start the test").click(); await tick(); await tick(); await tick();
check(toolBodies.trim?.mount === "/" && text(".modal .trim-step.running").includes("25% of 1.0 TB"), "starting shows its progress");
check(text(".modal .trim-step.running").includes("about 3 min left"), "with the time left in the pass, from its own pace");
check($$(".modal .trim-step").length === 8 && $$(".modal .trim-step.done").length === 2 && text(".modal .trim-step.done").includes("took 5 s"),
      "every step is listed: the ones done with how long they took");
const pending = $$(".modal .trim-step.pending").map(e => e.textContent).join(" | ");
check(pending.includes("about 20 min") && pending.includes("about 3 min, if needed"),
      "the ones to come with estimates, the optional ones marked");
check(text(".modal .trim-progress").includes("about 23 min left") && text(".modal .trim-progress").includes("plus about 23 min if the last pass is needed"),
      "and the time left in all");
$$(".modal .trim-progress button").find(b => b.textContent === "Stop").click(); await tick();
check(trimJob.stopping, "Stop asks the server to stop it");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
trimJob = { state: "done", mount: "/", stopping: false, now: 1, result: { verdict: "pass",
  headline: "TRIM works on this drive: none of the deleted test data could be read back.",
  lines: [{ label: "Test data read back after deleting", value: "0 of 524288 blocks" }],
  explanation: ["Once deleted data has been trimmed, nobody can read it back by plugging this drive in, even with your encryption key."],
  environment: [{ label: "Filesystem", value: "/ (ext4)" }], offsets: [], text: "TRIM test: TRIM works",
  commands: ["sudo fstrim -av"], names_mount: "/" } };
await window.openTrim(); await tick(); await tick();
check(text(".modal .verdict.ok .vtitle").startsWith("TRIM works on this drive"), "the result is shown, marked as a pass");
check($$(".modal .verdict button").some(b => b.textContent === "Copy as text"), "and can be copied");
check(text(".modal .verdict .cmds").includes("sudo fstrim -av"), "it gives the command to trim by hand");
$$(".modal .verdict button").find(b => b.textContent === "Look at your deleted file names…").click(); await tick(); await tick();
const namesModal = () => $$(".modal").at(-1);
check(namesModal().textContent.includes("it isn't saved") && namesModal().textContent.includes("Who could read them"),
  "the names tool says first that nothing is kept, and who could read the names");
check(namesModal().querySelectorAll(".trim-target input")[1].disabled && namesModal().textContent.includes("/mnt/old is xfs"),
  "a filesystem it can't read is shown, and can't be chosen");
check(namesModal().textContent.includes("The TRIM test passed on this drive"), "it knows the TRIM test's result from this session");
[...namesModal().querySelectorAll("button")].find(b => b.textContent === "Find them").click(); await tick(); await tick(); await tick();
check(namesCalls[0] === "start:/" && text(".names-list").includes("secret-plan.odt"), "then lists the names, by folder");
check(!text(".names-list").includes("tmp-1234") && !text(".names-list").includes("cache2"), "hidden folders are left out at first");
check($(".names-list").innerHTML.includes("&lt;b&gt;tax"), "names are shown as text, never as markup");
check(text(".names-list").includes("delete them permanently there") && !$$(".names-folder").find(f => f.textContent.includes("Dropbox"))
  .querySelector("input"), "a synced folder says where to delete them, and can't be ticked");
namesModal().querySelector(".names > .trim > label.check input").click(); await tick();
check(text(".names-list").includes("tmp-1234"), "and shown when asked");
const cacheFolder = $$(".names-folder").find(f => f.textContent.includes("cache2"));
check(cacheFolder.querySelector("details.hashes summary").textContent === "5 names made from a hash"
  && cacheFolder.textContent.includes("hash it the same way") && cacheFolder.textContent.includes("Keep the cache in memory"),
  "hash names are grouped, with what a browser cache's names give away and the remedy");
check(text(".names").includes("sudo e2fsck -fD /dev/nvme0n1p2"), "every folder at once: the live-USB command");
// ext4's journal: where the names are on a current kernel
const inList = (label) => [...namesModal().querySelectorAll("button")].find(b => b.textContent === label);
check(text(".names .notebox").includes("3 names of these are in the journal only")
  && text(".names .notebox").includes("139 records of folders that are gone or aren't yours"),
  "the list says how many names only the journal holds, and counts what isn't the user's without naming it");
const notes = $$(".names-folder").find(f => f.textContent.includes("~/Notes") && !f.textContent.includes("Project X"));
check(!notes.querySelector("input") && notes.textContent.includes("in the journal"),
  "a folder whose names are in the journal only can't be ticked: there is nothing in it to clean");
check($$(".names-folder").find(f => f.textContent.includes("Project X")).textContent.includes("deleted folder"),
  "a folder that is gone is listed where it was, marked as deleted");
check($$(".names-folder").find(f => f.textContent.includes("~/Documents")).textContent.includes("2 names, 1 in the journal only"),
  "a folder with both says how many are in the journal only");
inList("Show those names…").click(); await tick();
check($$(".modal").at(-1).textContent.includes("other people's file names") && !namesCalls.includes("journal-others"),
  "the names that aren't tied to the user's folders are asked for after saying whose they can be");
[...$$(".modal").at(-1).querySelectorAll(".buttons button")].find(b => b.textContent === "Show them").click(); await tick(); await tick();
check(namesCalls.at(-1) === "journal-others" && $$(".modal").at(-1).textContent.includes("someone-elses.txt")
  && $$(".modal").at(-1).innerHTML.includes("&lt;i&gt;x"), "then they are shown, as text");
$$(".modal").at(-1).querySelector(".buttons button").click(); await tick();
inList("Clear the journal…").click(); await tick();
const clearModal = $$(".modal").at(-1);
check(clearModal.textContent.includes("every folder's names in it and every account's") && clearModal.textContent.includes("Nothing is lost")
  && clearModal.textContent.includes("0x4004662B") && clearModal.textContent.includes("this disk is encrypted")
  && !namesCalls.includes("journal-clear"),
  "clearing the journal says first what it does, whose names it covers, what it doesn't reach, and the same from a terminal");
{ const starts = namesCalls.filter(c => c === "start:/").length;
  [...clearModal.querySelectorAll(".buttons button")].find(b => b.textContent === "Clear the journal").click();
  await tick(); await tick(); await tick(); await tick();
  check(namesCalls.includes("journal-clear") && namesCalls.filter(c => c === "start:/").length === starts + 1,
    "then the kernel clears it, and the names are listed again"); }
{ const res = window.cleanResult({ mount: "/", folders: [{ path: "~/Music", rel: "Music", method: "fillers", state: "partly", journal: 2,
    left: ["a.mp3"], text: "2 of its 2 deleted names can still be read: in the journal." }], explanation: [] },
    ["Music"], "/", () => {}, () => {}, (after) => { namesCalls.push("clear-offered"); after(); });
  window.document.body.append(res);
  [...res.querySelectorAll("button")].find(b => b.textContent === "Clear the journal…").click(); await tick(); await tick();
  check(namesCalls.at(-1) === "check:Music" && namesCalls.at(-2) === "clear-offered",
    "after a clean-up, names left in the journal offer the clear, and the check runs again after it");
  res.remove(); }
const cleanBtn = () => [...namesModal().querySelectorAll("button")].find(b => b.textContent.startsWith("Clean"));
check(cleanBtn().disabled, "nothing to clean until a folder is ticked");
$$(".names-folder").find(f => f.textContent.includes("~/Documents")).querySelector("input").click(); await tick();
check(cleanBtn().textContent === "Clean 1 folder…", "ticking a folder offers to clean it");
cleanBtn().click(); await tick(); await tick();
const planModal = $$(".modal").at(-1);
check(namesCalls.at(-1) === "plan:Documents" && planModal.textContent.includes("Rebuild ~/Documents")
  && planModal.textContent.includes("A rebuilt folder is a new folder"), "the plan says what it does and what is worth knowing");
const goBtn = [...planModal.querySelectorAll(".buttons button")].at(-1);
check(goBtn.disabled, "it can't start until the user says none of the folders is synced");
planModal.querySelector("label.confirm input").click(); await tick();
goBtn.click(); await tick(); await tick(); await tick();
check(namesCalls.includes("clean:Documents:true") && text(".modal .clean-result").includes("1 of its 2 deleted names"),
  "cleaning reports what is left, and where");
[...$$(".modal").at(-1).querySelectorAll("button")].find(b => b.textContent === "Check again").click(); await tick(); await tick();
check(namesCalls.at(-1) === "check:Documents" && text(".modal .clean-result").includes("None of its deleted names"),
  "and can check again later");
{ const res = window.cleanResult({ mount: "/", folders: [{ path: "~/Music", rel: "Music", method: "fillers", state: "partly",
    rebuild_offer: true, left: ["a.mp3"], text: "Fillers couldn't reach every place in this folder." }], explanation: [] },
    ["Music"], "/", () => {}, () => {});
  window.document.body.append(res);
  const offer = [...res.querySelectorAll("button")].find(b => b.textContent === "Rebuild instead…");
  check(!!offer, "fillers that left names offer a rebuild");
  offer.click(); await tick(); await tick();
  check(namesCalls.at(-1) === "plan:Music:rebuild=Music", "which plans that folder as a rebuild: " + namesCalls.at(-1));
  $$(".modal").at(-1).querySelector(".buttons button").click(); await tick();
  res.remove(); }
$$(".modal").at(-1).querySelector(".buttons button").click(); await tick();
namesModal().querySelector(".buttons button").click(); await tick();
check(namesCalls.at(-1) === "forget" && !$(".names-list"), "closing it forgets them");
$$(".modal .verdict button").find(b => b.textContent === "Test again…").click(); await tick(); await tick();
check(trimJob === null && $$(".modal .trim button").some(b => b.textContent === "Start the test"), "Test again forgets it and starts over");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// Before you hand over a drive: removable drives only, every file listed, deleting confirmed, never called erasing
await window.openHandover(); await tick(); await tick();
check(text(".modal .handover").includes("Deleting doesn't erase") && $$(".modal .handover .trim-target input")[1].disabled,
      "it says first that deleting doesn't erase, and a read-only drive can't be chosen");
$$(".modal .handover button").find(b => b.textContent === "Look at the drive").click(); await tick(); await tick();
check(handoverCalls[0] === "plan:/media/a/STICK" && text(".modal .handover .vtitle").startsWith("STICK carries 3 files"),
      "it lists what the drive carries besides the user's files");
check($(".modal .handover").innerHTML.includes("&lt;b&gt;x&lt;/b&gt;.jpg") && text(".modal .handover").includes("(the folder, with everything in it)"),
      "every file is listed, as text");
const delBtn = $$(".modal .handover button").find(b => b.textContent === "Delete 3 files");
check(delBtn.disabled, "deleting waits for the confirmation");
$(".modal .handover label.confirm input").click(); await tick();
delBtn.click(); await tick(); await tick();
check(handoverCalls.at(-1) === "clean:p1:true" && text(".modal .handover").includes("Deleted 3 files")
      && text(".modal .handover").includes("Eject the drive"), "then deletes and says to eject it");
check($$(".modal .handover button").some(b => b.textContent === "Show what they carry…"), "files on it can be shown in Remove metadata");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// Retire a drive: the system drive can't be chosen; what the drive says; commands only once its name is typed
await window.openRetire(); await tick(); await tick();
check($$(".modal .retire .trim-target input")[0].disabled && text(".modal .retire").includes("holds the running system"),
      "the drive the system runs from can't be chosen");
$$(".modal .retire .trim-target input")[1].click(); await tick();
check(text(".modal .retire").includes("listed as drive-managed SMR") && text(".modal .retire").includes("one full overwrite"),
      "a hard disk's choice says what works, and warns about SMR");
$$(".modal .retire button").find(b => b.textContent.startsWith("Read what the drive says")).click(); await tick(); await tick(); await tick();
check(retireCalls[0] === "facts:sdb" && text(".modal .retire").includes("Frozen: suspend and wake"), "what the drive says is shown, frozen included");
$(".modal .retire label.check input[type=checkbox]").click();
$(".modal .retire input.path").value = "sdb";
$$(".modal .retire button").find(b => b.textContent === "Show the commands").click(); await tick(); await tick();
check(retireCalls.at(-1) === "guide:sdb:sdb:true" && text(".modal .retire .cmds").includes("of=/dev/sdb"),
      "typing the name shows the commands for that drive, with what the user said");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// Before you travel: each item's result from the scan, why it matters on a trip, and the RAM disk
await window.openTravel(); await tick(); await tick();
{ const rows = $$(".modal .travel .trow");
  check(rows.length === travelIds.length + 1, "one row per known check, plus the RAM disk (an unknown id is skipped)");
  const r0 = fixture.state.report.results[travelIds[0]];
  check(rows[0].textContent.includes(`Why ${travelIds[0]} matters.`) && rows[0].textContent.includes(r0.summary),
        "each row says why it matters and what the scan found");
  const todo = travelIds.filter(id => ["fail", "warn"].includes(fixture.state.report.results[id].status)
    && fixture.state.report.results[id].effective_severity > 0).length + 1;
  check(text(".modal .travel .vtitle").startsWith(`${todo} thing`), "the headline counts what is left to do: " + text(".modal .travel .vtitle"));
  check(rows.at(-1).textContent.includes("Close and overwrite…"), "an open RAM disk is on the list, with a button to close it");
  { // a finding the user accepted isn't "to do", nor counted: the row says accepted
    const S = window.eval("S");
    const acc0 = S.state.accepted, r1 = S.report.results[travelIds[0]];
    S.report.results[travelIds[0]] = { ...r1, status: "fail", effective_severity: 5 };
    S.state.accepted = {};
    while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
    await window.openTravel(); await tick(); await tick();
    const before = parseInt(text(".modal .travel .vtitle"), 10);
    check($$(".modal .travel .trow")[0].classList.contains("todo"), "(a problem on the list is to do)");
    S.state.accepted = { [travelIds[0]]: { severity: 5, when: 1, note: "" } };
    while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
    await window.openTravel(); await tick(); await tick();
    const row = $$(".modal .travel .trow")[0];
    const left = text(".modal .travel .vtitle");
    check(row.classList.contains("accepted") && row.querySelector(".badge").textContent === "accepted"
          && row.textContent.includes("You accepted this risk") && !row.querySelector("button.primary")
          && (parseInt(left, 10) || 0) === before - 1,
          "an accepted finding isn't to do in Before you travel, nor counted: " + left);
    S.state.accepted = { [travelIds[0]]: { severity: 4, when: 1, note: "" } };
    while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
    await window.openTravel(); await tick(); await tick();
    check($$(".modal .travel .trow")[0].classList.contains("todo"), "until its severity rises above the one it was accepted at");
    S.state.accepted = acc0; S.report.results[travelIds[0]] = r1;
    while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
    await window.openTravel(); await tick(); await tick();
  }
  $$(".modal .travel .trow")[0].querySelector("button.ghost").click(); await tick();
  check(!$$(".modal").length && window.eval("S").open.has(travelIds[0]), "In the list closes it and opens that check"); }

// Presentation mode: what it changes before it is turned on, then the top bar shows it until it is turned off
check($("#presentation-chip").classList.contains("hidden"), "the top bar shows no Presentation mode while it is off");
await window.openTools(); await tick(); await tick();
$$(".modal #tool-presentation button").find(b => b.textContent === "Turn on…").click(); await tick(); await tick();
check($$(".modal").at(-1).textContent.includes("Notification banners off (Do Not Disturb)")
      && $$(".modal").at(-1).textContent.includes("isn't in History"), "turning it on first says what changes, and that it isn't a fix");
[...$$(".modal").at(-1).querySelectorAll(".buttons button")].at(-1).click(); await tick(); await tick();
check(presCalls.at(-1) === "on" && !$("#presentation-chip").classList.contains("hidden"), "once on, the top bar says so");
check($$(".modal #tool-presentation button").some(b => b.textContent === "Turn off"), "and its card offers to turn it off");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
$("#presentation-chip").click(); await tick(); await tick();
check(presCalls.at(-1) === "off" && $("#presentation-chip").classList.contains("hidden"), "the top bar's button turns it off");
check($$("#toasts .toast").some(t => t.textContent.includes("Notification banners were changed meanwhile")),
      "and says, in plain words, when a setting the user changed was kept");
window.eval("S").presentation = { on: true, since: 1790000000, lapsed: ["Do Not Disturb on"] }; window.renderTop();
check($("#presentation-chip").textContent.includes("Do Not Disturb ended"),
      "after a restart on KDE the top bar says Do Not Disturb ended, though Presentation mode is on");
$("#presentation-chip").click(); await tick(); await tick();
check(presCalls.at(-1) === "renew" && $("#presentation-chip").textContent.includes("Turn off"), "and its button takes it up again");
window.eval("S").presentation = { on: false, since: null, lapsed: [] }; window.renderTop();

// camera and microphone: a live view, asked again while it is open, and no longer once closed
await window.openInuse(); await tick();
check(text(".modal .inuse .vtitle") === "In use now: Firefox" && text(".modal .inuse-list").includes("Firefox is using a microphone"),
      "it says who is using what: " + text(".modal .inuse-list"));
check(text(".modal .inuse").includes("Integrated Camera") && text(".modal .inuse").includes("not in use"), "cameras are listed with their state");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }
{ const before = inuseCalls; await new Promise(r => setTimeout(r, 3300));
  check(inuseCalls === before, "closed, it stops asking"); }

// Try an app: a file chosen and prepared, the program in it picked, options, the run, the result, discarded
await window.openTrial(); await tick();
check(text(".modal .trial").includes("A sandbox isn't a guarantee") && $$(".modal .trial input[name=trial-where]").length === 2
      && text(".modal .trial").includes("which doesn't erase it"), "it starts by saying what a sandbox is and isn't, and where the trial can live");
{ const prep = $$(".modal .trial button").find(b => b.textContent === "Prepare it");
  prep.click(); await tick();
  check(!trialCalls.length && $$("#toasts .toast").some(t => t.textContent.includes("Choose a file first")), "nothing is prepared without a file");
  $(".modal .trial input.path").value = "/home/a/Downloads/tool.tar.gz";
  prep.click(); await tick(); await tick(); }
check(trialCalls.join() === "prepare:/home/a/Downloads/tool.tar.gz:memory" && text(".modal .trial").includes("Nothing has run yet")
      && $$(".modal .trial input[name=trial-prog]").length === 2, "prepared, it lists the programs in the archive: " + trialCalls.join());
check(text(".modal .trial .notebox.risk").includes("This is an X11 session") && text(".modal .trial .notebox.risk").includes("a display of its own"),
      "on X11 it says other windows can be read, and offers a display of its own");
{ const net = $$(".modal .trial input[name=trial-net]");
  check(net.length === 2 && net[0].checked && net[1].disabled && text(".modal .trial").includes("sudo apt install passt"),
        "no network by default; the observed one says what it needs when pasta is missing");
  const ticks = $$(".modal .trial input[type=checkbox]");
  check(ticks.length === 4 && ticks[0].checked && ticks[1].checked && !ticks[2].checked && !ticks[3].checked,
        "decoys and the graphics card are on, sound and a display of its own off");
  $$(".modal .trial input[name=trial-prog]")[1].click();
  $(".modal .trial input.path").value = "--demo";
  $$(".modal .trial button").find(b => b.textContent === "Start the trial").click(); await tick(); await tick(); }
{ const sent = JSON.parse(trialCalls.at(-1).slice(6));
  check(sent.program === "tool/main.py" && sent.args === "--demo" && sent.network === "off" && sent.decoys === true && sent.gpu === true,
        "the start sends what was chosen: " + trialCalls.at(-1));
  check(text(".modal .trial").includes("tool.tar.gz is running in its sandbox") && text(".modal .trial .warnbox").includes("looking at decoy files")
        && text(".modal .trial").includes("an SSH private key"), "while it runs, a decoy it looks at is shown at once"); }
$$(".modal .trial button").find(b => b.textContent === "End the trial").click(); await tick(); await tick();
{ const out = text(".modal .trial");
  check(trialCalls.at(-1) === "stop" && out.includes("was ended here"), "ending it shows the result");
  check(text(".modal .trial .warnbox.bad").includes("It opened 1 decoy file of 34") && out.includes("opened 2 times")
        && out.includes("Folders it looked into (1)"), "decoys opened are a warning; a folder only listed is apart");
  check(out.includes("telemetry.example.net") && out.includes("Looked up and not connected to: unused.example.org"),
        "the hosts it contacted are listed, and names it only looked up");
  check(out.includes("~/.config/Tool/id.json") && out.includes("3 files (5 kB) are there now"), "what it wrote is named: the home is made up");
  check(out.includes("bwrap --die-with-parent") && out.includes("discarding overwrites and removes it"),
        "the command that ran it can be seen, and what discarding does is said"); }
$$(".modal .trial button").find(b => b.textContent === "Discard the trial").click(); await tick(); await tick();
check(trialCalls.at(-1) === "discard" && $$(".modal .trial input[name=trial-where]").length === 2, "discarded, the start is back");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// Boxes: each with what it gets and its runs in numbers; started as from the menu
{ const boxCalls = [];
  let boxRunning = false;
  routes["GET /api/tools/boxes"] = () => ({ boxes: [
    { slug: "chat-app", name: "Chat App", kind: "installed", network: "observed", gpu: true, sound: false, folder: "~/Boxes/chat-app",
      exchange: "~/Boxes/chat-app/Exchange", problem: null, launcher: true, running: boxRunning,
      runs: [{ when: 1790000000, seconds: 1260, written: 14, deleted: 2, network: "observed", hosts: 5, new_hosts: 1, sent: 52000, failed: false }] },
    { slug: "old-tool", name: "Old Tool", kind: "appimage", network: "off", gpu: false, sound: false, folder: "~/Boxes/old-tool",
      exchange: "~/Boxes/old-tool/Exchange", problem: "its program is missing from the Box", launcher: false, running: false, runs: [] }] });
  routes["POST /api/tools/boxes/start"] = (body) => { boxCalls.push("start:" + body.box); boxRunning = true; return { ok: true }; };
  routes["POST /api/tools/boxes/clear"] = (body) => { boxCalls.push("clear:" + body.box); return { ok: true }; };
  await window.openBoxes(); await tick();
  const cards = $$(".modal .box-card");
  check(cards.length === 2 && cards[0].textContent.includes("its own network, observed") && cards[0].textContent.includes("~/Boxes/chat-app/Exchange"),
        "each Box says what it gets and where files go in and out");
  check(cards[0].textContent.includes("Its last 1 run, in numbers") && $$(".modal .box-card table.places tbody td").map(t => t.textContent).slice(1, 6).join("|")
        === "21 min|14|5|1|52 kB" && cards[0].textContent.includes("no names of sites or files are kept"),
        "its runs are numbers: " + $$(".modal .box-card table.places tbody td").map(t => t.textContent).join("|"));
  check(cards[1].textContent.includes("It can't start: its program is missing from the Box") && cards[1].textContent.includes("menu entry is missing")
        && cards[1].querySelector("button.primary").disabled, "a Box that can't start says why, and can't be started");
  cards[0].querySelector("button.primary").click(); await tick();
  check(boxCalls.join() === "start:chat-app" && $$("#toasts .toast").some(t => t.textContent.includes("Chat App is starting in its Box")),
        "Start runs it as its menu entry does");
  while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); } }

// What does this app keep?: the warning first, an app chosen, watched, ended; counts, and names only where they are the point
await window.openKeeps(); await tick();
check(text(".modal .activity .notebox.risk").includes("Administrator access for the whole time")
      && text(".modal .activity .notebox.risk").includes("until you end it"), "it says first that it needs administrator access throughout");
check($$(".modal .applist label").length === 2 && text(".modal .applist").includes("Flatpak"), "the menu's apps are listed, a Flatpak marked");
{ const find = $(".modal .activity input[type=search]");
  find.value = "bar"; find.dispatchEvent(new window.Event("input"));
  check($$(".modal .applist label").length === 1, "the list can be narrowed down");
  find.value = ""; find.dispatchEvent(new window.Event("input")); }
$$(".modal .activity button").find(b => b.textContent.startsWith("Start the app")).click(); await tick();
check(!keepsCalls.length && $$("#toasts .toast").some(t => t.textContent.includes("Choose an app first")), "nothing starts without an app chosen");
$$(".modal .applist input[type=radio]")[0].click(); await tick();
$$(".modal .activity button").find(b => b.textContent.startsWith("Start the app")).click(); await tick(); await tick();
check(keepsCalls.join() === "start:foo.desktop" && text(".modal .activity").includes("Watching Foo")
      && text(".modal .activity .tally").includes("7 files touched by the app"), "while it watches it shows counts: " + text(".modal .activity .tally"));
check(text(".modal .activity").includes("Administrator access is held until you end the watch"), "and that the access is held");
$$(".modal .activity button").find(b => b.textContent.startsWith("End the watch")).click(); await tick(); await tick();
{ const out = text(".modal .activity");
  check(keepsCalls.at(-1) === "stop" && out.includes("Foo was watched for 21 min"), "ending it shows the result: " + out.slice(0, 90));
  check(out.includes("~/.cache/thumbnails/large/0a.png") && out.includes("another program (tumblerd)") && out.includes("the app itself"),
        "the files that recorded what was opened are named, with who wrote them");
  check(out.includes("~/.config/Foo/history.db") && out.includes("written in 12 different minutes"), "and the files it writes to all the time");
  check(out.includes("Your own files are counted, never listed: 3 read") && $$(".modal table.places tbody tr").length === 5,
        "the rest is folders with counts, the user's own files only counted");
  check(out.includes("SSH keys and settings: 1 file read"), "a sensitive place it opened is said, by kind");
  check(out.includes("Not watched: /mnt/x"), "what couldn't be watched is said"); }
$$(".modal .activity button").find(b => b.textContent === "Dismiss this result").click(); await tick(); await tick();
check(keepsCalls.at(-1) === "dismiss" && $$(".modal .applist").length === 1, "dismissed, it is gone and the start is back");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// the welcome warning: on top at start-up, read rather than clicked away; the choice is kept; the name reopens it
{ const welcomeBodies = [], opened = [];
  routes["POST /api/welcome"] = (body) => { welcomeBodies.push(body); return { show: !body.hide }; };
  routes["POST /api/open"] = (body) => { opened.push(body.link); return { ok: true, url: "https://tails.net/" }; };
  const S = window.eval("S");
  S.state.welcome = { show: true, links: { tails: "https://tails.net/", qubes: "https://www.qubes-os.org/",
                                           releases: "https://github.com/DigitalArchon/DAPrivacyKit/releases",
                                           issues: "https://github.com/DigitalArchon/DAPrivacyKit/issues" } };
  S.state.app = { version: "0.1.0.dev50", built: "2026-10-12", built_text: "12 October 2026", days: 0, old: false, text: "" };
  window.openWelcome(); await tick();
  const box = () => $(".modal.welcome");
  check(box() && text(".modal.welcome h2") === "Important privacy warning" && box().querySelector("img.welcome-banner"),
        "the warning opens with the banner as its heading");
  check(text(".modal.welcome").includes("DA Privacy Kit is in public beta") && text(".modal.welcome").includes("expect bugs")
        && text(".modal.welcome").includes("Don't rely on it yet for critical privacy matters")
        && text(".modal.welcome").includes("run commands with administrator rights"),
        "it says the app is a public beta, not to be relied on yet, and not risk-free");
  check(text(".modal.welcome").includes("in no way a replacement for, or an alternative to, Tails or Qubes OS"),
        "it says first what the tool is not");
  check(text(".modal.welcome").includes("It helps in four ways") && text(".modal.welcome").includes("It is also meant to teach")
        && text(".modal.welcome").includes("think it through for yourself"), "it says the tool is also there to learn from");
  check(!box().querySelector("input[type=checkbox]").checked, "Don't show this again starts unticked");
  box().parentElement.click(); await tick();
  check(box() !== null, "clicking beside it doesn't close it");
  box().querySelector('a.extlink[href="https://tails.net/"]').click(); await tick();
  check(opened[0] === "tails", "a link asks the app to open it in the browser, by name");
  check(text(".modal.welcome .wbeta").includes("If you find a bug, please report it")
        && box().querySelector('.wbeta a.extlink[href$="/issues"]'), "the beta notice says where to report a bug");
  check(text(".modal.welcome").includes("Version 0.1.0.dev50, built 12 October 2026."), "it says which version this is, and when it was built");
  box().querySelector("input[type=checkbox]").click();
  [...box().querySelectorAll(".buttons button")].at(-1).click(); await tick(); await tick();
  check(!box() && welcomeBodies.at(-1)?.hide === true && S.state.welcome.show === false, "I understand closes it and keeps the choice");
  $("#brand").click(); await tick();
  check(box() && box().querySelector("input[type=checkbox]").checked, "the app's name opens it again, with the choice shown");
  [...box().querySelectorAll(".buttons button")].at(-1).click(); await tick(); }

// Easy fixes: counted in the summary, a badge on the row, one dialog with what each costs; without disk
// encryption it starts with what to do until then; deletions confirmed on their own; applied together
{ const S = window.eval("S");
  const spec = (id) => S.state.catalogue.find(s => s.id === id);
  const saved = JSON.stringify(S.report.results);
  spec("enc.tmp_on_disk").easy = { option: "tmp_mount", cost: "From the next restart." };
  spec("desk.thumbnails").easy = { option: "in_memory", cost: "Thumbnails are made again after each restart." };
  spec("enc.fde_missing").meanwhile = { text: "Until the disk is encrypted, these keep the most sensitive things off it.",
                                        checks: ["enc.swap_unencrypted", "enc.tmp_on_disk"] };
  S.report.results["enc.tmp_on_disk"].easy = true;
  Object.assign(S.report.results["desk.thumbnails"], { status: "warn", effective_severity: 3, fixable: true, easy: true });
  Object.assign(S.report.results["enc.fde_missing"], { status: "fail", effective_severity: 10, how_to: true });
  window.setShow("all");
  const btn = $(".report .easy-btn");
  check(btn?.textContent === "Easy fixes (2)…", "the summary offers the Easy fixes, counted: " + btn?.textContent);
  check($("#c-enc\\.tmp_on_disk .badge.easy") && !$("#c-tel\\.location .badge.easy"), "an Easy fix's row says so, and only theirs");
  const wasOpen = S.open.has("enc.fde_missing");
  S.open.add("enc.fde_missing"); window.renderChecks();
  check(text("#c-enc\\.fde_missing .meanwhile").includes("Until then")
        && $$("#c-enc\\.fde_missing .meanwhile .trow").length === 2,
        "an unencrypted disk's details say what to do until then: " + text("#c-enc\\.fde_missing").slice(0, 200));
  if (!wasOpen) S.open.delete("enc.fde_missing");
  const step = (text, irreversible = false) => ({ kind: irreversible ? "delete" : "root", text, reversible: !irreversible,
                                                   irreversible, needs_root: !irreversible });
  const plan = (id, check_id, title, steps, blockers = []) => ({ id, check_id, title, blockers, side_effects: [],
    needs_root: true, irreversible_files: 0, steps, dry_run: "" });
  const item = (check_id, title, cost, plans, extra = {}) => ({ check_id, title, cost, kind: "finding", severity: 2,
    status: "fail", needs_root: true, blockers: [], irreversible: false, plans, ...extra });
  routes["POST /api/easy/plan"] = () => ({ admin_active: false, items: [
    item("enc.tmp_on_disk", "/tmp is on disk rather than in memory", "From the next restart.",
         [plan("e1", "enc.tmp_on_disk", "Enable tmp.mount", [step("Enable tmp.mount")])]),
    item("desk.thumbnails", "Thumbnail cache", "Thumbnails are made again after each restart.",
         [plan("e2", "desk.thumbnails", "Mount ~/.cache/thumbnails in memory",
               [step("Delete 32 files of every cached thumbnail", true), step("Add the mount unit")])], { irreversible: true }),
    item("tel.browser_telemetry", "Browser telemetry and studies", "The browser has to be closed.",
         [plan("e3", "tel.browser_telemetry", "Turn off telemetry", [step("set a pref")], ["Close Firefox first."])],
         { blockers: ["Close Firefox first."] })] });
  const easyBodies = [];
  routes["POST /api/easy/apply"] = (body) => { easyBodies.push(body); return { ok: true, admin_active: true, undone: [],
    context: S.report.context, rechecked: { "enc.tmp_on_disk": { ...S.report.results["enc.tmp_on_disk"], status: "pass", easy: false } },
    results: [{ check_id: "enc.tmp_on_disk", title: "Enable tmp.mount", ok: true, error: "", entry_id: "u1",
                entry: { id: "u1", check_id: "enc.tmp_on_disk", title: "Enable tmp.mount", applied: 1790000000, state: "applied",
                  can_revert: true, needs_root: true, via_text: "Applied as an Easy fix", steps: [
                    { text: "Enable tmp.mount", reversible: true, reverted: false, as_root: true,
                      commands: ["systemctl enable /usr/share/systemd/tmp.mount", "systemctl daemon-reload"], files: [], lines: [],
                      undo: "Revert it in the app", revert_ran: [] }] } },
              { check_id: "desk.thumbnails", title: "Mount in memory", ok: true, error: "", entry_id: "u2",
                entry: { id: "u2", check_id: "desk.thumbnails", title: "Mount in memory", applied: 1790000000, state: "applied",
                  can_revert: true, needs_root: true, via_text: "From the guide “Thumbnails”, step 2 (In memory), applied as an Easy fix",
                  steps: [{ text: "Deleted 32 files of thumbnails", reversible: false, reverted: false, as_root: false, commands: [],
                            files: [], lines: [], undo: "", revert_ran: [] }] } }] }; };
  btn.click(); await tick(); await tick();
  const m = () => $(".modal.easy-modal");
  check(m() && text(".modal.easy-modal .warnbox.first").includes("Full-disk encryption not enabled")
        && $$(".modal.easy-modal .warnbox.first .trow").length === 2
        && $$(".modal.easy-modal .warnbox.first button").some(b => b.textContent === "How to…"),
        "without disk encryption the dialog starts with it, and what to do until then");
  const boxes = [...m().querySelectorAll(".eitem input[type=checkbox]")];
  check(boxes.length === 3 && boxes[0].checked && boxes[1].checked && !boxes[2].checked && boxes[2].disabled
        && text(".modal.easy-modal .eitem.blocked").includes("Close Firefox first"), "each is ticked, except one that can't be applied now, which says why");
  check(text(".modal.easy-modal .elist").includes("What it costs you: From the next restart."), "each says what it costs");
  const apply = [...m().querySelectorAll(".buttons button")].at(-1);
  const confirmBox = () => m().querySelector(".easy-confirm");
  check(apply.disabled && apply.textContent === "Apply 2 fixes" && !confirmBox().classList.contains("hidden")
        && confirmBox().textContent.includes("Thumbnail cache: Delete 32 files"), "deleting needs its own confirmation, naming what goes");
  boxes[1].click(); await tick();
  check(!apply.disabled && apply.textContent === "Apply 1 fix" && confirmBox().classList.contains("hidden"),
        "unticked, the confirmation goes away");
  boxes[1].click(); confirmBox().querySelector("input").click(); await tick();
  check(!apply.disabled && apply.className === "danger", "confirmed, it can be applied");
  apply.click(); await tick(); await tick();
  check(easyBodies[0]?.plan_ids.join() === "e1,e2" && easyBodies[0].confirm_irreversible === true,
        "it applies the ticked plans, with the deletion confirmed");
  check(!m() && S.report.results["enc.tmp_on_disk"].status === "pass", "then it closes and the results are rechecked");
  check($$("#toasts .toast").some(t => t.textContent.includes("2 Easy fixes applied")), "and says what was done");
  { const done = $$(".modal").at(-1);
    check(done?.querySelector("h2")?.textContent === "Done: 2 fixes applied" && $$(".modal .entry").length === 2
          && done.textContent.includes("systemctl enable /usr/share/systemd/tmp.mount") && done.textContent.includes("Ran, as root:")
          && done.textContent.includes("From the guide “Thumbnails”, step 2 (In memory), applied as an Easy fix"),
          "and shows every entry made, with what each ran: " + (done?.textContent || "").slice(0, 160));
    [...done.querySelectorAll(".buttons button")].at(-1).click(); await tick(); }
  Object.assign(S.report.results, JSON.parse(saved));
  delete spec("enc.fde_missing").meanwhile;
  window.renderChecks(); }

// a fix that doesn't cover this machine: "no fix here" in place of the tier, and why in the details
{ const S = window.eval("S");
  const saved = JSON.stringify(S.report.results["tel.location"]);
  Object.assign(S.report.results["tel.location"], { status: "warn", effective_severity: 3, fixable: false,
    no_fix: "GeoClue's settings file isn't there to change." });
  window.setShow("all"); S.open.add("tel.location"); window.renderChecks();
  check(text("#c-tel\\.location .badges").includes("no fix here") && !$("#c-tel\\.location .badge.tier-auto")
        && !$$("#c-tel\\.location .badges button").some(b => b.textContent === "Fix…"),
        "a fix that doesn't cover this machine shows no fix here, not auto: " + text("#c-tel\\.location .badges"));
  check(text("#c-tel\\.location .details .no-fix").includes("GeoClue's settings file"), "and the details say why");
  S.open.delete("tel.location");
  S.report.results["tel.location"] = JSON.parse(saved); window.renderChecks(); }

// a related chip that names a set-up opens the Tools panel
window.reveal("desk.file_manager_actions"); await tick(); await tick();
check($$(".modal .toolcard").length === TOOL_COUNT, "revealing a set-up opens the Tools panel");
while ($$(".modal").length) { $$(".modal .buttons button").at(-1).click(); await tick(); }

// a warning is a Risk, a failure a Problem: plain words, the severity alone coloured; at one severity problems come first
{ const S = window.eval("S");
  const saved = JSON.stringify(S.report.results["net.dns_unencrypted"]);
  Object.assign(S.report.results["net.dns_unencrypted"], { status: "warn", as_warning: true });    // 3, as net.firewall_off
  window.setShow("all"); S.open.clear(); S.open.add("net.dns_unencrypted"); window.renderChecks(); await tick();
  const ids = $$("#checks-list .citem").map(e => e.id.slice(2));
  check(text("#c-net\\.dns_unencrypted .sevcol .status") === "Risk" && text("#c-net\\.firewall_off .sevcol .status") === "Problem",
        "a warning reads Risk and a failure Problem");
  check(ids.indexOf("net.firewall_off") < ids.indexOf("net.dns_unencrypted"), "at the same severity the problem comes before the risk");
  check($("#c-net\\.dns_unencrypted .sevcol .sev").title.includes("a risk, rated 2 below the problem"), "the severity's tooltip says why a risk is lower");
  check(text("#c-net\\.dns_unencrypted .details").includes("A risk, not a confirmed problem"), "and so do the details");
  S.open.delete("net.dns_unencrypted"); S.report.results["net.dns_unencrypted"] = JSON.parse(saved); window.renderChecks(); await tick(); }

// the user sees checks by their titles; ids (enc.fde_missing) only in developer mode
{ const S = window.eval("S");
  window.setShow("all"); S.open.clear(); window.renderChecks(); await tick();
  check($$("#checks-list .citem").length > 0 && !$$("#checks-list .citem .id").length, "no row shows a check's id outside developer mode");
  check(!$$("#context-list .ctx .key").length, "the context pane shows no raw key outside developer mode");
  const spec = fixture.state.catalogue.find(sp => sp.related.length && sp.modifiers.length && results[sp.id]);
  S.open.add(spec.id); window.renderChecks(); await tick();
  const row = `#c-${spec.id.replace(".", "\\.")}`;
  const chips = $$(`${row} .details .related .chip`).map(c => c.textContent);
  check(chips.length === spec.related.length && chips.every((t, i) => t === checkTitleOf(spec.related[i]) && !/^[a-z]+\.[a-z_]+$/.test(t)),
        "related checks are chips with their titles: " + chips.join(" | "));
  const mods = $$(`${row} .details .mods li`);
  check(mods.length === spec.modifiers.length && !$$(`${row} .details .mods code`).length
        && mods.every((li, i) => li.textContent.includes(spec.modifiers[i].when_text)), "a modifier's condition is shown in words, not as an expression");
  S.state.dev = true; window.renderChecks(); window.renderContext(); await tick();
  check($$("#checks-list .citem .id").length > 0 && $$(`${row} .details .mods code`).length > 0 && $$("#context-list .ctx .key").length > 0,
        "developer mode shows the ids, the expressions and the keys");
  S.state.dev = false; S.open.delete(spec.id); window.renderChecks(); window.renderContext(); await tick(); }

// started with --browser: the page says what the user's own browser can do with it, at the top, until acknowledged
{ const S = window.eval("S");
  check(!$("#checks-list .notebox.danger"), "no browser warning in the app's window");
  S.state.in_browser = true; window.renderChecks(); await tick();
  const banner = $("#checks-list .notebox.danger");
  check(banner && banner.textContent.includes("browser extension allowed on all sites"), "in the browser, the page says what that exposes");
  banner.querySelector("button").click(); await tick();
  check(!$("#checks-list .notebox.danger"), "acknowledged, it goes for this page");
  S.state.in_browser = false; S.browserNoted = false; window.renderChecks(); await tick(); }

// the app never looks for updates: a copy built more than a few months ago says so at the top, with where the latest is
{ const S = window.eval("S");
  const note = () => [...window.document.querySelectorAll("#checks-list .notebox")].find(n => n.textContent.includes("getting old"));
  window.renderChecks(); await tick();
  check(!note(), "a recent copy says nothing about its age");
  S.state.app = { ...S.state.app, days: 130, old: true }; window.renderChecks(); await tick();
  check(note() && note().textContent.includes("built on 12 October 2026, about 4 months ago")
        && note().textContent.includes("never looks for updates by itself") && note().querySelector('a.extlink[href$="/releases"]'),
        "an old copy says when it was built and where the latest is: " + note()?.textContent);
  note().querySelector("button").click(); await tick();
  check(!note(), "Not now puts it away for this page");
  S.state.app = { ...S.state.app, days: 0, old: false }; S.oldCopyNoted = false; window.renderChecks(); await tick(); }

// dialogs for the keyboard and a screen reader: announced as dialogs, the focus inside and kept there, Escape closes
// the one on top (not a sticky one), and the focus goes back to where it was
{ const doc = window.document;
  const key = (k, shiftKey = false) => { const e = new window.KeyboardEvent("keydown", { key: k, shiftKey, bubbles: true, cancelable: true });
                                         (doc.activeElement || doc.body).dispatchEvent(e); return e; };
  const dialogs = () => $$("#modal-root .overlay .modal");
  for (const d of dialogs()) d.parentElement.remove();
  await tick();
  check(!$("#topbar").hasAttribute("inert"), "with no dialog open, the page can be reached");
  const opener = $("#history-btn");
  opener.focus();
  const field = doc.createElement("input");
  const m = window.modal({ title: "A question", body: [doc.createTextNode("Text. "), field],
                           buttons: [{ label: "No" }, { label: "Yes", kind: "primary" }] });
  const box = m.box, buttons = [...box.querySelectorAll(".buttons button")];
  check(box.getAttribute("role") === "dialog" && box.getAttribute("aria-modal") === "true"
        && doc.getElementById(box.getAttribute("aria-labelledby"))?.textContent === "A question",
        "a dialog says it is one, named by its title");
  check(doc.activeElement === box, "opening it moves the focus into it");
  check($("#topbar").hasAttribute("inert") && $("#workspace").hasAttribute("inert") && !$("#toasts").hasAttribute("inert")
        && !$("#modal-root").hasAttribute("inert"), "what is behind it can't be reached; toasts and the dialog can");
  check(key("Tab").defaultPrevented && doc.activeElement === field, "Tab goes to its first control");
  buttons.at(-1).focus();
  check(key("Tab").defaultPrevented && doc.activeElement === field, "Tab on the last control goes round to the first");
  check(key("Tab", true).defaultPrevented && doc.activeElement === buttons.at(-1), "Shift+Tab on the first goes round to the last");
  // WebKitGTK names Shift+Tab "Unidentified": it is known by its code and number (seen in the app's window on KDE)
  field.focus();
  const webkit = new window.KeyboardEvent("keydown", { key: "Unidentified", code: "Tab", keyCode: 9, shiftKey: true, bubbles: true, cancelable: true });
  field.dispatchEvent(webkit);
  check(webkit.defaultPrevented && doc.activeElement === buttons.at(-1), "Shift+Tab as WebKitGTK sends it goes round too");
  field.focus();
  check(!key("Tab").defaultPrevented, "in between, Tab is the browser's own");
  // a second dialog on top: Escape closes that one only, and the focus returns to the first
  buttons[0].focus();
  const top = window.modal({ title: "Sure?", body: "Really.", buttons: [{ label: "OK" }] });
  check(dialogs().length === 2 && box.parentElement.hasAttribute("inert") && !top.box.parentElement.hasAttribute("inert"),
        "a dialog under another is out of reach too");
  key("Escape"); await tick();
  check(dialogs().length === 1 && dialogs()[0] === box && !box.parentElement.hasAttribute("inert") && doc.activeElement === buttons[0],
        "Escape closes the dialog on top, and the focus goes back to the button that opened it");
  key("Escape"); await tick();
  check(dialogs().length === 0 && doc.activeElement === opener && !$("#topbar").hasAttribute("inert"),
        "Escape closes it; the focus is back on the page's button and the page can be reached again");
  // a sticky dialog (the welcome warning) is closed by its own buttons only
  const sticky = window.modal({ title: "Read this", body: "Important.", sticky: true, buttons: [{ label: "I understand" }] });
  key("Escape"); await tick();
  check(dialogs().length === 1, "Escape doesn't close a dialog that must be answered");
  sticky.box.querySelector(".buttons button").click(); await tick();
  check(dialogs().length === 0 && !$("#workspace").hasAttribute("inert"), "its button does");
  // one taken off the page some other way doesn't leave the page out of reach
  const gone = window.modal({ title: "Gone", body: "x" });
  gone.box.parentElement.remove(); await tick();
  check(!$("#topbar").hasAttribute("inert"), "a dialog removed without closing leaves the page reachable");
  window.toast("Saved.", "ok", 50); window.toast("It failed.", "error", 50);
  check($("#toasts .toast.ok")?.getAttribute("role") === "status" && $("#toasts .toast.error")?.getAttribute("role") === "alert",
        "toasts are read out: an error at once");
  await new Promise(r => setTimeout(r, 80)); }

if (failures) { console.error(`${failures} front-end checks failed`); process.exit(1); }
console.log("front-end: all checks passed");
