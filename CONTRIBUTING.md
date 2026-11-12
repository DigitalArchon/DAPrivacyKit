# Contributing to DA Privacy Kit

Thank you for looking. This is a one-person project, so the most useful contributions are bug reports with a
redacted report attached (**Export…** with **Redact** ticked), and fixes small enough to review. Vulnerabilities go
privately, as [SECURITY.md](SECURITY.md) says, never in an issue.

## Setting up

You need Python 3.11 or later, the system's PyGObject and WebKitGTK 4.1 (for the window), node 20 or later (for the
front-end test), [uv](https://docs.astral.sh/uv/) (for the CI's venvs), and rootless Podman to build the AppImage.

```sh
python3 -m venv --system-site-packages .venv     # the system's PyGObject for the WebKitGTK window
.venv/bin/pip install -e '.[dev]'
npm ci --prefix tests/web                         # jsdom and ESLint, exactly as tests/web/package-lock.json pins them
.venv/bin/python -m pytest                        # the suite: about 2,800 tests, a few minutes
.venv/bin/daprivacyscanner                        # the app (or --browser, --dev)
```

The internal name is `daprivacyscanner` (the package, the command, folders, the polkit action, `DAPRIVACYSCANNER_*`
variables): only what a user sees says DA Privacy Kit.

## Before you commit or push: make check

The project's CI runs on your computer, not on GitHub: `make check` (or `packaging/check.sh`; `--help` lists the
steps). It runs ruff and a check for programs started without a timeout, mypy, shellcheck on the packaging
scripts, ESLint on the page's script, the page in a real WebKitGTK window on a private Xvfb display (where Xvfb and
xdotool are installed: it never touches your display; screenshots in `.ci/webkit-shots/`), and the whole suite on
the dev venv and on Python 3.11, 3.12, 3.13 and 3.14 with exactly the packages the
AppImage ships, the front-end test included (it fails, never skips, there), and coverage (the 3.12 run, branches,
`.ci/coverage/html/index.html`). Every tool is pinned with hashes; the venvs are made under `.ci/` the first time,
which takes a minute (`uv python install 3.11 3.13 3.14` first, if uv doesn't have those Pythons yet). `make quick`
is the short version (lint, types, the page's checks and the dev venv's suite); `JOBS=3 make check` runs three
suites at once.
`packaging/install-hooks.sh` makes git run `make check` before every push, if you want that.

The linters came in after the code: what they found then is counted per file and rule in
`packaging/ci/*-baseline.txt`, and a run fails only on more. Fix what you touch, then `make rebaseline` shrinks the
baseline; never add to it to get a change through.

Tests never read the real machine: they get fixture homes and fake `/etc`, `/proc` and `/sys` trees
(`tests/conftest.py`'s `make_host`), captured command output (`tests/samples/`), and every test runs in a folder
of its own with HOME and the XDG folders in it, no session bus or display, and no network but loopback (a test that
tries fails). Never apply a fix to your own machine in a test.

## What matters most

The design rules are in [docs/TECHNICAL.md](docs/TECHNICAL.md#design-rules) (the code's comments cite them by
number), and the checks are [privacy-checks.yaml](privacy-checks.yaml) (read its header for the schema). In short:

- **A scan never changes anything** and never goes online. Online tests, the browser download and Check for
  updates… run only when the user starts them, after the app has named every host they contact.
- **Root only through the helper** (`helper.py`, standard library only), which validates every argument itself and
  never writes content the app sends. The rest runs as the user.
- **Every fix has a dry run that shows exactly what it does, and can be reverted from History**; deleting caches
  and histories can't, and is confirmed on its own. No "secure delete": encryption is what protects deleted data.
- **Nothing is guessed**: what couldn't be checked says so, never passes. Evidence holds counts and settings, never
  secrets, file contents or account names; reports can be redacted.
- **The catalogue first**: change `privacy-checks.yaml`, then the code; never rename a shipped check id. A check that
  reads an app's files lists the app in `apps.yaml`.
- The plain-words rule: what the user reads says what it means for them, then what to do, naming the button.

## Releases, and how to check one

Releases are made as [packaging/README.md](packaging/README.md#releasing) describes: `make release-check`, a tag,
the AppImage built and signed with the release key. The AppImage is reproducible: built twice and compared here,
optionally once more on another machine from the pushed tag (`packaging/second-build.sh`), and anyone can rebuild a
release from its tag and compare (`packaging/verify-release.sh TAG`).

## Licence

GPL-3.0-or-later. By contributing you agree that your contribution is licensed under it.
