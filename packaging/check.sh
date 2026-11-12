#!/bin/bash
# The project's CI, run on this computer (the owner's decision of 2026-11-12: nothing runs on GitHub). Run it before
# committing or pushing; `packaging/install-hooks.sh` makes git run it before every push.
#
#   packaging/check.sh                  everything below but the release steps (make check)
#   packaging/check.sh --quick          lint, types, shell scripts, and the suite on the dev venv (make quick)
#   packaging/check.sh --release        everything, on a clean tree, then the AppImage built twice and compared, and
#                                       smoke-tested extracted and mounted (make release-check)
#   packaging/check.sh STEP...          only those steps: lint types shell web dev py3.11 py3.12 py3.13 py3.14
#   packaging/check.sh --rebaseline     rewrite the lint and type baselines from what is found now (review the diff)
#   packaging/check.sh --lock           re-resolve packaging/ci/requirements.lock and tests/web/package-lock.json
#   -j N                                the test suites run N at a time (default 2)
#
# Steps:
#   lint     ruff (ruff.toml) and packaging/ci/check_timeouts.py, each against its baseline in packaging/ci/
#   types    mypy (pyproject.toml's [tool.mypy]) against packaging/ci/mypy-baseline.txt
#   shell    shellcheck on packaging/*.sh, packaging/appimage/*.sh and AppRun
#   web      jsdom installed as tests/web/package-lock.json pins it (npm ci); the front-end test then runs in every
#            suite below and fails, never skips, when it can't
#   dev      the suite on the dev venv (.venv: the system's Python and PyGObject, the versions pip gave)
#   py3.X    the suite on Python 3.11, 3.12, 3.13 and 3.14 (uv's), with exactly the packages the AppImage ships
#            (packaging/appimage/requirements.lock) and the test tools (packaging/ci/requirements.lock): the helper,
#            torgate, xfocus and the sandbox's scripts run on the host's python3, which is any of these. py3.12 runs
#            under coverage (branches, every module including helper.py, and what the tests start with python).
# Every tool is pinned with hashes (packaging/ci/requirements.lock, tests/web/package-lock.json); the venvs are
# made under .ci/ (ignored by git) and made again when a lock changes. Logs: .ci/logs/<step>.log.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
CI="$ROOT/.ci"
LOCKS=(packaging/appimage/build-requirements.lock packaging/appimage/requirements.lock packaging/ci/requirements.lock)
PYTHONS=(3.11 3.12 3.13 3.14)
TOOLS="$CI/py3.12/bin"              # ruff, mypy, shellcheck, coverage: from the py3.12 venv
jobs=2 mode=all steps=()

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) mode=quick ;;
        --release) mode=release ;;
        --rebaseline) mode=rebaseline ;;
        --lock) mode=lock ;;
        -j) jobs="$2"; shift ;;
        -j*) jobs="${1#-j}" ;;
        -h|--help) usage ;;
        lint|types|shell|web|dev|py3.1[1-4]) steps+=("$1") ;;
        *) echo "unknown step or option: $1" >&2; usage 2 >&2 ;;
    esac
    shift
done
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "-j takes a number" >&2; exit 2; }
if [ ${#steps[@]} -eq 0 ]; then
    case "$mode" in
        quick) steps=(lint types shell web dev) ;;
        *) steps=(lint types shell web dev "${PYTHONS[@]/#/py}") ;;
    esac
fi

command -v uv >/dev/null || { echo "uv is needed to make the venvs: https://docs.astral.sh/uv/ (or pipx install uv)" >&2
                              exit 2; }
mkdir -p "$CI/logs"
declare -A RESULT

venv() {  # python version -> .ci/pyX with the locked packages, made again when a lock or uv changes
    local v=$1 dir="$CI/py$1" stamp
    stamp="$( (uv --version; cat "${LOCKS[@]}") | sha256sum | cut -c1-16)"
    if [ "$(cat "$dir/.locks" 2>/dev/null)" != "$stamp" ]; then
        rm -rf "$dir"
        uv venv -q --python "$v" "$dir"
        # setuptools from the AppImage's build lock first: proxy-tools (pywebview's) has no wheel, and is built
        # without fetching an unpinned build backend
        uv pip install -q --python "$dir/bin/python" --require-hashes -r packaging/appimage/build-requirements.lock
        uv pip install -q --python "$dir/bin/python" --require-hashes --no-build-isolation \
            -r packaging/appimage/requirements.lock -r packaging/ci/requirements.lock
        echo "$stamp" > "$dir/.locks"
    fi
    echo "$dir/bin/python"
}

dev_python() {
    local common
    common="$(cd "$(git rev-parse --git-common-dir)/.." && pwd)"
    for p in "${DEV_PYTHON:-}" "$ROOT/.venv/bin/python" "$common/.venv/bin/python"; do
        [ -n "$p" ] && [ -x "$p" ] && { echo "$p"; return; }
    done
    return 1
}

web_deps() {
    command -v node >/dev/null || { echo "node isn't installed (node 20 or later)"; return 1; }
    local stamp
    stamp="$(sha256sum tests/web/package-lock.json | cut -c1-16)"
    if [ "$(cat "$CI/web.stamp" 2>/dev/null)" != "$stamp" ] || [ ! -d tests/web/node_modules/jsdom ]; then
        npm ci --prefix tests/web --ignore-scripts --no-audit --no-fund
        echo "$stamp" > "$CI/web.stamp"
    fi
}

# Each suite sees a runtime folder of its own (/run/user/UID as an empty tmpfs, in a bubblewrap namespace): fixture
# hosts name their runtime folder as the machine would, and some of the code (tools/owner.py's locks) takes it as a
# real path, so the suite wrote lock files into this computer's runtime folder and two suites at once refused each
# other's starts. Without bubblewrap (or where AppArmor keeps it from making a namespace) the suites run one at a time.
ISOLATE=()
if command -v bwrap >/dev/null && bwrap --dev-bind / / --tmpfs "/run/user/$(id -u)" -- true 2>/dev/null; then
    ISOLATE=(bwrap --dev-bind / / --tmpfs "/run/user/$(id -u)" --)
fi

suite() {  # step python [coverage]: the whole suite, the front-end test required, in a temporary folder of its own
    local step=$1 py=$2 cover=${3:-} tmp rc=0
    tmp="$(mktemp -d)"
    local env=(PYTHONPATH="$ROOT/src" DAPRIVACYSCANNER_REQUIRE_NODE=1
               DAPRIVACYSCANNER_NODE_PATH="$ROOT/tests/web/node_modules" PYTHONDONTWRITEBYTECODE=1)
    if [ -n "$cover" ]; then
        rm -rf "$CI/coverage" && mkdir -p "$CI/coverage"
        "${ISOLATE[@]}" env "${env[@]}" "$py" -m coverage run -m pytest -q -p no:cacheprovider --basetemp="$tmp/t" \
            || rc=$?
        "$py" -m coverage combine -q || rc=$?
        "$py" -m coverage report --sort=-miss > "$CI/coverage/report.txt" || rc=$?
        "$py" -m coverage html -q -d "$CI/coverage/html" || true
        echo "coverage: $(tail -1 "$CI/coverage/report.txt" | awk '{print $NF}') of statements and branches" \
             "(helper.py $(awk '$1 ~ /helper\.py$/ {print $NF}' "$CI/coverage/report.txt")); .ci/coverage/report.txt," \
             ".ci/coverage/html/index.html"
    else
        "${ISOLATE[@]}" env "${env[@]}" "$py" -m pytest -q -p no:cacheprovider --basetemp="$tmp/t" || rc=$?
    fi
    rm -rf "$tmp"
    return $rc
}

# what the linters found (they exit 1 when they find anything: the ratchet decides)
ruff_json() { "$TOOLS/ruff" check --output-format json --quiet src tests packaging || [ $? = 1 ]; }
mypy_out() { "$TOOLS/mypy" --no-error-summary --no-pretty 2>&1 || [ $? = 1 ]; }

run_step() {  # step: its log in .ci/logs, its result in RESULT
    local step=$1 log="$CI/logs/$1.log" rc=0
    case "$step" in
        lint)
            { ruff_json | "$TOOLS/python" packaging/ci/ratchet.py ruff packaging/ci/ruff-baseline.txt || rc=1
              "$TOOLS/python" packaging/ci/check_timeouts.py src packaging \
                  --baseline packaging/ci/timeouts-baseline.txt || rc=1; } > "$log" 2>&1 ;;
        types)
            mypy_out | "$TOOLS/python" packaging/ci/ratchet.py mypy packaging/ci/mypy-baseline.txt > "$log" 2>&1 \
                || rc=1 ;;
        shell)
            "$TOOLS/shellcheck" -x -P packaging/appimage -f gcc packaging/*.sh packaging/appimage/*.sh \
                packaging/appimage/AppRun > "$log" 2>&1 || rc=1 ;;
        web)
            web_deps > "$log" 2>&1 || rc=1 ;;
        dev)
            local py
            if py="$(dev_python)"; then
                { "$py" --version; suite dev "$py"; } > "$log" 2>&1 || rc=1
            else
                echo "no dev venv: python3 -m venv --system-site-packages .venv && .venv/bin/pip install -e '.[dev]'" \
                    "(or DEV_PYTHON=path)" > "$log"; rc=1
            fi ;;
        py3.12)
            { "$CI/py3.12/bin/python" --version; suite "$step" "$CI/py3.12/bin/python" coverage; } > "$log" 2>&1 || rc=1 ;;
        py3.*)
            { "$CI/$step/bin/python" --version; suite "$step" "$CI/$step/bin/python"; } > "$log" 2>&1 || rc=1 ;;
    esac
    RESULT[$step]=$rc
    return 0
}

if [ "$mode" = lock ]; then
    before="$(date -u -d '14 days ago' +%Y-%m-%dT00:00:00Z)"      # nothing newer than two weeks
    uv pip compile -q --universal --python-version 3.11 --generate-hashes --exclude-newer "$before" \
        packaging/ci/requirements.in -o packaging/ci/requirements.lock
    npm install --prefix tests/web --package-lock-only --ignore-scripts --no-audit --no-fund --before "${before%%T*}"
    git --no-pager diff --stat -- packaging/ci/requirements.lock tests/web/package-lock.json
    exit 0
fi
if [ "$mode" = release ]; then
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "--release checks what is committed: commit or set aside the changes first" >&2; exit 2
    fi
    command -v podman >/dev/null || { echo "--release builds the AppImage: install Podman" >&2; exit 2; }
fi

venv 3.12 > /dev/null                     # the tools' venv
if [ "$mode" = rebaseline ]; then
    ruff_json | "$TOOLS/python" packaging/ci/ratchet.py ruff packaging/ci/ruff-baseline.txt --write
    mypy_out | "$TOOLS/python" packaging/ci/ratchet.py mypy packaging/ci/mypy-baseline.txt --write
    "$TOOLS/python" packaging/ci/check_timeouts.py src packaging --write-baseline packaging/ci/timeouts-baseline.txt
    git --no-pager diff --stat -- packaging/ci/*-baseline.txt
    exit 0
fi

# the venvs first, one at a time (uv's cache is shared), then the quick steps, then the suites N at a time
for s in "${steps[@]}"; do
    case "$s" in py3.*) venv "${s#py}" > /dev/null ;; esac
done
need_web=0 have_web=0
for s in "${steps[@]}"; do
    case "$s" in dev|py3.*) need_web=1 ;; web) have_web=1 ;; esac
done
[ "$need_web" = 0 ] || [ "$have_web" = 1 ] || steps=(web "${steps[@]}")      # the suites need jsdom
suites=()
for s in "${steps[@]}"; do
    case "$s" in
        dev|py3.*) suites+=("$s") ;;
        *) printf '%-8s ' "$s"; run_step "$s"; [ "${RESULT[$s]}" = 0 ] && echo ok || echo "FAILED (.ci/logs/$s.log)" ;;
    esac
done
if [ ${#suites[@]} -gt 0 ]; then
    if [ ${#ISOLATE[@]} -eq 0 ] && [ "$jobs" -gt 1 ]; then
        echo "note: bubblewrap can't give each suite a runtime folder of its own here: one suite at a time"
        jobs=1
    fi
    echo "test suites (${suites[*]}), $jobs at a time: a few minutes each; logs in .ci/logs/"
    declare -A PIDS
    for s in "${suites[@]}"; do
        while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do wait -n || true; done
        ( run_step "$s"; exit "${RESULT[$s]}" ) &
        PIDS[$s]=$!
    done
    for s in "${suites[@]}"; do
        if wait "${PIDS[$s]}"; then RESULT[$s]=0; else RESULT[$s]=1; fi
        printf '%-8s %s  %s\n' "$s" "$([ "${RESULT[$s]}" = 0 ] && echo ok || echo FAILED)" \
            "$(grep -E '^[0-9]+ (passed|failed)|[0-9]+ (passed|failed).* in [0-9.]+s|^coverage:' "$CI/logs/$s.log" \
               | tr '\n' ' ' | sed 's/=//g')"
    done
fi

if [ "$mode" = release ]; then
    for s in build test-extracted test-mounted; do
        printf '%-8s ' "$s"
        case "$s" in
            build) packaging/build-appimage.sh check > "$CI/logs/$s.log" 2>&1 ;;
            test-extracted) packaging/test-appimage.sh > "$CI/logs/$s.log" 2>&1 ;;
            test-mounted) packaging/test-appimage.sh --mounted > "$CI/logs/$s.log" 2>&1 ;;
        esac && RESULT[$s]=0 || RESULT[$s]=1
        [ "${RESULT[$s]}" = 0 ] && echo ok || echo "FAILED (.ci/logs/$s.log)"
        [ "${RESULT[$s]}" = 0 ] || [ "$s" != build ] || break      # nothing to test without a build
    done
fi

failed=()
for s in "${!RESULT[@]}"; do [ "${RESULT[$s]}" = 0 ] || failed+=("$s"); done
if [ ${#failed[@]} -gt 0 ]; then
    echo "FAILED: ${failed[*]} (logs in .ci/logs/)" >&2
    exit 1
fi
echo "All checks passed."
