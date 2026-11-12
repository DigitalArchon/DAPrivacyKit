# The local CI and the release steps; packaging/check.sh does the work (packaging/check.sh --help).
# JOBS=N runs that many test suites at once (default 2).
JOBS ?= 2

.PHONY: check quick release-check rebaseline lock hooks appimage appimage-check dev-appimage

check:            ## lint, types, shell scripts, the front-end test, the suite on the dev venv and Python 3.11-3.14
	packaging/check.sh -j $(JOBS)

quick:            ## lint, types, shell scripts and the suite on the dev venv
	packaging/check.sh --quick

release-check:    ## all of check on a clean tree, then the AppImage built twice and compared, and smoke-tested
	packaging/check.sh --release -j $(JOBS)

rebaseline:       ## rewrite the lint and type baselines (packaging/ci/*-baseline.txt) from what is found now
	packaging/check.sh --rebaseline

lock:             ## re-resolve the CI's tool lock and the front-end test's npm lock
	packaging/check.sh --lock

hooks:            ## make git run `make check` before every push
	packaging/install-hooks.sh

appimage:         ## the AppImage of HEAD, in dist/
	packaging/build-appimage.sh build

appimage-check:   ## HEAD built twice from scratch and compared
	packaging/build-appimage.sh check

dev-appimage:     ## the working tree, uncommitted changes included, in dist/dev/ (never a release)
	packaging/build-appimage.sh dev
