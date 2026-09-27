#!/usr/bin/env bash
#
# ci/build.sh - WHIDS CI gate (run from the repository root).
#
# On a Windows runner (the agent links golang-win32 and the Windows service
# APIs, so it only compiles there) this:
#   1. runs `go vet` across the whole module, and
#   2. cross-compiles both binaries for every supported target.
#
# The whids and whids-man binaries need a version.go that the release
# makefiles generate on the fly; it is generated here so the sources build
# with no out-of-band step, then removed.
#
# `go test` is intentionally not part of this gate: the existing suite depends
# on data fixtures (data/events.json, a fake osqueryi binary, Sysmon) that are
# not committed, so most packages fail in test init() on a clean checkout
# (a pre-existing condition, independent of this change).
#
# Usage: bash ci/build.sh

set -uo pipefail

VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-dev}"
COMMITID="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

for src in utilities/whids utilities/manager; do
    printf 'package main\n\nconst(\n    version="%s"\n    commitID="%s"\n)\n' \
        "$VERSION" "$COMMITID" > "$src/version.go"
done
cleanup() { rm -f utilities/whids/version.go utilities/manager/version.go; }
trap cleanup EXIT

rc=0
mkdir -p build

# 1. static analysis across the whole module
echo ">>> go vet ./..."
go vet ./... || rc=1

# 2. cross-compile. The agent is Windows-only; the manager builds for all.
build() { # $1 = main package, $2 = os, $3 = arch, $4 = name
    GOOS="$2" GOARCH="$3" go build -o "build/$4-$2-$3" "$1" || { echo "build failed: $1 ($2/$3)"; rc=1; }
}

for target in windows/386 windows/amd64 linux/386 linux/amd64 darwin/amd64; do
    os="${target%/*}"; arch="${target#*/}"
    echo ">>> go build $os/$arch"
    if [ "$os" = "windows" ]; then
        build ./utilities/whids "$os" "$arch" whids
    fi
    build ./utilities/manager "$os" "$arch" whids-man
done

echo ">>> done (rc=$rc)"
exit $rc
