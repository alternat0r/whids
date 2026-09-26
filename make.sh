#!/usr/bin/bash

RELEASE=${GOPATH}/release
VERSION=$(git tag | tail -n 1)
TOOLS="utilities"

function check_err() {
    if [[ $? != 0 ]]
    then
        exit $?
    fi
}

echo "[1/4] Building Sysmon (download and configuration)"
pushd $TOOLS/sysmon && make -j 8 $@ || check_err && popd

echo "[2/4] Building WHIDS agent"
pushd $TOOLS/whids && make -j 8 $@ || check_err && popd

echo "[3/4] Building WHIDS manager"
pushd $TOOLS/manager && make -j 8 $@ || check_err && popd

echo "[4/4] Packaging release bundle (whids-${VERSION}-release-bundle.zip)"
pushd ${RELEASE}
# Remove previous bundles
rm *.zip
7z a -tzip whids-${VERSION}-release-bundle.zip *

popd


