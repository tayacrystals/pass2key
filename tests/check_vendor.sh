#!/bin/sh
# Verifies that the vendored Monocypher files still match the checksums
# recorded when they were imported. This does not prove the files match
# upstream (that needs network access); it proves nobody edited them locally
# by accident. See vendor/monocypher/README.md.

set -u

cd "$(dirname "$0")/../vendor/monocypher" || exit 1

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "check_vendor: sha256sum not available, skipping" >&2
    exit 0
fi

if sha256sum -c --quiet SHA256SUMS; then
    echo "check_vendor: ok"
    exit 0
fi

echo "check_vendor: FAIL: vendored files do not match SHA256SUMS" >&2
exit 1
