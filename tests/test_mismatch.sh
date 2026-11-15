#!/bin/sh
# Slow end-to-end tests for the --expect guarantee (SPEC section 5) and for the
# production derivation. Each run performs the full 4 GiB, 100-pass Argon2id
# derivation and therefore takes minutes and needs ~4.1 GiB of free memory.
#
# Run with: make check-slow

set -u

BIN=${1:-build/pass2key}
VECTORS=${2:-vectors}
[ -x "$BIN" ] || { echo "test_mismatch: no binary at $BIN" >&2; exit 1; }

expected_fpr=56F0DCE8653661D1F0809D1C5A41A96CE232B7D6
wrong_fpr=0000000000000000000000000000000000000000
passphrase="correct horse battery staple"
status=0

tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT

echo "test_mismatch: deriving the vector key (several minutes)..." >&2
printf '%s\n' "$passphrase" | "$BIN" --expect "$expected_fpr" \
    test@example.org >"$tmp" 2>/dev/null
exit_code=$?
if [ "$exit_code" -ne 0 ]; then
    echo "test_mismatch: FAIL: --expect with the right fingerprint exited $exit_code" >&2
    status=1
elif ! cmp -s "$tmp" "$VECTORS/e2e-test-example.org.asc"; then
    echo "test_mismatch: FAIL: output is not byte-identical to the vector" >&2
    status=1
else
    expected_seed=$(sed -n 's/.*"seed": "\([0-9a-f]*\)".*/\1/p' \
        "$VECTORS/e2e-test-example.org.json")
    derived_seed=$(python3 tests/extract_seed.py "$tmp") || {
        echo "test_mismatch: FAIL: cannot extract the seed" >&2
        derived_seed=""
        status=1
    }
    if [ "$derived_seed" != "$expected_seed" ]; then
        echo "test_mismatch: FAIL: seed $derived_seed != $expected_seed" >&2
        status=1
    fi
fi

echo "test_mismatch: deriving again with a wrong fingerprint (several minutes)..." >&2
printf '%s\n' "$passphrase" | "$BIN" --expect "$wrong_fpr" \
    test@example.org >"$tmp" 2>/dev/null
exit_code=$?
bytes=$(wc -c <"$tmp" | tr -d ' ')
if [ "$exit_code" -eq 0 ]; then
    echo "test_mismatch: FAIL: mismatch exited 0" >&2
    status=1
elif [ "$bytes" -ne 0 ]; then
    echo "test_mismatch: FAIL: mismatch wrote $bytes bytes to stdout" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "test_mismatch: ok"
fi
exit "$status"
