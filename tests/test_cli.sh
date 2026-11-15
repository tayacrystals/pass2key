#!/bin/sh
# Cheap CLI contract tests. Nothing here runs Argon2: every case fails before
# the derivation, so the whole file finishes in well under a second.
#
# The one property that cannot be checked cheaply is "a fingerprint mismatch
# writes nothing to stdout"; see tests/test_mismatch.sh (`make check-slow`).

set -u

BIN=${1:-build/pass2key}
[ -x "$BIN" ] || { echo "test_cli: no binary at $BIN" >&2; exit 1; }

tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
status=0

# check <expected-exit> <expected-stdout-bytes> <description> <command...>
check() {
    want_exit=$1
    want_bytes=$2
    description=$3
    shift 3

    "$@" >"$tmp" 2>/dev/null </dev/null
    got_exit=$?
    got_bytes=$(wc -c <"$tmp" | tr -d ' ')

    if [ "$got_exit" -ne "$want_exit" ] ||
        { [ "$want_bytes" != "-" ] && [ "$got_bytes" -ne "$want_bytes" ]; }; then
        echo "test_cli: FAIL: $description" >&2
        echo "  exit $got_exit (want $want_exit), stdout $got_bytes bytes (want $want_bytes)" >&2
        status=1
    fi
}

# check_pipe <expected-exit> <expected-stdout-bytes> <description> <stdin> <args...>
check_pipe() {
    want_exit=$1
    want_bytes=$2
    description=$3
    input=$4
    shift 4

    printf '%s\n' "$input" | "$@" >"$tmp" 2>/dev/null
    got_exit=$?
    got_bytes=$(wc -c <"$tmp" | tr -d ' ')

    if [ "$got_exit" -ne "$want_exit" ] ||
        { [ "$want_bytes" != "-" ] && [ "$got_bytes" -ne "$want_bytes" ]; }; then
        echo "test_cli: FAIL: $description" >&2
        echo "  exit $got_exit (want $want_exit), stdout $got_bytes bytes (want $want_bytes)" >&2
        status=1
    fi
}

fpr=56F0DCE8653661D1F0809D1C5A41A96CE232B7D6
digits41=0123456789012345678901234567890123456789012
digits39=012345678901234567890123456789012345678

check 0 - "--help exits 0 and prints help" "$BIN" --help
check 0 - "--help wins over invalid arguments" "$BIN" --help a@b c@d
check 0 - "--selftest prints one line" "$BIN" --selftest

check 2 0 "no arguments" "$BIN"
check 2 0 "empty email" "$BIN" ""
check 2 0 "email without local part" "$BIN" @example.org
check 2 0 "email without domain" "$BIN" user@
check 2 0 "two at signs" "$BIN" a@@b
check 2 0 "DEL in email" "$BIN" "$(printf 'a\177@b')"
check 2 0 "non-ASCII email" "$BIN" "$(printf 'a\200@b')"
check 2 0 "unknown option" "$BIN" --bogus a@b
check 2 0 "GNU-style --expect=" "$BIN" --expect=$fpr a@b
check 2 0 "two positionals" "$BIN" a@b c@d
check 2 0 "two --expect flags" "$BIN" --expect "$fpr" --expect "$fpr" a@b
check 2 0 "--expect without a value" "$BIN" --expect
check 2 0 "--expect too short" "$BIN" --expect ZZZ a@b
check 2 0 "--expect 39 digits" "$BIN" --expect "$digits39" a@b
check 2 0 "--expect 41 digits" "$BIN" --expect "$digits41" a@b
check 2 0 "--expect with a tab" "$BIN" --expect "$(printf '56F0\tDCE8')" a@b
check 2 0 "--selftest with an email" "$BIN" --selftest a@b
check 2 0 "--selftest with --public" "$BIN" --selftest --public

check 1 0 "no passphrase on stdin" "$BIN" a@b
check 1 0 "no passphrase, --expect given" "$BIN" --expect "$fpr" -- a@b
check_pipe 1 0 "three-word passphrase" "one two three" "$BIN" a@b
check_pipe 1 0 "one-word passphrase" "one" "$BIN" a@b
check_pipe 1 0 "blank-only passphrase" "   	 " "$BIN" a@b
check_pipe 1 0 "control byte in passphrase" "$(printf 'one\001 two three four')" "$BIN" a@b
check_pipe 1 0 "non-ASCII passphrase" "$(printf 'one two three fou\303\251')" "$BIN" a@b

# Shell redirection creates the file before the program runs; the program
# itself must still write no bytes on any of these failures.
: >"$tmp"
"$BIN" --expect "$fpr" a@b </dev/null >"$tmp" 2>/dev/null
if [ -s "$tmp" ]; then
    echo "test_cli: FAIL: stdout not empty on failure" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "test_cli: ok"
fi
exit "$status"
