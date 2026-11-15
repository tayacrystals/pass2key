# Test vectors

`--selftest` covers the primitive vectors:

- RFC 9106 §5.3, Argon2id version 19, with memory 32 KiB, 3 passes,
  4 lanes, 32-byte password, 16-byte salt, 8-byte secret, 12-byte
  associated data and a 32-byte tag.
- RFC 8032 §7.1, Ed25519 test 1 (key generation, signing and verification
  of the empty message).
- FIPS 180-4 SHA-1 vectors: `abc`, the 56-byte message (which forces the
  two-block padding path) and the 112-byte message, fed both in one call and
  byte by byte. SHA-1 is only used for v4 key fingerprints.

## End-to-end vector

`e2e-test-example.org.json` records the normalized email, passphrase, 32-byte
seed, fingerprint and the two armored files. The derivation parameters are
those of SPEC.md §2: Argon2id, memory 4194304 KiB, 100 passes, 1 lane,
version 0x13, salt `"pass2key" || 0x00 || "test@example.org"`.

- `e2e-test-example.org.asc` — `pass2key test@example.org` (secret key)
- `e2e-test-example.org.public.asc` — the same key with `--public`

`tests/test_e2e.c` reads the seed, email and fingerprint from the JSON, rebuilds
both armored files and compares them byte for byte, so a change to the packet
encoding, the armor or the fingerprint construction fails `make check` in
milliseconds without running Argon2. `make check-slow` additionally derives
from the email and passphrase and compares the full output, and checks that a
wrong `--expect` writes nothing.

## Provenance

The seed in the JSON was reproduced with the reference `libargon2` and with
Python `argon2-cffi`. The armored files were imported into GnuPG 2.4.9
(libgcrypt 1.12.4), which reported the expected fingerprint
`56F0DCE8653661D1F0809D1C5A41A96CE232B7D6` and one good self-signature for each
of them. `make check-slow` re-derives the secret-key file from
the passphrase and compares it byte for byte with the checked-in output, so the
provenance above can be checked again on any machine with GnuPG:

```sh
gpg --import vectors/e2e-test-example.org.public.asc
gpg --check-sigs test@example.org
```
