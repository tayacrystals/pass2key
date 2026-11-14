# Test vectors

`--selftest` covers the primitive vectors:

- RFC 9106 §5.3, Argon2id version 19, with memory 32 KiB, 3 passes,
  4 lanes, 32-byte password, 16-byte salt, 8-byte secret, 12-byte
  associated data and a 32-byte tag.
- RFC 8032 §7.1, Ed25519 test 1 (key generation, signing and verification
  of the empty message).
- FIPS 180-4 SHA-1 `abc` vector, used for v4 key fingerprints.

`e2e-test-example.org.json` is an end-to-end vector. It records the
normalized email, passphrase, 32-byte seed, fingerprint and the corresponding
complete armored secret-key block in `e2e-test-example.org.asc`.

The seed was independently reproduced with the reference `libargon2`
implementation. The armored output was imported into GnuPG 2.4.9, which
reported the expected fingerprint and one good self-signature.
