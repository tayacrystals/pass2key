## Specification
 
Everything needed to reimplement `pass2key` without reading its source.
Notation: `||` is concatenation, `0x00` is a single byte, all integers are
big-endian.
 
### 1. Inputs
 
Both inputs must consist of **printable ASCII** (0x20–0x7E) plus the tab
(0x09). Tabs are separators: they may appear anywhere in the passphrase and
only at the ends of the email. Every other byte, including DEL (0x7F) and any
byte above 0x7E, is rejected, not silently changed.

**Email** (`E`):

1. Remove leading and trailing spaces and tabs.
2. Convert `A`–`Z` to `a`–`z`.
3. Must contain exactly one `@`, with at least one character before and after it.
4. The remaining bytes are used verbatim: there is no interior whitespace
   normalization and no further validation. In particular `a@b c` is accepted
   as-is, while a tab inside the email is rejected.
**Passphrase** (`P`):
 
1. Remove leading and trailing spaces and tabs.
2. Replace every run of spaces and tabs with a single space (0x20).
3. Convert A–Z to a–z (Diceware convention; prevents lockout by Caps Lock or automatic capitalization).
4. Must contain at least 4 space-separated words.
### 2. Key derivation
 
```
salt = "pass2key" || 0x00 || E
seed = Argon2id(password = P, salt = salt,
                memory = 4194304 KiB (4 GiB),
                passes = 100,
                lanes  = 1,
                version = 0x13,
                secret = empty, associated data = empty,
                output length = 32)
```

> We prefix the salt with "pass2key" to avoid accidental collisions with other Argon2id users. And so that the salt is at least 8 bytes, as required by Argon2. The salt is public and does not need to be secret.
 
`seed` is the Ed25519 private key (RFC 8032 §5.1.5). `A` is the
corresponding 32-byte public key.
 
### 3. OpenPGP encoding
 
OpenPGP version 4 (RFC 4880 / RFC 9580), public-key algorithm 22
(EdDSALegacy) on Ed25519. All packets use OpenPGP (new) format headers.
 
**Constants**
 
| Item              | Value                                            |
|-------------------|--------------------------------------------------|
| Creation time `T` | `0x00000000` (Unix epoch 0)                      |
| Curve OID         | `09 2B 06 01 04 01 DA 47 0F 01` (length-prefixed)|
| Hash algorithm    | 10 (SHA-512)                                     |
 
**Public key body** (`PK`):
 
```
0x04 || T || 0x16 || OID || MPI(0x40 || A)
```
 
The MPI has a bit count of 263 (`0x01 0x07`).
 
**Fingerprint:** `SHA-1(0x99 || len16(PK) || PK)`. **Key ID:** its last
8 bytes.
 
**Secret-Key packet (tag 5):**
`PK || 0x00 || MPI(seed) || checksum`, where `0x00` means "not encrypted",
`MPI(seed)` is the seed as an MPI (whole leading zero octets dropped, length
field set to the exact bit count) and `checksum` is the sum modulo 65536 of
the MPI's bytes **including its two-octet bit-count prefix**, but not of the
`0x00` octet. For the vector in `vectors/` the sum of the 32 seed octets is
`0x0DE0` and the encoded checksum is `0x0DE1`.
 
**User ID packet (tag 13):** the bytes of `E`.
 
**Signature packet (tag 2)**, version 4, type `0x13` (positive
certification), algorithm 22, hash 10.
 
Hashed subpackets, in this order:
 
| Type | Name                     | Value                                |
|------|--------------------------|--------------------------------------|
| 33   | Issuer fingerprint       | `0x04 || fingerprint`                |
| 2    | Signature creation time  | `T`                                  |
| 27   | Key flags                | `0x01` (certify only)                |
| 11   | Preferred symmetric      | `09 07` (AES-256, AES-128)           |
| 21   | Preferred hash           | `0A 08` (SHA-512, SHA-256)           |
| 22   | Preferred compression    | `00` (uncompressed)                  |
| 30   | Features                 | `01` (modification detection)        |
 
Unhashed subpackets: type 16 (Issuer key ID) = Key ID.
 
Signed data:
 
```
H = SHA-512( 0x99 || len16(PK) || PK
          || 0xB4 || len32(E) || E
          || sig_header_and_hashed_subpackets
          || 0x04 || 0xFF || len32(sig_header_and_hashed_subpackets) )
```
 
The Ed25519 signature over `H` (as a 64-byte message) gives `R || S`. The
signature packet carries the two leftmost bytes of `H` first (the v4 "left 16
bits of the signed hash" field, RFC 4880 §5.2.3), then `MPI(R) || MPI(S)`.
 
**Output order:** Secret-Key packet, User ID packet, Signature packet.
With `--public`, the Secret-Key packet is replaced by a Public-Key packet
(tag 6) containing `PK`.
 
### 4. ASCII armor
 
Standard OpenPGP armor: header `-----BEGIN PGP PRIVATE KEY BLOCK-----` (or
`PUBLIC` with `--public`), one empty line, base64 in lines of 64 characters,
a CRC-24 checksum line (`=` + 4 base64 characters) and the matching END line.
No armor headers. Line endings are LF.

### 5. Fingerprint check (`--expect`)

The expected fingerprint is given as 40 hexadecimal digits. Spaces are
ignored and letters may be upper or lower case; any other input is rejected.

After derivation, the implementation compares the computed fingerprint
(section 3) with the expected one. If they differ, it writes **nothing** to
standard output, reports the mismatch, and exits with a non-zero status. If
they match, output is exactly as without `--expect`.

This also lets a future tool recognize keys made by this derivation: deriving
with every known method and comparing fingerprints identifies the one that was
used, without the user having to remember anything else.
 
---
 
## Test vectors
 
`vectors/` contains:
 
- **Primitive vectors:** RFC 9106 §5.3 (Argon2id) and RFC 8032 §7.1
  (Ed25519). These run in `--selftest`.
- **End-to-end vectors:** email, passphrase, seed (hex), fingerprint and the
  complete armored output. These were produced by this implementation and
  checked against an independent implementation (Python `argon2-cffi` +
  `PyNaCl` + manual packet encoding) and by importing the output into GnuPG and
  Sequoia.
A correct reimplementation reproduces every end-to-end vector byte for byte.
 
---
 
## Design decisions
 
**Why deterministic?** Nothing to back up except a passphrase you can
remember and write on paper. The key cannot be lost with a disk.
 
**Why certify-only?** The primary key is the long-lived identity. Everything
used day to day (signing, encryption, SSH) lives in subkeys, which can expire,
rotate and be stored normally. The primary is recreated only when needed.
 
**Why creation time 0?** The fingerprint covers the creation time, so it must
be fixed. Epoch 0 is the obvious constant. Keys show as created on 1970-01-01;
that is cosmetic.
 
**Why OpenPGP v4 and not v6?** v4 Ed25519 keys work in GnuPG, Sequoia,
OpenPGP.js and practically everything else. v6 keys (RFC 9580) are not
supported by GnuPG.
 
**Why the salt prefix?** Argon2 requires a salt of at least 8 bytes, and the
prefix guarantees that no other tool derives the same bytes from the same
email and passphrase. It is a fixed constant, not a version number: the
derivation is frozen forever, so there is no version to remember.
 
**Why `--expect`?** A typo in the passphrase silently produces a different,
perfectly valid key. Comparing against the public fingerprint is the only way
to detect that, and it costs nothing since the fingerprint is computed anyway.

**Why ASCII-only input?** Unicode normalization needs large tables that would
complicate a small, long-lived C program, and the same-looking text can be
typed as different bytes. Diceware words and almost all email addresses are
ASCII.
 
**Why C99 and Monocypher?** A single small, audited, public-domain library
and a language that will compile anywhere for decades. No package manager, no
network, no build system.
 
**Why such heavy Argon2id parameters?** So that a 4-word Diceware passphrase,
which people can actually remember, is still very expensive to brute-force.
