# pass2key

Derive a deterministic OpenPGP certify-only primary key from an email address and a passphrase.

The same email and passphrase always produce the same key, byte for byte, on any machine, today or in thirty years. You never need to back up the key itself: the passphrase is the backup. Signing, encryption and authentication subkeys are created afterwards with ordinary OpenPGP tools and can be rotated freely, while the primary key (your identity) stays the same forever.

```
email + passphrase ──Argon2id──> 32-byte seed ──Ed25519--> OpenPGP primary key
```

## Usage

```sh
pass2key you@example.org > key.asc
gpg --import key.asc
```

`pass2key` prompts for the passphrase with terminal echo disabled. If standard
input is not a terminal it reads the passphrase from standard input instead and
says so on standard error; there is no prompt then. That is how scripts feed it,
but note that `echo passphrase | pass2key ...` leaves the passphrase in your
shell history, so prefer a here-document or a file with restricted permissions.

Options:

| Option | Effect |
|--------|--------|
| `--public` | Output the public key only |
| `--expect <fingerprint>` | Check the derived key against your known fingerprint; output nothing and fail if it differs (e.g. a typo in the passphrase). Spaces are ignored and hex letters may be either case |
| `--selftest` | Run a self-test against known values; must be the only argument |
| `-h`, `--help` | Print usage and exit successfully |
| `--` | End of options; every later argument is treated as the email |

Exit status: `0` on success, `2` for a usage error (unknown option, missing or
malformed argument, invalid email) and `1` for every other failure, including
an invalid passphrase and a `--expect` mismatch.

Requirements at run time: a 64-bit POSIX system with at least 4 GiB of free
memory. Derivation is deliberately slow; expect it to take several minutes. Pressing
Ctrl-C during the derivation aborts the run and writes nothing to standard
output, but the work is lost.

## Input normalization

Both inputs are normalized before derivation, so trivial typing differences do
not change the resulting key:

| Input | Normalization |
|-------|---------------|
| Email | leading and trailing spaces and tabs removed; `A`-`Z` lowercased |
| Passphrase | leading and trailing spaces and tabs removed; every run of spaces and tabs collapsed to a single space; `A`-`Z` lowercased |

What this means in practice:

- Both inputs are case-insensitive, and the passphrase ignores spacing
  differences: `Correct   HORSE Battery  staple` derives the same key as
  `correct horse battery staple`. Caps Lock, an autocapitalizing keyboard or an
  editor that rewraps whitespace cannot cost you your key.
- The email must contain exactly one `@`, with at least one character on each
  side of it.
- The passphrase must contain at least four words, separated by spaces or tabs.
- Only printable ASCII (0x20-0x7E) is accepted, plus tabs as separators inside
  the passphrase; anything else is rejected rather than silently altered.
  Unicode normalization tables are large, and visually identical text can be
  encoded as different bytes; Diceware words and essentially all email
  addresses are ASCII.

The normative rules are in [`SPEC.md`](SPEC.md).

## Choosing a passphrase

Use [Diceware](https://theworld.com/~reinhold/diceware.html): roll real dice and pick words from a 7776-word list (e.g. the [EFF large wordlist](https://www.eff.org/dice)).

- 4 words is the minimum. The tool refuses shorter passphrases.
- 5 or more words is recommended if you expect a well-funded adversary to target you specifically over decades (see Security model).
- Never invent the words yourself or reuse a passphrase from anywhere else.
- Remember that a lost passphrase means a lost key. There is no recovery. So choose a passphrase you can remember.

## Recommended workflow
 
The primary key only *certifies*: it signs your User ID and your subkeys. Keep it offline and recreate it only when you need it.
 
**Initial setup**
 
```sh
pass2key you@example.org > primary.asc
gpg --import primary.asc
FPR=<fingerprint shown by gpg>
 
gpg --quick-add-key "$FPR" ed25519 sign 1y
gpg --quick-add-key "$FPR" cv25519 encr 1y
gpg --quick-add-key "$FPR" ed25519 auth 1y   # optional, e.g. for SSH
 
gpg --armor --export "$FPR" > public.asc      # publish this
gpg --export-secret-subkeys "$FPR" > subkeys.gpg
gpg --delete-secret-keys "$FPR"
gpg --import subkeys.gpg                       # primary is now offline-only
rm primary.asc subkeys.gpg
```

`shred` and friends cannot reliably erase data on SSDs, journaling filesystems
or copy-on-write storage, so it is not recommended here. What matters is that
the files are gone from the machine's reachable storage; the key itself can
always be re-derived from the passphrase.

**Later (renew subkeys, revoke, etc)**
 
Run `pass2key` again with the same email and passphrase, import the output,
perform the operation in gpg, then delete the primary secret key again as above. The fingerprint never changes.

Pass your fingerprint with `--expect`, so a mistyped passphrase gives a clear
error instead of a different, valid-looking key:

```sh
pass2key --expect "$FPR" you@example.org > primary.asc.tmp &&
    mv primary.asc.tmp primary.asc
```

The temporary file matters: the shell truncates `primary.asc` before `pass2key`
runs, so a plain redirect would destroy an existing key file when the check
fails. `set -o noclobber` has the same effect.

Note your fingerprint somewhere after the initial setup. It is public, so it
can be kept anywhere (and it is also on keyservers and in your contacts'
keyrings).
 
**If the passphrase is compromised**
 
Regenerate the key, import it, and publish a revocation:
 
```sh
gpg --gen-revoke "$FPR" | gpg --import
gpg --armor --export "$FPR" > revoked.asc
```

## Security model
 
**What protects your key:** the passphrase alone. The email is public and the algorithm is public, so anyone holding your public key can try passphrases offline, forever, without asking anyone. Argon2id with 4 GiB of memory and 100 passes makes every single guess very expensive.
 
**Rough cost to brute-force one key** (as of 2026, renting GPUs; order of
magnitude only):
 
| Diceware words | Search space      | Expected cost to crack       |
|----------------|-------------------|------------------------------|
| 4              | 7776⁴ ≈ 2^51.7    | ~ one hundred billion US dollars |
| 5              | 7776⁵ ≈ 2^64.6    | ~ one quadrillion US dollars     |
| 6              | 7776⁶ ≈ 2^77.5    | far beyond any feasible cost |
 
Each added word multiplies the attacker's cost by 7776. Hardware gets cheaper
over time, so the margin of a 4-word passphrase shrinks over decades. The
email acts as a per-user salt, so an attacker cannot crack many users at
once: every target needs its own full search.
 
**Process hygiene.** Core dumps are disabled for the process (`RLIMIT_CORE` 0,
and `PR_SET_DUMPABLE` 0 on Linux) so a crash during the derivation cannot leave
the passphrase and the private key in a core file. The 4 GiB Argon2 work area is
not `mlock`ed and can be swapped to disk; if that matters to you, run the tool
inside an encrypted swap or with `mlockall` limits raised. Buffers holding the
passphrase, the seed and the secret key are wiped with a non-eliminable write
before they are freed.

**What this tool does not protect against:**
 
- A weak, reused or human-chosen passphrase.
- Malware on the machine where you run it.
- You writing down, or otherwise leaking your passphrase.
- You forgetting your passphrase.
- Anyone reading swap or memory while the derivation runs.

## Building
 
The only dependency is [Monocypher](https://monocypher.org), vendored in
`vendor/`. Any C99 compiler works:

```sh
make                 # builds build/pass2key
make check           # unit tests, vector comparison, CLI and PTY tests
./build/pass2key --selftest
```

`make check` takes a few seconds and needs no Argon2 derivation. It needs
`python3` (for the PTY tests) and `sha256sum`; the C tests and the vector
comparison run without either. The full production derivation is checked
separately, because it needs 4 GiB and several minutes per run:

```sh
make check-slow      # derives twice: vector must match byte for byte,
                     # and a wrong --expect must write nothing
```

Without `make`, the equivalent single command (note the include path, which is
required because the sources include `monocypher.h` by quoted name):

```sh
cc -std=c99 -O2 -Ivendor/monocypher -o pass2key \
   src/*.c vendor/monocypher/*.c
```

`CFLAGS` from the environment is respected, and the C99 dialect, warning flags
and `-Isrc` are appended to it. Passing `CFLAGS` on the `make` command line
replaces all of that, so add the include flags yourself in that case.

Layout:

```
src/        pass2key source (main, OpenPGP packets, armor, SHA-1, CLI parsing)
vendor/     Monocypher 4.0.3 (Argon2id, Ed25519, SHA-512), unmodified
tests/      unit tests, vector tests, CLI and PTY tests
tests/check.h  CHECK macro that survives -DNDEBUG
vectors/    test vectors (end-to-end private and public output)
README.md   this file
SPEC.md     the specification
LICENSE     MIT licence
```

There is no CI configuration and no release script in this repository; releases
are produced by running `make check` and `make check-slow` on a clean checkout
and archiving the source tree. Static binaries are not built here.

## License

pass2key is released under the [MIT License](LICENSE).

Monocypher in `vendor/` is dual-licensed 2-clause BSD or CC0-1.0 (see
`vendor/monocypher/LICENCE.md`); pass2key uses the CC0-1.0 option, so
redistributing pass2key adds no notice requirement beyond the MIT one.
