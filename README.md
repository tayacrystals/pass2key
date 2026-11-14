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

> `pass2key` will interactively prompt for the passphrase

Options:

| Option | Effect |
|--------|--------|
| `--public` | Output the public key only |
| `--expect <fingerprint>` | Check the derived key against your known fingerprint; output nothing and fail if it differs (e.g. a typo in the passphrase) |
| `--selftest` | Run a self-test against known values |

Requirements at run time: a 64-bit system with at least 4 GiB of free memory. Derivation is deliberately slow; expect it to take several minutes.

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
shred -u primary.asc subkeys.gpg
```

**Later (renew subkeys, revoke, etc)**
 
Run `pass2key` again with the same email and passphrase, import the output,
perform the operation in gpg, then delete the primary secret key again as above. The fingerprint never changes.

Pass your fingerprint with `--expect`, so a mistyped passphrase gives a clear
error instead of a different, valid-looking key:

```sh
pass2key --expect "$FPR" you@example.org > primary.asc
```

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
 
**What this tool does not protect against:**
 
- A weak, reused or human-chosen passphrase.
- Malware on the machine where you run it.
- You writing down, or otherwise leaking your passphrase.
- You forgetting your passphrase.

## Building
 
The only dependency is [Monocypher](https://monocypher.org), vendored in
`vendor/`. Any C99 compiler works:
 
```sh
cc -std=c99 -O2 -o pass2key \
   src/*.c vendor/monocypher/monocypher.c \
   vendor/monocypher/monocypher-ed25519.c
./pass2key --selftest
```
 
Layout:
 
```
src/        pass2key source (main, OpenPGP packets, armor, SHA-1)
vendor/     Monocypher 4.x (Argon2id, Ed25519, SHA-512), unmodified
tests/      development test programs
vectors/    test vectors
README.md   this file
SPEC.md     the specification
LICENSE     MIT licence
```
 
Release archives include the source, the vendored dependencies, the
specification, the test vectors and static binaries for common platforms.

## License

pass2key is released under the [MIT License](LICENSE).

Monocypher in `vendor/` is dual-licensed 2-clause BSD or CC0-1.0 (see
`vendor/monocypher/LICENCE.md`); pass2key uses the CC0-1.0 option, so
redistributing pass2key adds no notice requirement beyond the MIT one.
