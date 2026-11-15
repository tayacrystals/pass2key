# Vendored Monocypher

Monocypher 4.0.3, downloaded from <https://monocypher.org/>.

The unmodified core and optional `monocypher-ed25519` source and header
files, along with `LICENCE.md`, come from the official release archive:

- URL: <https://monocypher.org/download/monocypher-4.0.3.tar.gz>
- SHA-256: `8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`

Monocypher and its add-on are dual-licensed under BSD-2-Clause or CC0-1.0;
see `LICENCE.md`.

`SHA256SUMS` records the checksums of the vendored files as imported. It is a
local file, not part of the Monocypher release; `make check-vendor` (also run
by `make check`) uses it to detect accidental local edits. It cannot prove the
files match upstream, which needs the archive above.
