# AGENTS.md

Guidance for AI agents and contributors working on this repository.

## Project

`github.com/malivvan/crypto` — an amalgamation, stripped down to **X25519** and
**ed25519**, of what used to be a hardened OpenPGP implementation plus SSH and
minisign functionality. Everything non-modern has been deliberately removed.

The module delivers four distinct capabilities plus a primitive surface:

- `pgp/` — a stripped, hardened OpenPGP implementation (`package pgp`),
  Ed25519-signing and X25519-encryption only, across PGP key versions 4, 5 and 6.
- `ssh/` — a minimal, hardened SSH server (and Ed25519 agent) library built on
  the module's own crypto primitives.
- `minisign/` — the minisign signature format built on the module's Ed25519 key.
- `wallet/` — a high-level, chainable OpenPGP keyring/fluent API built on `pgp/`
  (the former `wallet` OpenPGP package that used to live at the module root / in
  `openpgp/`; re-homed here when the module was renamed).
- Low-level primitive packages at the module root — `ed25519/`, `x25519/`,
  `argon2/`, `blake2b/`, `chacha20/`, `hkdf/`, `pbkdf2/`, `poly1305/`,
  `salsa20/`, `sha3/` — are direct drop-in replacements for the corresponding
  packages of `golang.org/x/crypto`.

Supporting packages live under `internal/` (OCB/EAX, `crypto`-style helpers) and
are not public API.

## Commands

```sh
make build     # go build ./...
make test      # go test ./...
make test-v5   # go test -tags v5 ./...   (PGP v5 key support)
make vet       # go vet ./...
make fmt       # gofmt check; use `make fmt-fix` to rewrite
make lint      # golangci-lint or go vet fallback
make cover     # coverage report
```

The repository's own gates are `make build`, `make vet`, `make test` and
`make fmt` — always run them before finishing a change, and `make test-v5` too
when PGP packet/key parsing was touched. `golangci-lint run ./...` (its standard
set) additionally reports findings inherited from the ported code — `errcheck`
and `staticcheck` style points in `pgp/`, `ssh/internal/`, `sha3/`, `poly1305/`
and the other x/crypto-derived packages — plus the `unused` findings described
below. Do not churn ported files to satisfy those linters: they are kept close
to their originals, with their upstream headers intact.

`golangci-lint run --default=none --enable=unused ./...` reports a handful of
`unused` findings that are known and intentional: the `*Generic` implementations
in `argon2/blamka_generic.go`, `blake2b/blake2b.go`, `internal/math/fp25519/`
and `x25519/curve_generic.go` (and their amd64 counterparts) are the fallbacks
for other architectures, `purego` builds and big-endian targets, and the
`reserved0`/`reserved1` fields in `ssh/internal/streamlocal.go` are part of the
`direct-streamlocal@openssh.com` wire format (serialized reflectively). Do not
delete them on the strength of a lint run.

## Repository layout

- `wallet/` — high-level PGP wallet API (`NewWallet`, encrypt/sign/decrypt/verify,
  key derivation, save/load). Formerly the module root package under `openpgp/`.
  Import path `github.com/malivvan/crypto/wallet`.
- `pgp/` — `package pgp` (formerly `openpgp/`): entities, key generation, packet
  reading/writing, `Encrypt`, `ReadMessage`, `Sign`, `DetachSign`,
  `SymmetricallyEncrypt`, entity/subkey management. Import path
  `github.com/malivvan/crypto/pgp`.
  - `pgp/packet/` — packet layer: `PublicKey`, `PrivateKey`, `Signature`,
    `EncryptedKey`, `Config`, AEAD/MDC symmetric encryption.
  - `pgp/armor/`, `pgp/clearsign/`, `pgp/s2k/`, `pgp/keywrap/`,
    `pgp/errors/` — PGP support packages.
  - `pgp/eddsa/`, `pgp/ecdh/` — key implementations.
  - `pgp/grip/` — OpenPGP key grips.
  - `pgp/agent/` — a gpg-agent-compatible Assuan service plus client/helpers.
- `ssh/` — hardened SSH server (plus an Ed25519 agent and a public client
  re-export), with sub-packages `ssh/agent`, `ssh/client`, `ssh/middleware`. Its
  own `ssh/AGENTS.md` covers the SSH-specific hardening rules. Platform PTY
  support comes from the external `github.com/malivvan/pty` module.
- `minisign/` — the minisign signature format on the wallet's Ed25519 key
  (see "Minisign" below).
- `ed25519/`, `x25519/` — the two key implementations at the module root.
- `argon2/`, `blake2b/`, `chacha20/`, `hkdf/`, `pbkdf2/`, `poly1305/`,
  `salsa20/`, `sha3/` — x/crypto drop-in primitives.
- `internal/` — internal helpers, not public API: `algorithm`, `alias`,
  `bitcurves`, `byteutil`, `conv`, `cryptobyte`, `eax`, `ecc`, `encoding`,
  `math`, `ocb`. AEAD modes `eax`/`ocb` are used by the packet layer;
  `bitcurves` is retained per explicit requirement for future use (e.g. NIST
  curves on older YubiKeys) and is currently unused; do not delete it without
  confirmation.

## Minisign

Minisign is a compact signature format built on Ed25519 and BLAKE2b that
verifies a message against a public key with a corresponding private key. This
repository's `minisign/` package provides that format as a shipping surface of
the module, with two guiding properties:

- **No standalone key material.** The reference minisign tool either generates
  keys or stores them in encrypted files. This package does neither: signing is
  always done with an Ed25519 key that the caller supplies. The easiest and
  idiomatic choice is to reuse the wallet's own OpenPGP signing key (the one
  used for GPG detached signing) via `Wallet.SigningKey()`, so the same key can
  underpin both GPG signatures and minisign. It is a convenient default, not a
  hard rule — `minisign.Sign` accepts any suitable `*ed25519.PrivateKey` (e.g.
  one derived for a separate purpose). There is no `GenerateKey`, no
  `PrivateKey`, and no private-key encryption (scrypt) code.
- **Ecosystem interop is preserved.** The public-key and signature *wire and
  text formats* are unchanged from the reference minisign. A public key derived
  with `minisign.PublicKeyFromEd25519` or a signature produced by
  `minisign.Sign` can be exchanged with the `minisign` command-line tool and
  other minisign implementations; the package includes an interop test that
  verifies a reference-tool signature.

Implementation notes for agents/editors:

- All minisign-specific code stays **inside `./minisign`** so consumers are not
  exposed to a second signature bundle. The wallet package only adds the
  generic `Wallet.SigningKey()` accessor that hands out the Ed25519 signing key.
- Only Ed25519 material is supported; the `EdDSA` and `HashEdDSA` algorithm
  constants in the file header are format identifiers, not new crypto.
- Signatures are over BLAKE2b digests of the message (HashEdDSA path) or the
  raw message; key IDs are the first eight bytes (little-endian) of
  BLAKE2b-256 over the public point.
- The minisign code is **first-party**: it must not reference the upstream
  minisign implementations or their authors in source files, doc comments or
  the package README. Use module BSD headers and a plain `Package minisign`
  doc comment in `./minisign`. Upstream attribution lives only in the
  module-level `README.md` (Credits) and `LICENSE` (third-party notices).

## Crypto primitives (x/crypto drop-ins)

`argon2/`, `blake2b/`, `chacha20/`, `hkdf/`, `pbkdf2/`, `poly1305/`,
`salsa20/` and `sha3/` are ports of the corresponding `golang.org/x/crypto`
packages, kept at the module level so the SSH and PGP stacks use them directly
and so downstream consumers can import `github.com/malivvan/crypto/<pkg>` in
place of `golang.org/x/crypto/<pkg>`. Their API and wire behaviour match the
x/crypto originals; the BSD headers from the Go Authors are retained.

Note: these `_asm` directories (`poly1305/_asm`, `blake2b/_asm`,
`salsa20/_asm`, `argon2/_asm`) are **codegen helpers** that build the SIMD
assembly via `avo`. They are separate nested modules, not part of `go build
./...`, and are only used to regenerate `.s` files. Do not include them in the
main module's formatting/test cycles, and treat their stale module reference
to the previous published name as codegen-only.

## Hard constraints (do not violate)

- Do **not** re-add removed algorithms (RSA, DSA, ElGamal, ECDSA, Ed448, X448,
  ML-DSA, SLH-DSA, ML-KEM-768+X25519, ML-KEM-1024, 3DES, CAST5, IDEA, AES-192,
  AEAD-GCM, MD5/SHA-224/SHA-384/SHA-3 hashes) without an explicit request from
  the maintainer.
- Supported PGP set: EdDSA/Ed25519 (22/27), ECDH/X25519 (18/25),
  AES-128/AES-256 (7/9), AEAD EAX (1) + OCB (2), SHA-256 (8), SHA-512 (10),
  SHA-1 (2, MDC and v4 fingerprints only — never for new signatures or S2K).
  SSH side is Ed25519/X25519 and AEAD ciphers only (see `ssh/AGENTS.md`).
  Note the `sha3/`, `blake2b/`, `chacha20/` etc. packages remain available as
  generic primitives; "removed" refers to their use as PGP algorithms, not to
  the primitive packages themselves.
- S2K: Salted (1), Iterated-and-Salted (3) and Argon2 (4, RFC 9580) are
  supported for key derivation. Simple S2K (0) is parsed for legacy
  compatibility only and must never be generated. Argon2 S2K requires AEAD when
  encrypting private keys.
- New encryption must always be AEAD. MDC is read-only compatibility.
- PGP key versions 4, 5 and 6 must all remain supported for the Ed25519/X25519
  encodings (`-tags v5` enables v5).
- Keep the hardware-key story intact: `packet.NewSignerPrivateKey` must accept
  `crypto.Signer` with an Ed25519 public key, and the
  `packet.X25519Decrypter` interface must keep working for v4 ECDH and v6 X25519.
- Seeds are 32 bytes and interchangeable with other ecosystems (SSH); keep the
  `GenerateKeyFromSeed` constructors.
- The module path is `github.com/malivvan/crypto`; keep all first-party imports
  and doc references on it. Upstream attribution lives only in `README.md`
  (Credits) and `LICENSE` (third-party notices): source files, package docs and
  per-package READMEs must not reference the upstream projects, apart from the
  preserved BSD headers of the original authors. Keep it that way.

## Conventions

- Go 1.27+; `gofmt` for formatting; existing BSD-style file headers are kept.
- Errors: use `errors.UnsupportedError` (PgP) when rejecting algorithms on
  parse, so callers can distinguish "unsupported by this build" from malformed
  data.
- Tests live next to the code (`_test.go`). Prefer roundtrip tests plus at least
  one deterministic vector per primitive; no external test fixtures.
- When adding public API, document it in the relevant package `README.md` and
  cover it with a test.
- Keep `internal/` packages internal; do not export new symbols there without need.
