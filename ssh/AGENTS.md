# AGENTS.md

Guidance for AI agents (and humans) working in this repository.

## Project overview

This directory is the **`github.com/malivvan/crypto/ssh`** package of the
`github.com/malivvan/crypto` module — a minimal, hardened SSH server *and
client* library for Go.

- The root package `ssh` (`*.go` at this directory's root) is the public API
  for both roles. Server side: `Server`, `ServerSession`, `Context`,
  functional options (`PasswordAuth`, `PublicKeyAuth`, `HostKeyFile`, ...),
  PTY handling, port forwarding, agent forwarding and subsystems. Client side:
  `Dial`, `DialContext`, `NewClientConn`/`NewClient`, `Client`,
  `ClientConfig`/`Config`, `ClientSession`, the `AuthMethod` constructors
  (`Password`, `PublicKeys`, `KeyboardInteractive`, ...) and the host key
  callbacks (`FixedHostKey`, `CertChecker.CheckHostKey`,
  `InsecureIgnoreHostKey`).
- The root package's client, key, certificate and wire-level types are
  **aliases** of the `internal` ones (`type Client = gossh.Client`, ...), so
  they are one and the same type and values round-trip without conversion.
  Keep new public identifiers on that pattern: put the implementation and its
  `ssh:` error strings in `internal/`, and the alias/wrapper plus the doc
  comment in the root package.
- `internal/` contains a stripped SSH protocol implementation (package
  `internal`): transport, handshake, key exchange, auth, channels, sessions
  and the client the root package re-exports. It is not importable from
  outside this subtree, which is why the aliases above exist.
- `agent/` implements the OpenSSH agent protocol for Ed25519 keys.
- PTY support — Unix terminals, terminal modes and window sizes, and Windows
  ConPTY — comes from the external `github.com/malivvan/pty` module; nothing
  platform specific for it is duplicated here.
- `middleware/` provides reusable server middleware (access control, rate
  limiting, logging, panic recovery, scp servers) plus the `Chain` helper.
- The bcrypt_pbkdf KDF for encrypted OpenSSH private keys lives in the
  `pbkdf2/` package at the module root (its Blowfish primitive is
  `pbkdf2/blowfish.go`); the transport's ChaCha20/Poly1305 primitives also live
  at the module root. None of these are part of this directory's `internal/`.

## Hard constraints (do not violate)

1. **Algorithm whitelist.** The only supported algorithms are:

   - KEX: `curve25519-sha256`, `mlkem768x25519-sha256`
   - CERT: `ssh-ed25519-cert-v01@openssh.com`, `sk-ssh-ed25519-cert-v01@openssh.com`
   - CIPHER: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`
   - MAC: `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`

   Never re-add RSA/DSA/ECDSA keys, SHA-1, CBC/CTR/RC4 ciphers, legacy
   Diffie-Hellman or ECDH key exchange, GSSAPI, or any other algorithm or
   documentation for them. The canonical lists live in `internal/common.go`
   (`supportedKexAlgos`, `supportedCiphers`, `supportedMACs`,
   `supportedHostKeyAlgos`, `supportedPubKeyAuthAlgos`) and the
   implementations in `internal/kex.go`, `internal/mlkem.go`,
   `internal/cipher.go`, `internal/mac.go`, `internal/keys.go` and
   `internal/certs.go`.

2. **Host keys are Ed25519 certificates.** The client only offers the two
   CERT algorithms, so server host keys must be Ed25519 certificates. The
   root package's default `generateSigner()` (util.go) creates a self-signed
   Ed25519 host certificate. Test fixtures use `testSigners["cert"]` for
   `AddHostKey`; plain Ed25519 signers are for user auth only.

3. **Module identity.** The module path is `github.com/malivvan/crypto` (this
   package: `github.com/malivvan/crypto/ssh`) and the author is `malivvan`.
   Source files, package docs and per-package READMEs must not reference the
   repositories this code was derived from; upstream attribution belongs
   solely in the module-level `README.md` (Credits) and `LICENSE`
   (third-party notices). Preserved BSD headers naming The Go Authors (in
   `internal/`) stay as they are.

4. **No dead weight in `internal/`.** Only code actually used by this
   repository belongs in `internal/`. Do not re-add the removed `knownhosts`,
   `terminal`, `test`, `testenv` or SFTP subsystem packages, and do not add
   imports of any external SSH implementation.

## Build, test, lint

```sh
make help      # list targets
make test      # go test -race ./...        (extra args: make test ARGS="-run X")
make fmt       # gofmt -w (requires go; gofumpt/goimports are not configured here)
make lint      # golangci-lint run (optional; no repository .golangci.yml)
make lint-fix  # golangci-lint run --fix
make tidy      # go mod tidy
```

- Always run `make test` (or `go test -race ./...`) before finishing a
  change; `go vet ./...` must be clean.
- Code is formatted with `gofmt` (`gofmt -l .` must be empty); Go 1.27+ is
  required. Linting with golangci-lint is optional and uses its defaults,
  since this package does not ship a `.golangci.yml` (wrapcheck is therefore
  not enforced: the root package intentionally returns errors from the
  protocol layer unchanged so callers can match them with
  `errors.Is`/`errors.As`).
- Tests that need a certificate host key use the `testSigners["cert"]`
  fixture from `internal/testdata_test.go`; `testSigners["rsa"]`,
  `["ecdsa"]`, `["dsa"]`, `["ed25519"]` are plain Ed25519 fixtures (legacy
  names kept to minimize churn in ported tests).

## Conventions

- Root package doc is in `ssh.go`; keep it in sync with the algorithm table
  in `README.md`.
- Comments and error messages in `internal/` keep the original `ssh:` error
  prefix and BSD-style copyright headers.
- Any example code must compile against the public root package only
  (no `github.com/malivvan/crypto/ssh/internal` imports — that is an internal
  package; the root package re-exports the supported client API).
- New client-facing API belongs in the root package (`client.go`,
  `client_auth.go`, `wrap.go`, `certs.go`, `wire.go`, `errors.go`) and must be
  documented in `README.md` (see "Using `ssh` as a client") and covered by a
  test — `client_test.go` dials a real loopback server without touching
  `internal/`.
- When adding tests, prefer table-driven tests and `t.Run` subtests, and do
  not call `t.Fatal` from non-test goroutines (report errors through
  channels); `go vet` enforces this.

## Known deliberate limitations

- The client cannot connect to servers presenting plain (non-cert) host
  keys, by design: only the two Ed25519 CERT algorithms are offered. Verify
  host keys with `FixedHostKey` or `CertChecker.CheckHostKey`.
- The server-side session interface is `ServerSession` (not `Session`), so
  that `ClientSession` can name the client session type without a clash.
- AEAD ciphers mean no separate MAC is negotiated on the wire; the two HMAC
  algorithms remain only as configurable/reportable entries.
