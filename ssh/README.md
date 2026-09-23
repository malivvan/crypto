# ssh

A minimal, hardened SSH server library for Go.

`github.com/malivvan/crypto/ssh` lets you build SSH servers on top of `net.Listener`
without dealing with the SSH wire protocol yourself. It provides session and
PTY handling, password/public-key/keyboard-interactive authentication,
subsystems, TCP and Unix port forwarding, and agent support (forwarding plus an
Ed25519 SSH agent) — but deliberately supports only a small, modern set of
cryptographic algorithms. Everything else has been removed from the codebase.

## Supported algorithms

| Category | Algorithm | Name |
| --- | --- | --- |
| Key exchange | X25519 with ML-KEM-768 (hybrid, post-quantum) | `mlkem768x25519-sha256` |
| Key exchange | Curve25519 | `curve25519-sha256` |
| Host key certificate | Ed25519 certificate | `ssh-ed25519-cert-v01@openssh.com` |
| Host key certificate | Ed25519 security-key certificate | `sk-ssh-ed25519-cert-v01@openssh.com` |
| Cipher | ChaCha20-Poly1305 | `chacha20-poly1305@openssh.com` |
| Cipher | AES-256-GCM | `aes256-gcm@openssh.com` |
| MAC | HMAC-SHA2-256 (encrypt-then-MAC) | `hmac-sha2-256-etm@openssh.com` |
| MAC | HMAC-SHA2-512 (encrypt-then-MAC) | `hmac-sha2-512-etm@openssh.com` |

User authentication keys are Ed25519 (`ssh-ed25519`) and Ed25519 security keys
(`sk-ssh-ed25519@openssh.com`). Certificates over those key types are
supported for both user and host authentication.

Because only AEAD ciphers are supported, the two MAC algorithms are available
for configuration and reporting but are never negotiated on the wire (AEAD
ciphers provide their own authentication, as specified in RFC 5647).

### Removed

The following are intentionally **not** supported and their implementations
have been removed: RSA, DSA and ECDSA keys (including certificates), SHA-1 and
SHA-1-based MACs, `diffie-hellman-group*` and `ecdh-sha2-*` key exchanges,
AES-CTR/CBC, 3DES and RC4 ciphers, GSSAPI authentication, PROXY protocol
support (`EnableProxyProtocol`), the per-session logger, the `ssh/sftp`
subsystem package, and the `knownhosts` and `terminal` helper packages. The
client half of the library therefore only connects to servers that present an
Ed25519 host key certificate.

## Requirements

- Go 1.27 or later (the ML-KEM hybrid key exchange uses the standard library's
  `crypto/mlkem` package).

## Installation

```sh
go get github.com/malivvan/crypto/ssh
```

## Usage

### Server

```go
package main

import (
    "log"

    "github.com/malivvan/crypto/ssh"
)

func main() {
    ssh.Handle(func(s ssh.Session) {
        // Each connection gets its own session.
        s.Write([]byte("hello world\n"))
        s.Exit(0)
    })

    log.Println("starting ssh server on port 2222...")
    log.Fatal(ssh.ListenAndServe(":2222", nil,
        ssh.PasswordAuth(func(ctx ssh.Context, password string) bool {
            return password == "letmein" // replace with a real check
        }),
    ))
}
```

```sh
ssh -p 2222 localhost
```

When no host key is configured the server generates an Ed25519 host key and
wraps it in a self-signed host certificate on startup, since only Ed25519 host
key certificates are negotiable. Use `ssh.HostKeyFile(path)` or
`ssh.HostKeyPEM(pem)` to load your own key; the `ssh.Server` can also be
configured directly with `AddHostKey`.

### Public key authentication

```go
ssh.Handle(func(s ssh.Session) { ... })

publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
    allowed, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAA..."))
    return err == nil && ssh.KeysEqual(allowed, key)
})

log.Fatal(ssh.ListenAndServe(":2222", nil, publicKeyOption))
```

### Client

The SSH protocol client used by the test suite lives in the `internal`
package. It behaves like a standard Go SSH client and only negotiates the
algorithms listed above, so it only connects to servers that present an
Ed25519 host key certificate. Because Go's `internal` rule prevents code
outside this subtree from importing it, the same API is re-exported for
external consumers as [`github.com/malivvan/crypto/ssh/client`](./client/).

### Agent

[`ssh/agent`](./agent/) exposes the module's Ed25519 keys as `ssh-ed25519`
identities over the OpenSSH agent protocol: a dependency-free server on a unix
socket plus a matching client. See [`agent/README.md`](./agent/README.md).

## Features

- Sessions, commands, environments, exit codes and signals
- PTY allocation and window-resize handling, including emulated PTYs on
  platforms without a TTY (`EmulatePty`, `AllocatePty`, `PtyHandler`)
- Password, public-key and keyboard-interactive authentication
- Agent forwarding (`NewAgentListener`, `ForwardAgentConnections`)
- Local and reverse TCP forwarding (`DirectTCPIPHandler`,
  `LocalPortForwardingCallback`, `ReversePortForwardingCallback`)
- Subsystems and custom global/channel request handlers
- Connection timeouts, idle timeouts and callbacks for connection lifecycle

### Examples

Runnable examples live in [`example_test.go`](./example_test.go) —
`ExampleListenAndServe`, `ExamplePasswordAuth`, `ExamplePublicKeyAuth`,
`ExampleHostKeyFile` and `ExampleNoPty` — and are rendered by `go doc` and on
pkg.go.dev.

## Middleware

The `middleware/` package provides reusable server middleware that composes
with the root package: `SCP`, `AccessControl`, `ActiveTerm`, `Comment`,
`Elapsed`, `Logging`, `Recover`, the rate limiter (`Middleware` with
`NewRateLimiter`), and the `Chain` helper.

## Repository layout

This directory is the `github.com/malivvan/crypto/ssh` package within the
`github.com/malivvan/crypto` module:

```
.                     # high-level server API (package ssh)
├── agent/            # OpenSSH agent protocol server/client for Ed25519 keys
├── client/           # public re-export of the internal SSH client
├── internal/         # stripped SSH protocol implementation (package internal)
├── middleware/       # reusable middleware: SCP, ActiveTerm, logging, ...
└── example_test.go    # runnable examples for the godoc
```

Related packages live at the module root rather than under `internal/`: the
bcrypt_pbkdf KDF for encrypted OpenSSH private keys in `pbkdf2/`. PTY support
(Unix terminals and Windows ConPTY) comes from the external
[`github.com/malivvan/pty`](https://github.com/malivvan/pty) module.

## Development

```sh
make help     # list targets
make fmt      # gofmt -w
make test     # go test -race ./... (extra flags via ARGS="...")
make lint     # golangci-lint run
make lint-fix # golangci-lint run --fix
make tidy     # go mod tidy
```

### Algorithm policy

The algorithm set above is a hard contract of this repository. Do not add
support for other algorithms, and keep any code or documentation referencing
removed algorithms out of the tree. The `internal` package must only contain
code that this repository actually uses.

## License

BSD 3-Clause — see [`LICENSE`](./LICENSE). The protocol implementation in
`internal/` retains the BSD-style copyright headers of its original authors
(Glider Labs); see the [Credits](../README.md#credits) section of the
repository README.
