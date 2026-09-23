# ssh

A minimal, hardened SSH server and client library for Go.

`github.com/malivvan/crypto/ssh` lets you build SSH servers on top of `net.Listener`
without dealing with the SSH wire protocol yourself, and dial them (or any
other server speaking the same algorithm set) from Go. It provides session and
PTY handling, password/public-key/keyboard-interactive authentication,
subsystems, TCP and Unix port forwarding, and agent support (forwarding plus an
Ed25519 SSH agent) — but deliberately supports only a small, modern set of
cryptographic algorithms. Everything else has been removed from the codebase.

The package is split in two halves, both exported from the same import path:

- **server** — `Server`, `Serve`, `ListenAndServe`, `Handle`, the functional
  options, and `ServerSession` for per-connection handlers;
- **client** — `Dial`, `DialContext`, `NewClientConn`, `Client`, `ClientConfig`
  and `ClientSession` (see [the client guide](#client)).

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
    ssh.Handle(func(s ssh.ServerSession) {
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
ssh.Handle(func(s ssh.ServerSession) { ... })

publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
    allowed, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAA..."))
    return err == nil && ssh.KeysEqual(allowed, key)
})

log.Fatal(ssh.ListenAndServe(":2222", nil, publicKeyOption))
```

### Client

The client half of the library is exported from the same package: everything
the test suite dials with is available as `github.com/malivvan/crypto/ssh`. It
behaves like a standard Go SSH client, but it only negotiates the algorithms
listed above, so it only connects to servers that present an **Ed25519 host key
certificate** (this package's own `Server` does so by default).

All client-side types are aliases of the implementation the server uses, so a
key or session obtained from one half can be used with the other without
conversion. The client session type is `ClientSession`, because `ServerSession`
is the server-side handler interface.

#### Dialing and running commands

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/malivvan/crypto/ssh"
)

func main() {
    client, err := ssh.Dial("tcp", "example.com:2222", &ssh.ClientConfig{
        User:            "alice",
        Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // see "Host key verification"
        Timeout:         10 * time.Second,             // TCP connect timeout
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    session, err := client.NewSession()
    if err != nil {
        log.Fatal(err)
    }
    defer session.Close()

    out, err := session.Output("uname -a") // run a command, return stdout
    if err != nil {
        log.Fatal(err)
    }
    fmt.Print(string(out))
}
```

`Client` also offers `HandleChannelOpen`, `Dial`/`DialContext`/`DialTCP` (open a
connection from the remote host towards a target), `Listen`/`ListenTCP`/
`ListenUnix` (reverse forwarding) and `SendRequest` for global requests.

`ClientSession` mirrors the standard client session API: `Run`, `Start`,
`Shell`, `Output`, `CombinedOutput`, `Wait`, `Setenv`, `Signal` (for example
`ssh.SIGTERM`), `RequestPty` with `ssh.TerminalModes`, `WindowChange`, the
`Stdin`/`Stdout`/`Stderr` writers, `StdinPipe`/`StdoutPipe`/`StderrPipe`, and
`Close`. `Wait` returns `*ssh.ExitError` when the remote command exits
non-zero, and `*ssh.ExitMissingError` when the server never reports a status:

```go
if err := session.Run("./deploy.sh"); err != nil {
    var exitErr *ssh.ExitError
    if errors.As(err, &exitErr) {
        log.Fatalf("remote command exited with status %d", exitErr.ExitStatus())
    }
    log.Fatal(err)
}
```

#### Dialing with a context

`DialContext` is `Dial` with cancellation: if the context expires while the TCP
connection is being established or while the handshake runs, the attempt is
aborted. Once dialed, the context no longer affects the client.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

client, err := ssh.DialContext(ctx, "tcp", "example.com:2222", config)
```

#### Dialing an existing connection

To use your own transport (a proxied dialer, a unix socket, a connection from a
pool), establish the `net.Conn` yourself and hand it to `NewClientConn`; the
returned channel and request streams must be serviced, which `NewClient` does
for you:

```go
conn, err := net.Dial("tcp", "example.com:2222")
if err != nil {
    log.Fatal(err)
}

c, chans, reqs, err := ssh.NewClientConn(conn, "example.com:2222", config)
if err != nil {
    log.Fatal(err)
}
client := ssh.NewClient(c, chans, reqs)
defer client.Close()
```

`NewControlClientConn` does the same over an OpenSSH `ControlMaster` socket in
proxy mode (pass a local, secure connection such as a Unix domain socket).

#### Authentication

| Method | Use |
| --- | --- |
| `ssh.Password(secret)` | A fixed password. |
| `ssh.PasswordCallback(prompt)` | Ask for a password when the server offers the method. |
| `ssh.PublicKeys(signers...)` | One or more Ed25519 keys. |
| `ssh.PublicKeysCallback(getSigners)` | Load keys lazily (e.g. from an agent). |
| `ssh.KeyboardInteractive(challenge)` | Challenge/response driven by the server. |
| `ssh.RetryableAuthMethod(m, n)` | Wrap a method so it can be retried up to `n` times. |

```go
pemBytes, err := os.ReadFile("id_ed25519")
if err != nil {
    log.Fatal(err)
}
signer, err := ssh.ParsePrivateKey(pemBytes)
if err != nil {
    log.Fatal(err)
}

config := &ssh.ClientConfig{
    User:            "alice",
    Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
    HostKeyCallback: ssh.FixedHostKey(serverKey),
}
```

Keys are handled with the same helpers as the server: `ParsePrivateKey`,
`ParsePrivateKeyWithPassphrase`, `ParseRawPrivateKey`,
`ParseRawPrivateKeyWithPassphrase`, `MarshalPrivateKey`,
`ParseAuthorizedKey`, `ParsePublicKey`, `MarshalAuthorizedKey`,
`NewPublicKey`, `NewSignerFromKey`, `NewSignerFromSigner`, `NewCertSigner` and
`FingerprintSHA256` all live in this package. Use
`ssh.NewSignerFromSigner` to authenticate with a hardware-backed Ed25519 key.
Passing `ssh.ClientConfig.AuthCallback` lets you choose each method as the
handshake progresses, based on `ssh.ClientAuthContext` (allowed methods,
partial successes and previous failures).

#### Host key verification

`ClientConfig.HostKeyCallback` is mandatory and must verify the host key the
server presents. Because this library only negotiates Ed25519 host key
certificates, the server's key is a certificate, not a bare key. Three options
are provided:

- `ssh.FixedHostKey(pub)` pins one public key: use it when the server has a
  stable host certificate. `pub` is compared byte for byte against the
  certificate the server sends, so it can be obtained from the server side with
  `ssh.Server.HostSigners[i].PublicKey()` (or `ssh.ParseAuthorizedKey` on an
  `authorized_keys` line).
- `(&ssh.CertChecker{IsHostAuthority: ...}).CheckHostKey` verifies the
  certificate structure, validity window, principals and signature. Set
  `IsHostAuthority` to accept the authority that signed the host certificate;
  `HostKeyFallback` can additionally accept non-certificate keys.
- `ssh.InsecureIgnoreHostKey()` accepts anything. For tests and throwaway
  tooling only.

```go
config.HostKeyCallback = (&ssh.CertChecker{
    IsHostAuthority: func(authority ssh.PublicKey, address string) bool {
        return ssh.KeysEqual(authority, trustedCA) // trustedCA parsed from a key file
    },
}).CheckHostKey
```

When a callback rejects a key, `Dial` fails with the callback's error and the
connection is closed.

#### Port forwarding

```go
// Open a TCP connection from the remote host to db.internal:5432.
conn, err := client.Dial("tcp", "db.internal:5432")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Ask the remote host to listen and forward incoming connections locally.
listener, err := client.Listen("tcp", "127.0.0.1:0")
if err != nil {
    log.Fatal(err)
}
defer listener.Close()

for {
    conn, err := listener.Accept()
    if err != nil {
        log.Fatal(err)
    }
    go handle(conn)
}
```

The remote side must permit the request: on a server built with this package
that means enabling `DirectTCPIPHandler` in `ChannelHandlers` and returning true
from `LocalPortForwardingCallback` (and the corresponding reverse-forwarding
handler/callback for `Listen`).

#### Choosing and reporting algorithms

`ssh.SupportedAlgorithms()` reports the algorithm set this package implements
(`Algorithms`), and the individual names are exported as
`ssh.KeyExchangeMLKEM768X25519`, `ssh.KeyExchangeCurve25519`,
`ssh.CipherChaCha20Poly1305`, `ssh.CipherAES256GCM`, `ssh.HMACSHA256ETM`,
`ssh.HMACSHA512ETM`, `ssh.KeyAlgoED25519`, `ssh.CertAlgoED25519v01` and
friends. Use them to restrict `ClientConfig.Config` (or to inspect what was
negotiated through `ssh.NegotiatedAlgorithms`). Unsupported values are ignored,
which means a client can never be forced onto an algorithm outside the set.

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

Client-side:

- `Dial`, `DialContext`, `NewClientConn`/`NewClient` and
  `NewControlClientConn`
- Password, public-key and keyboard-interactive authentication with a
  pluggable `AuthCallback`, plus `RetryableAuthMethod`
- Host key verification with `FixedHostKey` or `CertChecker.CheckHostKey`
- Remote commands, shells, PTYs, signals and exit statuses (`ClientSession`)
- Local, reverse and Unix-socket forwarding, and custom channel handlers

### Examples

Runnable examples live in [`example_test.go`](./example_test.go) —
`ExampleListenAndServe`, `ExamplePasswordAuth`, `ExamplePublicKeyAuth`,
`ExampleHostKeyFile`, `ExampleNoPty` and `ExampleDial` (the client) — and are
rendered by `go doc` and on pkg.go.dev. The client API itself is covered by
[`client_test.go`](./client_test.go), which dials both a password- and a
public-key-authenticated server over a real loopback connection.

## Middleware

The `middleware/` package provides reusable server middleware that composes
with the root package: `SCP`, `AccessControl`, `ActiveTerm`, `Comment`,
`Elapsed`, `Logging`, `Recover`, the rate limiter (`Middleware` with
`NewRateLimiter`), and the `Chain` helper.

## Repository layout

This directory is the `github.com/malivvan/crypto/ssh` package within the
`github.com/malivvan/crypto` module:

```
.                     # public server + client API (package ssh)
├── agent/            # OpenSSH agent protocol server/client for Ed25519 keys
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
