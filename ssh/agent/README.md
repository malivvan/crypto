# ssh/agent — an OpenSSH agent (RFC 4819 / PROTOCOL.agent) service for the module's Ed25519 keys

Package `agent` lets the caller expose its **Ed25519** keys as
`ssh-ed25519` identities over the OpenSSH agent protocol. It is the SSH-side
counterpart of the module's gpg-agent (`pgp/agent`): a dependency-free server
and client plus a small convenience client, with no dependency on any external
SSH agent client
implementation.

Only `ssh-ed25519` keys are served. The module's supported-set constraints
(`AGENTS.md`) forbid RSA/DSA/ECDSA/Ed448 and friends, so the agent never
advertises or signs with them.

## What you get

* a **standalone server** on a 0700 unix socket (`Listen` / `Serve` / `Close`)
  that answers OpenSSH list and sign requests for the registered wallet keys;
* a **dependency-free client** (`DialUnix` / `DialEnv` over `SSH_AUTH_SOCK`)
  whose `Client` lists identities and requests signatures — usable
  against this Server or any OpenSSH-grounded agent socket;
* a deliberately small client/server surface. For a wider protocol reach
  (any SSH library client, certificates, extensions), point a full ssh library
  client at this server — the wire format is the standard OpenSSH agent one.

## Serving wallet keys

```go
import (
    "github.com/malivvan/crypto/ed25519"
    sshagent "github.com/malivvan/crypto/ssh/agent"   // package agent / alias sshagent
)

skey, err := ed25519.GenerateKeyFromSeed(seed)   // wallet Ed25519 signing key

srv, err := sshagent.Listen("/path/to/agent.sock", nil, false)
srv.AddKey(skey, "alice@example.com")            // keys may also be added up front
go srv.Serve()                                   // goroutine; Close() tears it down
// srv.Path() → bound unix socket
```

`socket` permissions are `0700`. `Listen(path, kr, force)` requires the socket
not exist unless `force` is true (a stale name is then removed). `Close` stops
the listener and waits for the serving goroutine to return. The package
identifier is `agent` (imported as `sshagent` in these examples via an alias).

To create and register several keys up front use `sshagent.NewServerKeyring()` +
`AddKey(...)` and pass it to `Listen`.

## Protocol surface (Agent / NewClient / NewKeyring / ServeAgent)

Beyond the unix-socket client/server above, `proto.go` carries a self-contained
Ed25519 wire-codec protocol surface (no dependency on an SSH client stack):

* `Agent` / `ExtendedAgent` interfaces and identity type `Key` (`Format` /
  `Blob` / `Comment`), plus `AddedKey`, `SignatureFlags` and
  `ConstraintExtension`;
* `NewClient(rw)` returns an `ExtendedAgent` that talks the OpenSSH agent
  protocol over any `io.ReadWriter` (a socket, `net.Pipe`, or an SSH channel),
  supporting `List`, `Sign`, `Remove`, `RemoveAll`, `Lock`/`Unlock`;
* `NewKeyring()` returns an in-memory Ed25519-`Agent` (add keys by seed, list,
  sign, remove, lock/unlock);
* `ServeAgent(a, rw)` serves the Ed25519 subset of the agent protocol over a
  connection for a given `Agent`, answering `SSH_AGENT_FAILURE` for anything
  outside the supported subset.

As throughout this module, the agent is Ed25519-only: the RSA/DSA/ECDSA and
certificate code paths, and any dependency on an SSH *client* stack, are
intentionally not ported. `Agent`/`Key` in this package are a self-contained
representation: identities are addressed
by the standard `"ssh-ed25519"` + 32-byte-point public blob and `Sign` returns
the raw 64-byte Ed25519 signature, so the wire bytes interoperate with OpenSSH
agent peers.

## Client

```go
c, err := sshagent.DialEnv()          // or sshagent.DialUnix(path)
ids, err := c.List()                  // []sshagent.Identity{Blob, Comment}
sig, err := c.Sign(ids[0].Blob, []byte("data"))
c.Close()
```

`Sign` returns the raw 64-byte Ed25519 signature over `data`.

## Wire protocol served

The Unix-socket `Server` answers the two identity/sign messages every modern
`ssh-ed25519` agent needs, and answers every other opcode with
`SSH_AGENT_FAILURE`:

| Request | Reply |
|---------|-------|
| `SSH2_AGENTC_REQUEST_IDENTITIES` (11) | `SSH2_AGENT_IDENTITIES_ANSWER` (12) |
| `SSH2_AGENTC_SIGN_REQUEST` (13) | `SSH2_AGENT_SIGN_RESPONSE` (14) |

`ServeAgent` additionally understands remove/remove-all and lock/unlock over
the same frame protocol for an `Agent` that supports them.

`ssh-ed25519` signs its data directly (no extra pre-hash), matching what
verifiers (including `github.com/malivvan/crypto/ssh`) recompute.

## Package layout

| File | Role |
|------|------|
| `wire.go`    | agent wire framing + codec, message constants, size guards |
| `sshkey.go`  | `Identity` / `ServerKey`, `ssh-ed25519` public-blob marshal + parse |
| `server.go`  | `ServerKeyring` + `replyTo`/`serveConn` connection handling |
| `sshserve.go`| exported `Server` (unix socket `Listen`/`Serve`/`Close`/`AddKey`) |
| `client.go`  | exported dependency-free `Client` (`DialUnix`/`DialEnv`/`List`/`Sign`) |
| `proto.go`   | protocol port: `Agent`/`ExtendedAgent`/`Key`/`AddedKey`/`SignatureFlags`, `NewClient`, `NewKeyring`, `ServeAgent` |

This package is a self-contained, Ed25519-only rebuild of the OpenSSH agent
protocol surface. The generic implementation it replaces was generic over
RSA/DSA/ECDSA keys and certificates and depended on an SSH client stack that
this module does not carry, so it was removed with the rest of the non-modern
algorithms; its Ed25519 protocol surface lives here (see "Protocol surface"
above), alongside this package's own server/client for local key
distribution.

Implementation notes: the agent framing uses the standard `uint32`-length
prefixed messages with a 16 MiB read guard (`maxMessageLen`) to bound hostile
allocations. Unrecognised or malformed messages return `SSH_AGENT_FAILURE`, and
signing with a key that is not in the keyring is refused.

## Security notes

* Only `ssh-ed25519` key material is held or served; there is no signing with
  RSA/ECDSA/DSA/Ed448 host keys and no certificate issuance.
* The unix socket is created with owner-only (`0700`) permissions.
* The 16 MiB message-cap prevents unbounded allocation from a length field.
* A signature is only produced for a public key the server actually registered
  (`ServerKeyring`/`keyringAgent` lookup), so an attacker cannot sign with
  someone else's key.

## License

BSD 3-Clause — see [`../LICENSE`](../LICENSE); attribution is listed in the
[Credits](../../README.md#credits) section of the repository README.
