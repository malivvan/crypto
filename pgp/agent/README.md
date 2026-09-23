# pgp/agent — an OpenPGP (gpg-agent / Assuan) service for the module's keys

Package `gpg` turns the caller's `Ed25519` (signing) and `X25519` (encryption)
keys into a **gpg-agent-compatible Assuan service**. It is the Assuan /
GnuPG-side counterpart of the module's SSH agent (`ssh/agent`).

The wallet holds private keys already, so no PIN/passphrase prompting
(pinentry) is required. Only Ed25519 signing and X25519 decryption are ever
performed; every other algorithm family is rejected, matching the module's
hardened supported-set constraints (see `AGENTS.md`).

```
import "github.com/malivvan/crypto/pgp/agent"
```

## What you get

* a **standalone agent server** on a 0700 unix socket (`Listen` / `Serve` /
  `Close`) that answers a minimal, honest gpg-agent Assuan surface;
* an **extension client** (`Dial`, `AgentSocketPath`) that talks to an
  already-running agent (for example the system `gpg-agent`) over its
  `S.gpg-agent` unix socket;
* a **keyring-extension / merge helper** (`LocalKeyguard` + `ReadAndRelay`)
  that serves the wallet's own keygrips locally and transparently forwards
  commands for keygrips it does *not* hold to an upstream agent socket.

GnuPG's real `gpg-agent` has no standard remote "add a key" command, so
"wrapping an existing agent" is implemented as **forwarding**: the wallet agent
owns its keygrips and delegates everything else to the running upstream agent.
Unknown keygrips are the *only* things ever sent upstream, so local secret key
material is never exposed to the existing agent.

## Spinning up a keyring

Each wallet key is added by wrapping the private key and computing its OpenPGP
keygrip:

```go
import (
    "github.com/malivvan/crypto/ed25519"
    "github.com/malivvan/crypto/pgp/agent"
)

skey, err := ed25519.GenerateKeyFromSeed(seed)      // wallet Ed25519 signing key
kr := gpg.NewKeyring(
    gpg.SignKey(skey, "primary"),
    gpg.DecryptKey(dkey, "encryption"),             // dkey is an *x25519.PrivateKey
)
```

`Keyring` is addressed by hexadecimal keygrip (`Has`, `Get`, `List`), exactly
how gpg-agent names keys over Assuan (`HAVEKEY`/`KEYINFO`/`SIGKEY`/`SETKEY`).

## Redacted server (standalone)

```go
ln, err := gpg.Listen("/path/to/S.gpg-agent", kr, false)
go ln.Serve()
// ... ready ...
ln.Close()                 // tidy lifecycle
```

Each client connection is handled concurrently; the socket is chmod'ed `0700`
after bind, and a stale file is only removed when `force` is true.

### Command surface

The server implements the Assuan commands needed to sign and decrypt with the
wallet keys and no more:

| Command     | Purpose |
|-------------|---------|
| `GETINFO`   | report `version` / environment info |
| `HAVEKEY`   | `HAVEKEY <grip> [<grip> ...]` — OK only if every grip is held |
| `KEYINFO`   | `KEYINFO [--list] [<grip>]` — one gpg-style row per key |
| `SIGKEY`    | select the signing key for this connection |
| `SETKEY`    | select the working (decryption) key for this connection |
| `PKSIGN`    | sign the digest sent over `INQUIRE HASHVAL` with the selected Ed25519 key |
| `PKDECRYPT` | unwrap the X25519 session key sent over `INQUIRE DATA` |

`RESET`, `NOP`, `BYE`, `OPTION`, and `HELP` are handled by the Assuan server
core. Unsupported commands, unknown options, and every other key algorithm are
rejected with the appropriate Assuan/crypto error codes.

### Wire/parameter notes

* `PKSIGN`: client first does `SIGKEY <grip>`; on `PKSIGN` the server issues
  `INQUIRE HASHVAL`; the client answers `D <hexdigest> END`; the server returns
  the raw 64-byte Ed25519 signature as one lowercase-hex `D` line followed by
  `OK`. This framing is deterministic and self-contained (see below).
* `PKDECRYPT`: client first does `SETKEY <grip>`; on `PKDECRYPT` the server
  issues `INQUIRE DATA`; the client sends `D <hex> END` where `<hex>` decodes
  to `ephemeral-public-key(32B) || encrypted-session-key` in the module's
  `x25519` encoding; the server responds with the unwrapped session key as hex.

**Compatibility.** The framing above matches the wallet's own `ed25519`/`x25519`
primitives exactly and is fully testable (see `roundtrip_test.go`). It is a
documented, in-package encoding and does **not** attempt to byte-match GnuPG's
libgcrypt S-expression `PKSIGN`/`PKDECRYPT` payloads, its pre-hash flags, or its
KDF wrapping. If you need byte-level interop with a stock `gpg-agent` sign /
decrypt session key, adapt the `INQUIRE HASHVAL`/`INQUIRE DATA` payload marshalling
at the calling layer to the GnuPG format — the Assuan line transport and the
`HAVEKEY`/`KEYINFO`/`SIGKEY`/`SETKEY` handshake here are already compatible.

## Extending an existing gpg-agent (keyring merge)

To expose the wallet's keys through a socket while the real `gpg-agent` keeps
serving everything else, read each incoming Assuan command, decide whether it
names only local keygrips, and relay it upstream otherwise:

```go
up, err := gpg.Dial(socketPath)      // the running agent's S.gpg-agent
defer up.Close()

// on each request (cmd, params) from the local downstream socket:
local, err := gpg.LocalKeyguard(kr)(cmd, params)
if err != nil || local {
    // handle locally (ok: local key); err => nothing upstream configured
} else {
    gpg.ReadAndRelay(localPipe, up, cmd, params)  // tunnel the whole exchange upstream
}
```

`LocalKeyguard`'s rule is conservative: a command that references a keygrip the
local keyring does not own is treated as remote, so `HAVEKEY`/`KEYINFO`/`SIGKEY`
answer for foreign keys by asking the real agent. Non-keygrip commands (`OPTION`,
`RESET`, `NOP`, ...) are always served locally, never forwarded.

`gpg.Dial` performs the Assuan handshake; `gpg.AgentSocketPath(explicit)` locates
`$GNUPGHOME/S.gpg-agent` (or `~/.gnupg/S.gpg-agent`) when no explicit path is
given.

## Protocol / package layout

`pgp/agent` additionally vendors the Assuan **transport** as first-party
packages used by this API:

| Package | Role |
|---------|------|
| `pgp/agent/common`   | Assuan line codec: `Pipe`, `ReadLine`/`WriteData`, escape, errors |
| `pgp/agent/client`   | `client.Session` (`Init`, `SimpleCmd`, `Transact`, `Option`, `Close`) |
| `pgp/agent/server`   | `server.ProtoInfo`, `server.Serve`, Assuan command dispatch |
| `pgp/agent/pinentry` | optional pinentry-style client/server helpers (not required by the wallet) |
| `pgp/agent` (root)   | high-level keyring + server + extension helpers marketed here |

The transport keeps its original MIT attribution in `LICENSE` and `NOTICE`.

## Security notes

* Private keys stay in-process; only signatures / unwrapped session keys leave
  the agent boundary, and only after an explicit `SIGKEY`/`SETKEY`.
* The server binds with owner-only (`0700`) permissions and never listens on a
  world-accessible socket by default.
* The supported set is deliberately narrow (Ed25519 sign / X25519 decrypt) —
  no RSA/DSA/ECDSA/Ed448 host of key families are advertised or performed.
* In merge mode, forwarding is scoped to keygrips not held locally; the wallet
  never sends its own secret keys, session keys, or signatures-of-foreign-data
  to the upstream agent.

## License

BSD 3-Clause — see [`../../LICENSE`](../../LICENSE) and [`LICENSE`](./LICENSE).
The Assuan transport portions (`common`, `client`, `server`, `pinentry`) are
MIT: Copyright © Max Mazurov (fox.cpp) 2018; see [`LICENSE`](./LICENSE) and
[`NOTICE`](./NOTICE). Attribution for the OpenPGP layer is listed in the
[Credits](../../README.md#credits) section of the repository README.
