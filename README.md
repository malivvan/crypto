# crypto

`github.com/malivvan/crypto` is a Go module amalgamating SSH, PGP and
minisign functionality — each stripped down to the modern key material
**X25519** (encryption) and **Ed25519** (signing) — alongside a set of
primitive packages provided as drop-in replacements for
`golang.org/x/crypto`.

## Composition

The module bundles several formerly separate concerns into one tree. The
former high-level `openpgp` package (the "wallet") moved out of the module root
with the rename and now lives in `./wallet`, while the raw OpenPGP layer sits
under `./pgp`.

| Path                                                                                     | What it is                                                                                                         |
|------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| [`wallet/`](./wallet/)                                                                   | high-level chainable OpenPGP wallet API (former root `openpgp` package)                                            |
| [`pgp/`](./pgp/)                                                                         | stripped, hardened OpenPGP library, Ed25519 sign / X25519 encrypt only                                             |
| [`ssh/`](./ssh/)                                                                         | hardened SSH server, Ed25519 SSH agent, PTY handling and middleware, plus a public client re-export (`ssh/client`) |
| [`minisign/`](./minisign/)                                                               | the minisign signature format on the module's Ed25519 key                                                          |
| [`ed25519/`](./ed25519/), [`x25519/`](./x25519/)                                         | the two key implementations                                                                                        |
| `argon2/`, `blake2b/`, `chacha20/`, `hkdf/`, `pbkdf2/`, `poly1305/`, `salsa20/`, `sha3/` | drop-in `golang.org/x/crypto` replacements                                                                         |

Each directory keeps its own `README.md` (see `pgp/`, `ssh/`, `wallet/`,
`minisign/` and the sub-package docs under `ssh/` and `pgp/`). Contributors
should read `AGENTS.md` at the repository root (and `ssh/AGENTS.md` for the
SSH-specific hardening rules) before making changes.

## Quick orientation

- **PGP / wallet.** [`pgp/`](./pgp/README.md) implements OpenPGP across key
  versions 4, 5 and 6 for Ed25519/X25519 only; the [`wallet`](./wallet/)
  sub-package layers a deterministic, mnemonic-derived keyring and fluent API
  on top of it.
- **SSH.** [`ssh/`](./ssh/README.md) is a hardened server (with an Ed25519
  agent) supporting a minimal AEAD-only algorithm set and Ed25519 user/host
  keys.
- **Minisign.** [`minisign/`](./minisign/) exposes the minisign signature format
  reusing a wallet Ed25519 key — no standalone key material, wire-compatible
  with the reference tool.

```go
import "github.com/malivvan/crypto/wallet"
import pgp "github.com/malivvan/crypto/pgp"
import "github.com/malivvan/crypto/ssh"
import "github.com/malivvan/crypto/minisign"
```

## Requirements

Go 1.27 or later. Runtime dependencies are deliberately few:
[`github.com/malivvan/pty`](https://github.com/malivvan/pty) for PTY handling,
`github.com/hashicorp/golang-lru/v2`, `golang.org/x/sys` and
`golang.org/x/time`.

## Building and testing

```sh
make build     # go build ./...
make test      # go test ./...
make test-v5   # go test -tags v5 ./...  (PGP v5 key support)
make vet       # go vet ./...
make fmt       # gofmt check
make lint      # golangci-lint (falls back to go vet)
make cover     # coverage report
```

## License

BSD 3-Clause, see [`LICENSE`](./LICENSE). The primitive packages derive from
`golang.org/x/crypto` and retain the Go Authors BSD headers; the SSH packages
retain the Glider Labs headers. See [Credits](#credits) for the full list of
upstream projects.

## Credits

This module is an assembly of older open-source work, stripped down to modern
key material. It would not exist without the authors and maintainers of the
projects below — thank you.

| Project                                                                      | Authors                                             | License      | What it contributes here                                                                                                                                                        |
|------------------------------------------------------------------------------|-----------------------------------------------------|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`github.com/ProtonMail/go-crypto`](https://github.com/ProtonMail/go-crypto) | The Go Authors and the ProtonMail go-crypto authors | BSD 3-Clause | the OpenPGP implementation in [`pgp/`](./pgp/) and [`wallet/`](./wallet/), the internal helpers (`ecc`, `encoding`, `algorithm`, `bitcurves`) and the v6 / RFC 9580 key support |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto)              | The Go Authors                                      | BSD 3-Clause | the primitive packages (`argon2/`, `blake2b/`, `chacha20/`, `hkdf/`, `pbkdf2/`, `poly1305/`, `salsa20/`, `sha3/`) and the shared internals they build on                        |
| [`github.com/cloudflare/circl`](https://github.com/cloudflare/circl)         | Cloudflare, Inc.                                    | BSD 3-Clause | the [`ed25519/`](./ed25519/) and [`x25519/`](./x25519/) implementations and the field/big-int math in [`internal/math/`](./internal/math/)                                      |
| [`github.com/charmbracelet/ssh`](https://github.com/charmbracelet/ssh)       | Glider Labs and the Charmbracelet authors           | BSD 3-Clause | the SSH server library and PTY handling in [`ssh/`](./ssh/)                                                                                                                     |
| [`github.com/gliderlabs/ssh`](https://github.com/gliderlabs/ssh)             | Glider Labs                                         | BSD 3-Clause | the SSH server API that [`ssh/`](./ssh/) and `charmbracelet/ssh` build on                                                                                                       |
| [`github.com/aead/minisign`](https://github.com/aead/minisign)               | Andreas Auernhammer                                 | MIT          | the [`minisign/`](./minisign/) implementation and its wire format, interoperable with the reference [minisign](https://jedisct1.github.io/minisign/) tool                       |
| [`github.com/anyproto/go-bip39`](https://github.com/anyproto/go-bip39)       | Tyler Smith and contributors (anyproto fork)        | MIT          | the BIP-39 mnemonic and seed code in [`wallet/bip39/`](./wallet/bip39/)                                                                                                         |
| [`github.com/anyproto/go-slip10`](https://github.com/anyproto/go-slip10)     | anytype                                             | MIT          | the SLIP-0010 hardened key derivation in [`wallet/slip10/`](./wallet/slip10/)                                                                                                   |
| [`github.com/anyproto/go-slip21`](https://github.com/anyproto/go-slip21)     | anytype                                             | MIT          | the SLIP-0021 labeled key derivation in [`wallet/slip21/`](./wallet/slip21/)                                                                                                    |
| [`github.com/foxcpp/go-assuan`](https://github.com/foxcpp/go-assuan)         | Max Mazurov (fox.cpp)                               | MIT          | the Assuan IPC transport used by the gpg-agent service in [`pgp/agent/`](./pgp/agent/)                                                                                          |

The BSD 3-Clause notices are reproduced in [`LICENSE`](./LICENSE), as are the
MIT notices above; the per-directory `LICENSE` files
([`wallet/bip39/LICENSE`](./wallet/bip39/LICENSE),
[`wallet/slip10/LICENSE`](./wallet/slip10/LICENSE),
[`wallet/slip21/LICENSE`](./wallet/slip21/LICENSE),
[`pgp/agent/LICENSE`](./pgp/agent/LICENSE)) carry the full texts.

Two files also retain, verbatim, the notice of the individual author they came
from: [`pgp/keywrap/`](./pgp/keywrap/) keeps Matthew Endsley's 2014 notice for
the RFC 3394 AES key-wrapping implementation, and
[`internal/bitcurves/`](./internal/bitcurves/) keeps ThePiachu's 2011 notice
(next to the Go Authors' one) for the Koblitz curve code. Both were carried
into this module through `github.com/ProtonMail/go-crypto`.

`github.com/charmbracelet/ssh` is a fork of `github.com/gliderlabs/ssh`, and
`github.com/anyproto/go-bip39` is a fork of Tyler Smith's `go-bip39`.
