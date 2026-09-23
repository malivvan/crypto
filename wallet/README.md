# wallet

`github.com/malivvan/crypto/wallet` is a high-level, chainable API on top of the
[OpenPGP layer](../pgp/) (`package pgp`) — it is the re-homed former root
`openpgp` package. A `wallet.Wallet` is a self-contained gpg-like keyring: it
owns one OpenPGP entity whose Ed25519/X25519 keys are derived deterministically
from a BIP-39 mnemonic via SLIP-10, it can hold trusted correspondent keys, and
it offers fluent builders for signing, verification, encryption, decryption and
clearsigning.

```
import "github.com/malivvan/crypto/wallet"
```

## Creating a wallet

```go
password := []byte("correct horse battery staple")

wl, err := wallet.NewWallet("Alice", "alice@example.com", mnemonic, password, nil)
if err != nil { /* ... */ }
```

`NewWallet` derives a primary signing key plus decryption, signing and
authentication subkeys from the mnemonic, so the same mnemonic reproduces the
same keys. A nil config selects `wallet.Defaults()` (AES-256 + AEAD, SHA-512,
ZLIB). Options such as cipher, hash, compression, AEAD mode and v6 keys are
configured through `packet.Config`; `wallet.Defaults()` returns a ready-made
starting point for a custom config.

## Message operations

Every operation starts with the data and returns a fluent builder. String,
`[]byte` and `io.Reader` inputs are all accepted. Configuring options:
`Config` (per-call `packet.Config`), `Armor`, `Text`, `File` (`pgp.FileHints`),
`To`/`ToHidden` (recipients), `Password`, `SessionKey`, `EncryptionTime`,
`OutsideSig` and `Sign`/`Verifier` (extra entities). Terminals: `Output(w)`,
`String()`, `Bytes()`, `Verify()`, `Message()`, `Plaintext()`.

### Detached signatures

```go
sig, err := wl.Sign(message).Armor().File(&pgp.FileHints{FileName: "doc.txt"}).String()

// verify against the wallet keyring (own key + imported entities)
err = wl.Verify(message).Signature(sig).Armor().Verify()
```

### Encrypt / EncryptSign / Decrypt / DecryptVerify

```go
// Encrypt: no recipient configured -> encrypted to the wallet's own key.
ct, err := wl.Encrypt("secret").Armor().String()

// EncryptSign: signed by the wallet, encrypted to Bob's public key.
ct, err = wl.EncryptSign("secret").To(bobPublicEntity).Armor().String()

plain, md, err := wl.Decrypt(ct).Armor().Plaintext()
plain, md, err = wl.DecryptVerify(ct).Armor().Verifier(bobPublicEntity).Plaintext()
```

`DecryptVerify` refuses to return the plaintext unless an embedded signature
verified successfully. `Decryptor.Message()` returns the raw `pgp.MessageDetails`
for streaming via `md.UnverifiedBody`, while `Decryptor.Output(w)` streams the
decrypted plaintext directly to an `io.Writer` (fully consuming the body so
integrity and signature checks run before it returns).

### Clearsign

```go
out, err := wl.Clearsign("text to sign").String()
```

### Passphrase encryption

```go
ct, err := wl.Encrypt(msg).Password([]byte("hunter2")).Bytes()
plain, md, err := wl.Decrypt(ct).Password([]byte("hunter2")).Plaintext()
```

## Keyring behaviour

`Wallet` implements the `pgp.KeyRing` interface
(`KeysById`/`EntitiesById`) over its own entity plus every imported entity:

```go
wl.AddEntity(correspondentPublicEntity) // trust a correspondent's key
ids := wl.Entities()
keys := wl.KeysById(id)
```

Once an entity is imported, `Verify`, `DecryptVerify` and `DetachVerifier`
automatically consider it as a potential signer.

## Lock / Unlock

Private keys can be passphrase-protected in memory:

```go
wl.Lock("passphrase")   // encrypts all private keys (S2K + AEAD)
wl.Unlock("passphrase") // decrypts them again
wl.IsLocked()
```

While locked, signing and decryption fail until `Unlock` succeeds. `Lock` and
`Unlock` mirror `pgp.Entity.EncryptPrivateKeys`/`DecryptPrivateKeys`; the
passphrase is zeroed after use.

## Save / Load

A wallet can be persisted in ASCII armor together with its keyring:

```go
var file bytes.Buffer
wl.Lock("passphrase")
wl.Save(&file)                       // refuses while unlocked

wl2, err := wallet.Load(&file)       // starts locked
err = wl2.Unlock("passphrase")
```

The file contains the (locked) private key block followed by one public key
block per imported entity. Saving an unlocked wallet is refused so that key
material never reaches disk in plaintext. A loaded wallet no longer has the
SLIP-10/SLIP-21 master nodes, so `DeriveEd25519`, `DeriveX25519` and
`DeriveSecret` return an error on loaded wallets.

## Key derivation

Keys are derived from the BIP-39 seed with purpose-built, misuse-resistant
functions:

```
BIP-39 seed
├── SLIP-10 hardened paths  -> Ed25519 signing/authentication keys -> DeriveEd25519
├── SLIP-10 hardened path   -> 32-byte seed for X25519 encryption  -> DeriveX25519
└── SLIP-21 labeled paths   -> symmetric application/storage keys  -> DeriveSecret
```

```go
const hardened = uint32(0x80000000) // or any index >= 2^31

signKey, err := wl.DeriveEd25519(hardened+44, hardened)     // *ed25519.PrivateKey
encKey,  err := wl.DeriveX25519(hardened+44, hardened+1)    // *x25519.PrivateKey
secret,  err := wl.DeriveSecret([]byte("com.example.app"))  // []byte
clear(secret)
```

All SLIP-10 paths must be **hardened**: passing an unhardened index
(< 2^31), an empty path, or an empty/nil SLIP-21 label returns a clear error
instead of silently deriving the wrong key. Every key is deterministic for a
given mnemonic, password and path; the 32-byte seeds are interchangeable with
other Ed25519/X25519 ecosystems (e.g. SSH). `DeriveSecret` returns a freshly
allocated `[]byte` owned by the caller, which should be zeroed once it is no
longer needed.

## Minisign signing

The wallet supports the [minisign](../minisign/) signature format using an
Ed25519 key it already holds — you never generate or store a separate minisign
key. The easy, idiomatic choice is to reuse the same key as GPG (OpenPGP)
signing via `Wallet.SigningKey()`; `minisign.Sign` accepts any
`*ed25519.PrivateKey` though, so you can sign with any suitably derived key.
Pull a key from the wallet and use the `minisign` package:

```go
import "github.com/malivvan/crypto/minisign"

sk, err := wl.SigningKey() // any wallet Ed25519 key (by default the GPG signing key)
if err != nil { /* ... */ }

// Sign a message (textual minisign signature).
sig, err := minisign.Sign(sk, message)

// Derive the public key for verification / .pub export.
pub := minisign.PublicKeyFromEd25519(&sk.PublicKey)
ok := minisign.Verify(pub, message, sig)

// Long/streamed messages: hash while reading, then sign or verify.
r := minisign.NewReader(file)
io.Copy(io.Discard, r)
sig, err = r.Sign(sk)          // HashEdDSA signature over the streamed digest
ok = r.Verify(pub, sig)
```

`signature` blocks and `.pub` files produced here interoperate with the
reference `minisign` tool (the wire formats are unchanged). Keys are
Ed25519-only, matching the rest of the module.

## Concurrency and secret handling

- A `Wallet` is **not safe for concurrent mutation**: it owns a single OpenPGP
  entity and keyring that `Lock`, `Unlock`, `AddEntity` and the message
  operations read and modify. Callers that share a wallet across goroutines
  must serialize access with their own lock.
- The fluent builders are **single-shot**: `io.Reader` inputs are consumed by
  the terminal call, so use one builder per operation.
- `NewWallet` takes the seed passphrase as a `[]byte`. `Lock`,
  `Unlock` and `Password` accept Go `string`/`[]byte` passphrases: the library
  zeroes its internal copy after use, but it cannot wipe the caller's original
  buffer — callers handling sensitive passphrases should zero their own buffers
  (e.g. with the `clear` builtin).

## License

BSD 3-Clause — see [`../LICENSE`](../LICENSE). The BIP-39, SLIP-10 and SLIP-21
derivation helpers under this directory are MIT-licensed by their original
authors (Tyler Smith and contributors; anytype); see `bip39/LICENSE`,
`slip10/LICENSE` and `slip21/LICENSE`. Upstream attribution for the OpenPGP
layer is listed in the [Credits](../README.md#credits) section of the
repository README.
