# pgp

`github.com/malivvan/crypto/pgp` is a heavily stripped and hardened
[OpenPGP](https://www.openpgp.org/) implementation for Go,
focused exclusively on modern key material: **Ed25519** for signing and **X25519** for
encryption.

The codebase was slimmed down from a general-purpose OpenPGP implementation to a
single, consistent API (the former v2 API), while preserving interoperability with
all common Ed25519/X25519 key formats across PGP versions 4, 5 and 6.

```
import "github.com/malivvan/crypto/pgp"
```

## Supported algorithms

Everything else has been removed. Attempts to parse or use other algorithms fail with
`UnsupportedError` instead of silently negotiating them.

### Public-key algorithms

| Algorithm            | PGP ID | Key versions | Purpose                     |
| -------------------- | ------ | ------------ | --------------------------- |
| EdDSA (Ed25519)      | 22     | v4, v5       | signing (legacy encoding)   |
| ECDH (X25519)        | 18     | v4, v5       | encryption (legacy encoding)|
| Ed25519              | 27     | v6           | signing                     |
| X25519               | 25     | v6           | encryption                  |

All other public-key algorithms (RSA, DSA, ElGamal, ECDSA, Ed448, X448, ML-DSA,
SLH-DSA, ML-KEM-768+X25519, ML-KEM-1024) have been removed.

### Symmetric ciphers and modes

| Algorithm        | PGP ID | Mode of operation                          |
| ---------------- | ------ | ------------------------------------------ |
| AES-128          | 7      | CFB (legacy MDC read), AEAD (EAX + OCB)    |
| AES-256          | 9      | CFB (legacy MDC read), AEAD (EAX + OCB)    |

- New encryption is always **AEAD**, preferring OCB, then EAX.
- Legacy **SEIP/MDC** (CFB + SHA-1 modification detection) messages can still be
  decrypted for compatibility; SHA-1 is retained *only* for the MDC check and is never
  used for new signatures or key derivation.
- 3DES, CAST5, IDEA, AES-192 and AEAD-GCM have been removed.

### Hash functions, KDF and S2K

| Algorithm | PGP ID | Use                                        |
| --------- | ------ | ------------------------------------------ |
| SHA-256   | 8      | signatures, S2K, fingerprints              |
| SHA-512   | 10     | signatures, S2K, v4 ECDH KDF               |
| SHA-1     | 2      | legacy MDC check and v4 fingerprints only  |

- S2K supports **Salted** and **Iterated-and-Salted** modes (SHA-256/SHA-512) and
  **Argon2** (RFC 9580) for key derivation. **Simple S2K** (mode 0) is parsed for
  legacy compatibility but never generated.
- Key wrapping uses RFC 3394 AES key wrap (AES-128/AES-256).

## Features

- **Full entity configuration**: `NewEntity` generates exactly
  - 1 ed25519 primary key (sign + certify),
  - 1 ed25519 signing subkey,
  - 1 x25519 encryption subkey,
  - 1 ed25519 authentication subkey.
  For version 6 keys the modern encodings (Ed25519/X25519) are used; for version 4
  the interoperable legacy encodings (EdDSA/ECDH over Curve25519, as produced by
  GnuPG).
- **ASCII armoring** for keys and messages.
- **Clearsigning** via the `github.com/malivvan/crypto/pgp/clearsign` package.
- **Passphrase encryption** (`SymmetricallyEncrypt`) with salted/iterated or Argon2 S2K.
- **Detached signatures**, armored and binary.
- **Key wrapping** (`github.com/malivvan/crypto/pgp/keywrap`).
- **Hardware keys (YubiKey)**: signing through any `crypto.Signer` and decryption
  through the `packet.X25519Decrypter` interface — see below.
- Version 5 keys are supported for reading; generate/parse them by building with
  `-tags v5`.

## Quick start

### Generate an entity

```go
config := &packet.Config{
    DefaultCipher: packet.CipherAES256,
    DefaultHash:   crypto.SHA512,
    AEADConfig:    &packet.AEADConfig{}, // enables AEAD (EAX/OCB)
}

entity, err := pgp.NewEntity("Alice", "", "alice@example.com", config)
// entity.PrivateKey          -> ed25519 primary key
// entity.Subkeys[0..2]       -> x25519 encryption, ed25519 signing, ed25519 auth
```

For a version 6 entity set `config.V6Keys = true`.

### Seeded/deterministic keys

`NewSigner`, `NewDecrypter`, `SignerAlgorithm` and `DecrypterAlgorithm` read
key material from `config.Random()`. Seeding `config.Rand` with 32 bytes
therefore derives reproducible keys that are interchangeable with other
Ed25519/X25519 ecosystems:

```go
seed := make([]byte, 32)
io.ReadFull(rand.Reader, seed)

seeded := *config
seeded.Rand = bytes.NewReader(seed)

signer, err := pgp.NewSigner(&seeded, pgp.SignerAlgorithm(&seeded))
// -> crypto.Signer material for packet.NewSignerPrivateKey
decrypter, err := pgp.NewDecrypter(&seeded, pgp.DecrypterAlgorithm(&seeded))
// -> X25519/ECDH material for packet.NewDecrypterPrivateKey
```

`Entity.AddDirectKeySignature(config)` adds the v6 direct-key signature that
advertises the key preferences derived from `config`.

### Encrypt and sign

```go
var ciphertext bytes.Buffer
w, err := pgp.Encrypt(&ciphertext, []*pgp.Entity{bob}, nil,
    []*pgp.Entity{alice}, nil, config)
w.Write([]byte("hello"))
w.Close()
```

### Decrypt and verify

```go
md, err := pgp.ReadMessage(&ciphertext, pgp.EntityList{bob}, nil, config)
plaintext, err := io.ReadAll(md.UnverifiedBody) // read until EOF
if md.SignatureError == nil && md.SignedBy != nil {
    // signature valid
}
```

### Clearsign


```go
var out bytes.Buffer
w, _ := clearsign.Encode(&out, alice.PrivateKey, config)
w.Write([]byte("cleartext message\n"))
w.Close()

block, _ := clearsign.Decode(out.Bytes())
signer, err := block.VerifySignature(EntityList{alice}, config)
```

### Passphrase encryption

```go
w, _ := pgp.SymmetricallyEncrypt(&out, []byte("passphrase"), nil, config)
w.Write([]byte("secret"))
w.Close()
```

## Sharing key material with other ecosystems (e.g. SSH)

The private keys are plain 32-byte seeds, exactly like Ed25519/X25519 keys elsewhere:

```go
// One seed can back both an SSH key and an OpenPGP key.
seed := make([]byte, 32)
io.ReadFull(rand.Reader, seed)

pgpSign, err := pgped25519.GenerateKeyFromSeed(seed) // crypto/ed25519 package
pgpDec,  err := x25519.GenerateKeyFromSeed(seed)      // crypto/x25519 package
```

See `pgp/openpgp_test.go` (`TestSeedsCompatibility`) for an end-to-end example
verifying signatures made with `crypto/ed25519` against a PGP key derived from the
same seed.

## Using a YubiKey (or other hardware)

**Signing**: build a `packet.PrivateKey` from any `crypto.Signer` whose public key
is an Ed25519 key:

```go
pk := packet.NewSignerPrivateKey(time.Now(), myHardwareSigner) // implements crypto.Signer
pk.UpgradeToV6() // optional
```

**Decryption**: replace the private key of an encryption subkey with any
implementation of:

```go
type X25519Decrypter interface {
    DecryptX25519(ephemeralPublic []byte) (sharedSecret []byte, err error)
}
```

Both v4 ECDH (Curve25519) and v6 X25519 sessions are supported through this
interface, so a YubiKey that computes the X25519 shared secret can decrypt without
ever exposing the private scalar. `pgp/openpgp_test.go` contains a full roundtrip
test with simulated hardware keys (`TestHardwareBackedKeys`).

## Packages

| Path                                | Description                                        |
| ----------------------------------- | -------------------------------------------------- |
| `github.com/malivvan/crypto/pgp` | `package pgp`: entities, messages, signatures, keys |
| `/pgp`                            | This package's source directory                  |
| `/pgp/packet`                     | Packet parsing and serialization                 |
| `/pgp/armor`                     | ASCII armor                                        |
| `/pgp/clearsign`                 | Clearsigned messages                               |
| `/pgp/s2k`                       | String-to-key (Salted / Iterated-and-Salted / Argon2) |
| `/pgp/keywrap`                   | RFC 3394 AES key wrapping                          |
| `/pgp/errors`                    | OpenPGP error types (`UnsupportedError`, ...)      |
| `/pgp/grip`                      | OpenPGP key grips                                  |
| `/pgp/agent`                     | gpg-agent-compatible Assuan service (`LICENSE`/`NOTICE` cover its Assuan transport) |
| `/ed25519`, `/x25519`                | Key implementations at the module root             |
| `/pgp/eddsa`, `/pgp/ecdh`    | Key implementations                                |
| `/internal/eax`, `/internal/ocb`     | AEAD modes (used by the packet layer)              |
| `/internal/bitcurves`               | Curve implementation (retained for future use)     |
| `/internal/...`                     | Other internal helpers (`algorithm`, `alias`, `byteutil`, `conv`, `cryptobyte`, `ecc`, `encoding`) |

## Build tags

- `v5` — enables parsing and generating version 5 keys/signatures.
  Build with `go build -tags v5 ./...`.

## Security posture

- Only AEAD-encrypted data (EAX/OCB) is produced; unauthenticated CFB messages
  without MDC are rejected unless explicitly allowed via
  `Config.InsecureAllowUnauthenticatedMessages`.
- SHA-1 is never used for new signatures or key derivation; it exists only for
  legacy MDC verification and v4 fingerprints.
- Parsing of any unsupported algorithm fails closed.

## Development

```
make build     # build everything
make test      # run all tests
make test-v5   # run tests with the v5 build tag
make vet       # go vet
make fmt       # check formatting
make lint      # golangci-lint (falls back to go vet)
make cover     # test coverage report
```

The high-level `wallet` package lives in [`../wallet/`](../wallet/) and builds on
this one. See [`../AGENTS.md`](../AGENTS.md) for repository conventions, and
[`../README.md`](../README.md) for the overall module layout.

## License

BSD 3-Clause — see [`../LICENSE`](../LICENSE). The OpenPGP implementation
retains the BSD headers of its original authors (The Go Authors); see the
[Credits](../README.md#credits) section of the repository README.
