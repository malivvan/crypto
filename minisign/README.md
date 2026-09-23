# minisign

`github.com/malivvan/crypto/minisign` implements the minisign signature
format — Ed25519 signatures with BLAKE2b key IDs and digests — on top of the
module's Ed25519 keys.

Minisign is a small alternative to GPG for signing and verifying files: a
public key is a single base64 line, and a signature is a base64 blob that
embeds the algorithm, the signing key ID, the signature and optional
trusted/untrusted comments.

```
import "github.com/malivvan/crypto/minisign"
```

## No standalone key material

This package never generates or stores minisign keys. Signing always uses an
Ed25519 key supplied by the caller; the idiomatic choice is the wallet's own
OpenPGP signing key, so that one key backs both GPG and minisign signatures
(see [`../wallet/`](../wallet/)):

```go
sk, err := wl.SigningKey() // *ed25519.PrivateKey, the wallet's GPG signing key
```

Any other suitably derived `*ed25519.PrivateKey` works just as well — there is
no `GenerateKey` and no private-key encryption here.

## Signing and verifying

```go
pub := minisign.PublicKeyFromEd25519(&sk.PublicKey) // .pub material

sig, err := minisign.Sign(sk, message)              // textual signature
ok := minisign.Verify(pub, message, sig)
```

`SignWithComments` adds the trusted and untrusted comment lines, returning the
complete textual signature ready to be written to a `.minisig` file. For
messages that do not fit in memory, use a `Reader`, which hashes the message
while reading it and then signs or verifies the digest (the pre-hashed
`HashEdDSA` path):

```go
r := minisign.NewReader(file)
io.Copy(io.Discard, r)   // hash the whole message
sig, err := r.Sign(sk)
ok = r.Verify(pub, sig)
```

## Public keys and signatures as text

`PublicKey` and `Signature` implement `encoding.TextMarshaler` and
`encoding.TextUnmarshaler`, so both round-trip through their minisign text
encoding, and `PublicKeyFromFile` / `SignatureFromFile` read `.pub` and
`.minisig` files:

```go
pub, err := minisign.PublicKeyFromFile("minisign.pub")
sig, err := minisign.SignatureFromFile("message.txt.minisig")
```

`PublicKey.ID()` returns the 64-bit key ID embedded in signatures;
`PublicKey.Equal` compares against another `crypto.PublicKey` and
`Signature.Equal` compares two signatures, without needing the original bytes.

## Interoperability

The public-key and signature wire and text formats are unchanged from the
reference `minisign` command-line tool: a public key exported with
`PublicKey.MarshalText` and a signature produced by `Sign` verify with the
reference tool, and signatures produced by the reference tool verify here (the
test suite checks a known reference vector).

Only Ed25519 material is supported; the `EdDSA` and `HashEdDSA` algorithm
constants in the signature header are format identifiers, not new
cryptographic primitives.

## License

BSD 3-Clause — see [`../LICENSE`](../LICENSE). Attribution for the format and
its implementation is listed in the [Credits](../README.md#credits) section of
the repository README.
