// Package ed25519 implements the ed25519 signature algorithm for OpenPGP
// as defined in the Open PGP crypto refresh.
package ed25519

import (
	"crypto"
	"crypto/subtle"
	stdErrors "errors"
	"io"

	"github.com/malivvan/crypto/pgp/errors"
)

const (
	// PublicKeySize is the size, in bytes, of public keys in this package.
	PublicKeySize = 32
	// SeedSize is the size, in bytes, of private key seeds.
	// The private key representation used by RFC 8032.
	SeedSize = 32
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
)

// Compile-time assertion: a *PrivateKey can be handed to any consumer that
// accepts a crypto.Signer (e.g. the module's ssh stack).
var _ crypto.Signer = (*PrivateKey)(nil)

type PublicKey struct {
	// Point represents the elliptic curve point of the public key.
	Point []byte
}

type PrivateKey struct {
	PublicKey
	// Key the private key representation by RFC 8032,
	// encoded as seed | pub key point.
	Key []byte
}

// NewPublicKey creates a new empty ed25519 public key.
func NewPublicKey() *PublicKey {
	return &PublicKey{}
}

// NewPrivateKey creates a new empty private key referencing the public key.
func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

// Seed returns the ed25519 private key secret seed.
// The private key representation by RFC 8032.
func (pk *PrivateKey) Seed() []byte {
	return pk.Key[:SeedSize]
}

// MarshalByteSecret returns the underlying 32 byte seed of the private key.
func (pk *PrivateKey) MarshalByteSecret() []byte {
	return pk.Seed()
}

// UnmarshalByteSecret computes the private key from the secret seed
// and stores it in the private key object.
func (sk *PrivateKey) UnmarshalByteSecret(seed []byte) error {
	sk.Key = privateKeyFromSeed(seed)
	return nil
}

// GenerateKey generates a fresh private key with the provided randomness source.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return GenerateKeyFromSeed(seed)
}

// GenerateKeyFromSeed derives a private key from the given 32-byte seed.
// The seed is the raw RFC 8032 private key material, i.e. the same 32 bytes
// used by other ed25519 implementations (e.g. SSH keys), which allows one
// seed to back keys in multiple ecosystems.
func GenerateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.InvalidArgumentError("ed25519: the seed has the wrong size")
	}
	privateKeyOut := new(PrivateKey)
	seedCopy := make([]byte, SeedSize)
	copy(seedCopy, seed)
	if err := privateKeyOut.UnmarshalByteSecret(seedCopy); err != nil {
		return nil, err
	}
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKeyOut.Key[SeedSize:])
	privateKeyOut.PublicKey.Point = publicKey
	return privateKeyOut, nil
}

// Sign signs a message with the ed25519 algorithm.
// priv MUST be a valid key! Check this with Validate() before use.
func Sign(priv *PrivateKey, message []byte) ([]byte, error) {
	signature := make([]byte, SignatureSize)
	signAll(signature, priv.Key, message, []byte(""), false)
	return signature, nil
}

// Verify verifies an ed25519 signature.
func Verify(pub *PublicKey, message []byte, signature []byte) bool {
	return verify(pub.Point, message, signature, []byte(""), false)
}

// Validate checks if the ed25519 private key is valid.
func Validate(priv *PrivateKey) error {
	expectedPrivateKey := privateKeyFromSeed(priv.Seed())
	if subtle.ConstantTimeCompare(priv.Key, expectedPrivateKey) == 0 {
		return errors.KeyInvalidError("ed25519: invalid ed25519 secret")
	}
	if subtle.ConstantTimeCompare(priv.PublicKey.Point, expectedPrivateKey[SeedSize:]) == 0 {
		return errors.KeyInvalidError("ed25519: invalid ed25519 public key")
	}
	return nil
}

// Public returns the public key corresponding to this private key, so that
// *PrivateKey implements crypto.Signer.
func (sk *PrivateKey) Public() crypto.PublicKey {
	pub := make([]byte, PublicKeySize)
	copy(pub, sk.PublicKey.Point)
	return &PublicKey{Point: pub}
}

// Sign implements crypto.Signer for the pure Ed25519 scheme: ed25519 does no
// pre-hashing, so digest must already hold the full message to sign and opts
// must be crypto.Hash(0) (signing a digested message is not supported). rand
// is ignored: wallet ed25519 signatures are deterministic.
func (sk *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, stdErrors.New("ed25519: cannot sign a pre-hashed message")
	}
	if err := Validate(sk); err != nil {
		return nil, err
	}
	return Sign(sk, digest)
}

// ENCODING/DECODING signature:

// WriteSignature encodes and writes an ed25519 signature to writer.
func WriteSignature(writer io.Writer, signature []byte) error {
	_, err := writer.Write(signature)
	return err
}

// ReadSignature decodes an ed25519 signature from a reader.
func ReadSignature(reader io.Reader) ([]byte, error) {
	signature := make([]byte, SignatureSize)
	if _, err := io.ReadFull(reader, signature); err != nil {
		return nil, err
	}
	return signature, nil
}
