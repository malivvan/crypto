// Package wallet provides a high-level, chainable API on top of the
// github.com/malivvan/crypto/pgp package. A wallet holds a single
// OpenPGP entity whose key material is deterministically derived from a
// mnemonic seed (BIP-39 + SLIP-10/SLIP-21), plus the packet configuration
// used for all cryptographic operations.
//
// All message operations are exposed as fluent builders that mirror the
// underlying OpenPGP options (armor, text signatures, file hints, custom
// packet configs, recipients, passwords, signers, ...). Terminal methods
// (Output, String, Bytes, Verify, Message, Plaintext) execute the operation.
package wallet

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/pgp"
	"github.com/malivvan/crypto/pgp/eddsa"
	"github.com/malivvan/crypto/pgp/packet"
	"github.com/malivvan/crypto/pgp/s2k"
	"github.com/malivvan/crypto/wallet/bip39"
	"github.com/malivvan/crypto/wallet/slip10"
	"github.com/malivvan/crypto/wallet/slip21"
	"github.com/malivvan/crypto/x25519"
)

const (
	// rootPath derives the primary signing key.
	rootPath = uint32(2763105104)
	// signPath derives the dedicated signing subkey.
	signPath = uint32(4115595627)
	// encrPath derives the encryption subkey.
	encrPath = uint32(2670132125)
	// authPath derives the authentication subkey.
	authPath = uint32(3927356478)
)

// Defaults returns the packet configuration used by NewWallet when the
// config argument is nil: SHA-512 hashes, AES-256 with AEAD (EAX/OCB),
// ZLIB compression and Argon2 key derivation.
func Defaults() *packet.Config {
	return &packet.Config{
		AEADConfig:             &packet.AEADConfig{},
		DefaultHash:            crypto.SHA512,
		DefaultCipher:          packet.CipherAES256,
		CompressionConfig:      &packet.CompressionConfig{Level: 9},
		DefaultCompressionAlgo: packet.CompressionZLIB,
		S2KConfig: &s2k.Config{
			Hash:    crypto.SHA512,
			S2KMode: s2k.Argon2S2K,
			Argon2Config: &s2k.Argon2Config{
				DegreeOfParallelism: 4,
				NumberOfPasses:      2,
				Memory:              64,
			},
		},
	}
}

// NewWallet creates a new Wallet from a mnemonic seed. The primary signing
// key and the decryption, signing and authentication subkeys are derived
// deterministically from the seed using SLIP-10; the returned Wallet is
// therefore reproducible from the same mnemonic and password.
//
// The password is only read, never retained or modified: the caller keeps
// ownership of the slice and is responsible for zeroing it if it is sensitive.
func NewWallet(name, email, mnemonic string, password []byte, config *packet.Config) (Wallet, error) {
	if password == nil {
		return nil, fmt.Errorf("wallet: password must not be nil")
	}
	if config == nil {
		config = Defaults()
	}
	// v4 keys carry their key preferences in the user-id self-signature, so
	// an identity is mandatory; only v6 keys can be generated without one.
	if name == "" && email == "" && !config.V6() {
		return nil, fmt.Errorf("wallet: a user id (name or email) is required for non-v6 keys")
	}

	slip10Node, slip21Node, err := func() (slip10.Node, slip21.Node, error) {
		seed := bip39.NewSeed(mnemonic, string(password))
		defer clear(seed)

		slip10Node, err := slip10.NewMasterNode(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating slip10 master node: %w", err)
		}
		slip21Node, err := slip21.NewMasterNode(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating slip21 master node: %w", err)
		}
		return slip10Node, slip21Node, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("error generating seed: %w", err)
	}

	creationTime := config.Now()

	// Primary signing key, derived from the root path.
	primarySub, err := slip10Node.Derive(rootPath)
	if err != nil {
		return nil, fmt.Errorf("error generating master key: %w", err)
	}
	primaryKey, err := pgp.NewSigner(configSeed(config, primarySub.PrivateKey()), pgp.SignerAlgorithm(config))
	if err != nil {
		return nil, fmt.Errorf("error generating primary key from seed: %w", err)
	}
	primary := packet.NewSignerPrivateKey(creationTime, primaryKey)
	if config.V6() {
		if err := primary.UpgradeToV6(); err != nil {
			return nil, err
		}
	}
	entity := &pgp.Entity{
		PrimaryKey:       &primary.PublicKey,
		PrivateKey:       primary,
		Identities:       make(map[string]*pgp.Identity),
		Subkeys:          []pgp.Subkey{},
		DirectSignatures: []*packet.VerifiableSignature{},
	}
	if config.V6() {
		// v6 keys carry a direct key signature advertising the key properties.
		if err := entity.AddDirectKeySignature(config); err != nil {
			return nil, err
		}
	}
	if name != "" || email != "" {
		if err := entity.AddUserId(name, "", email, config); err != nil {
			return nil, err
		}
	}

	// Decryption, signing and authentication subkeys, each derived from its
	// own SLIP-10 path. The derived seed is injected through the config RNG
	// so that the entity construction is fully deterministic.
	decryptionSub, err := slip10Node.Derive(encrPath)
	if err != nil {
		return nil, fmt.Errorf("error generating decrypting key: %w", err)
	}
	if err := entity.AddEncryptionSubkey(configSeed(config, decryptionSub.PrivateKey())); err != nil {
		return nil, fmt.Errorf("error generating decrypting key from seed: %w", err)
	}

	signingSub, err := slip10Node.Derive(signPath)
	if err != nil {
		return nil, fmt.Errorf("error generating signing key: %w", err)
	}
	if err := entity.AddSigningSubkey(configSeed(config, signingSub.PrivateKey())); err != nil {
		return nil, fmt.Errorf("error generating signing key from seed: %w", err)
	}

	authSub, err := slip10Node.Derive(authPath)
	if err != nil {
		return nil, fmt.Errorf("error generating authentication key: %w", err)
	}
	if err := entity.AddAuthenticationSubkey(configSeed(config, authSub.PrivateKey())); err != nil {
		return nil, fmt.Errorf("error generating authentication key from seed: %w", err)
	}

	// Verify that the entity exposes the keys the chaining operations need,
	// so that misuse fails fast at creation instead of at operation time.
	wallet := &wallet{
		config: config,
		entity: entity,
		slip10: slip10Node,
		slip21: slip21Node,
	}
	if _, ok := entity.SigningKey(creationTime, config); !ok {
		return nil, fmt.Errorf("error retrieving signing key")
	}
	if _, ok := entity.EncryptionKey(creationTime, config); !ok {
		return nil, fmt.Errorf("error retrieving encryption key")
	}
	return wallet, nil
}

// Wallet is the high-level wallet interface. It combines hierarchical
// key derivation (SLIP-10/SLIP-21) with chainable OpenPGP message
// operations. Every operation returns a fluent builder that is executed
// by its terminal methods, mirroring the options of the underlying
// pgp package.
type Wallet interface {
	// DeriveEd25519 derives an Ed25519 signing/authentication key from the
	// wallet's SLIP-10 master node. Every path index must be hardened
	// (>= 2^31); unhardened or empty paths are rejected. The key is fully
	// deterministic for a given mnemonic, password and path and is
	// interchangeable with other Ed25519 ecosystems through its Seed.
	DeriveEd25519(path ...uint32) (*ed25519.PrivateKey, error)
	// DeriveX25519 derives the 32-byte seed of an X25519 encryption key from
	// the wallet's SLIP-10 master node. Every path index must be hardened
	// (>= 2^31); unhardened or empty paths are rejected.
	DeriveX25519(path ...uint32) (*x25519.PrivateKey, error)
	// SigningKey returns the wallet's OpenPGP signing key as a raw
	// *ed25519.PrivateKey. This is the same key used for GPG (OpenPGP)
	// detached signing and is the key meant to back the minisign format (see
	// the minisign package). For wallets derived from a mnemonic it is
	// derived deterministically from the signing SLIP-10 path; for wallets
	// loaded from a file it is reconstructed from the stored entity. It
	// returns an error if the signing key cannot be recovered (for example a
	// locked or missing private key).
	SigningKey() (*ed25519.PrivateKey, error)
	// DeriveSecret derives a symmetric key for application/storage use from
	// the wallet's SLIP-21 master node and the given non-empty labels. The
	// key is returned in a freshly allocated []byte owned by the caller,
	// which should be zeroed once it is no longer needed.
	DeriveSecret(labels ...[]byte) ([]byte, error)

	// Sign starts a detached-signature chain over v.
	Sign(v any) *DetachSigner
	// Verify starts a detached-signature verification chain over the signed
	// data v. Signatures are checked against the whole wallet keyring.
	Verify(v any) *DetachVerifier
	// Encrypt starts an encryption-only chain over plaintext v.
	Encrypt(v any) *Encryptor
	// EncryptSign starts an encrypt-and-sign chain over plaintext v. Unless
	// overridden, the message is signed by the wallet's own key.
	EncryptSign(v any) *Encryptor
	// Decrypt starts a decryption chain over the (possibly armored)
	// ciphertext v.
	Decrypt(v any) *Decryptor
	// DecryptVerify starts a decryption-and-verification chain over the
	// (possibly armored) ciphertext v. The plaintext is only returned once
	// an embedded signature has been verified against the wallet keyring.
	DecryptVerify(v any) *Decryptor
	// Clearsign starts a clearsign chain over plaintext v.
	Clearsign(v any) *Clearsigner

	// KeysById returns the keys matching id (KeyRing interface).
	KeysById(id uint64) []pgp.Key
	// EntitiesById returns the entities whose primary key matches id
	// (KeyRing interface).
	EntitiesById(id uint64) []*pgp.Entity
	// Entities returns the wallet's own entity followed by every keyring
	// entity.
	Entities() []*pgp.Entity
	// AddEntity imports a trusted entity (public key) into the wallet's
	// keyring.
	AddEntity(e *pgp.Entity) error

	// IsLocked reports whether the wallet's private keys are passphrase
	// encrypted.
	IsLocked() bool
	// Lock encrypts all private keys with the given passphrase. Locked
	// wallets must be unlocked before signing or decrypting.
	Lock(password string) error
	// Unlock decrypts all private keys with the given passphrase.
	Unlock(password string) error

	// Save writes the whole wallet (own locked private key plus keyring
	// entities) to w in ASCII armor.
	Save(w io.Writer) error
}

type wallet struct {
	config   *packet.Config
	entity   *pgp.Entity
	entities []*pgp.Entity // trusted keyring entities
	slip21   slip21.Node
	slip10   slip10.Node
}

// deriveSlip10 walks the wallet's SLIP-10 master node along a chain of
// hardened indices. Public (unhardened) derivation is deliberately rejected:
// Ed25519/X25519 keys must only be derived from hardened nodes.
func (wl *wallet) deriveSlip10(path []uint32) (slip10.Node, error) {
	if wl.slip10 == nil {
		return nil, fmt.Errorf("wallet: SLIP-10 master node unavailable (wallet was loaded from a file)")
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("wallet: empty SLIP-10 derivation path")
	}
	node := wl.slip10
	for _, index := range path {
		if index < slip10.FirstHardenedIndex {
			return nil, fmt.Errorf("wallet: SLIP-10 index %d is not hardened; use an index >= %d", index, slip10.FirstHardenedIndex)
		}
		var err error
		node, err = node.Derive(index)
		if err != nil {
			return nil, err
		}
	}
	return node, nil
}

// deriveSlip21 walks the wallet's SLIP-21 master node along a chain of
// non-empty labels.
func (wl *wallet) deriveSlip21(labels [][]byte) (slip21.Node, error) {
	if wl.slip21 == nil {
		return nil, fmt.Errorf("wallet: SLIP-21 master node unavailable (wallet was loaded from a file)")
	}
	if len(labels) == 0 {
		return nil, fmt.Errorf("wallet: empty SLIP-21 label path")
	}
	node := wl.slip21
	for _, label := range labels {
		if len(label) == 0 {
			return nil, fmt.Errorf("wallet: empty SLIP-21 label")
		}
		var err error
		node, err = node.Derive(label)
		if err != nil {
			return nil, err
		}
	}
	return node, nil
}

// DeriveEd25519 derives an Ed25519 signing/authentication key.
func (wl *wallet) DeriveEd25519(path ...uint32) (*ed25519.PrivateKey, error) {
	node, err := wl.deriveSlip10(path)
	if err != nil {
		return nil, err
	}
	return ed25519.GenerateKeyFromSeed(node.PrivateKey())
}

// SigningKey returns the wallet's OpenPGP signing key as a raw
// *ed25519.PrivateKey. This is the same key used for GPG/OpenPGP detached
// signing and backs the minisign package.
func (wl *wallet) SigningKey() (*ed25519.PrivateKey, error) {
	// For mnemonic-derived wallets the SLIP-10 master node is available and
	// the signing key is the deterministic key derived from signPath.
	if wl.slip10 != nil {
		return wl.DeriveEd25519(signPath)
	}

	// For wallets loaded from a file the private key lives in the stored
	// entity. Recover the signing subkey and normalize its material to a
	// *wallet/ed25519.PrivateKey. Both the legacy EdDSA (v4) and the modern
	// Ed25519 (v6) encoding carry the same raw RFC 8032 32-byte seed.
	signingKey, ok := wl.entity.SigningKeyById(wl.config.Now(), wl.config.SigningKey(), wl.config)
	if !ok {
		return nil, fmt.Errorf("wallet: no usable signing key in entity")
	}
	pk := signingKey.PrivateKey
	if pk == nil {
		return nil, fmt.Errorf("wallet: no private key material for the signing key")
	}
	if pk.Encrypted {
		return nil, fmt.Errorf("wallet: signing key is locked; unlock the wallet first")
	}
	switch raw := pk.PrivateKey.(type) {
	case *eddsa.PrivateKey:
		return ed25519.GenerateKeyFromSeed(raw.D)
	case *ed25519.PrivateKey:
		return ed25519.GenerateKeyFromSeed(raw.Seed())
	default:
		return nil, fmt.Errorf("wallet: unsupported signing key material %T", pk.PrivateKey)
	}
}

// DeriveX25519 derives the 32-byte seed of an X25519 encryption key.
func (wl *wallet) DeriveX25519(path ...uint32) (*x25519.PrivateKey, error) {
	node, err := wl.deriveSlip10(path)
	if err != nil {
		return nil, err
	}
	return x25519.GenerateKeyFromSeed(node.PrivateKey())
}

// DeriveSecret derives a symmetric application/storage key. The returned
// slice is a copy owned by the caller.
func (wl *wallet) DeriveSecret(labels ...[]byte) ([]byte, error) {
	node, err := wl.deriveSlip21(labels)
	if err != nil {
		return nil, err
	}
	key := node.Key()
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

func (wl *wallet) Sign(v any) *DetachSigner {
	reader, err := readerFrom(v)
	return &DetachSigner{
		wallet:  wl,
		reader:  reader,
		err:     err,
		signers: []*pgp.Entity{wl.entity},
	}
}

func (wl *wallet) Verify(v any) *DetachVerifier {
	reader, err := readerFrom(v)
	return &DetachVerifier{
		wallet: wl,
		data:   reader,
		err:    err,
	}
}

func (wl *wallet) Encrypt(v any) *Encryptor {
	reader, err := readerFrom(v)
	return &Encryptor{
		wallet: wl,
		reader: reader,
		err:    err,
	}
}

func (wl *wallet) EncryptSign(v any) *Encryptor {
	return wl.Encrypt(v).Sign(wl.entity)
}

func (wl *wallet) Decrypt(v any) *Decryptor {
	reader, err := readerFrom(v)
	return &Decryptor{
		wallet: wl,
		reader: reader,
		err:    err,
	}
}

func (wl *wallet) DecryptVerify(v any) *Decryptor {
	reader, err := readerFrom(v)
	return &Decryptor{
		wallet: wl,
		reader: reader,
		err:    err,
		verify: true,
	}
}

func (wl *wallet) Clearsign(v any) *Clearsigner {
	reader, err := readerFrom(v)
	return &Clearsigner{
		wallet:  wl,
		reader:  reader,
		err:     err,
		signers: []*pgp.Entity{wl.entity},
	}
}

// resolveConfig returns the config to use for a chained operation: the
// per-call override if one was configured, the wallet config otherwise.
func (wl *wallet) resolveConfig(override *packet.Config) *packet.Config {
	if override != nil {
		return override
	}
	return wl.config
}

// configSeed clones the given config and points its random source at the
// given seed bytes, making key generation deterministic. Once the seed has
// been consumed, entropy falls back to crypto/rand so that subsequent
// operations (e.g. randomized signature creation) still work.
func configSeed(config *packet.Config, seed []byte) *packet.Config {
	if config == nil {
		config = &packet.Config{}
	}
	return &packet.Config{
		DefaultCipher: config.Cipher(),
		DefaultHash:   config.Hash(),
		Time:          config.Time,
		Rand:          io.MultiReader(bytes.NewReader(seed), rand.Reader),
		AEADConfig:    config.AEAD(),
		Algorithm:     config.Algorithm,
		Curve:         config.Curve,
		V6Keys:        config.V6Keys,
	}
}

// readerFrom converts a plain value into an io.Reader. Strings and []byte
// are wrapped in a bytes.Buffer and io.Readers are passed through unchanged.
// Any other value (including nil) yields an error instead of silently
// producing an empty message, which would otherwise be a silent data-loss
// trap.
func readerFrom(v any) (io.Reader, error) {
	switch t := v.(type) {
	case string:
		return bytes.NewBufferString(t), nil
	case []byte:
		return bytes.NewBuffer(t), nil
	case io.Reader:
		if t == nil {
			return nil, fmt.Errorf("wallet: input is nil")
		}
		return t, nil
	default:
		return nil, fmt.Errorf("wallet: unsupported input type %T; use string, []byte or io.Reader", v)
	}
}
