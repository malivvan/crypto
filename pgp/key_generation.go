// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pgp

import (
	"crypto"
	"time"

	"github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/internal/algorithm"
	"github.com/malivvan/crypto/internal/ecc"
	"github.com/malivvan/crypto/pgp/ecdh"
	"github.com/malivvan/crypto/pgp/eddsa"
	"github.com/malivvan/crypto/pgp/errors"
	"github.com/malivvan/crypto/pgp/packet"
	"github.com/malivvan/crypto/x25519"
)

type userIdData struct {
	name, comment, email string
}

type keyProperties struct {
	primaryKey      *packet.PrivateKey
	creationTime    time.Time
	keyLifetimeSecs uint32
	hash            crypto.Hash
	cipher          packet.CipherFunction
	aead            *packet.AEADConfig
	compression     packet.CompressionAlgo
}

// NewEntityWithoutId returns an Entity that contains fresh keys for signing and
// encrypting pgp messages. The key is not associated with an identity.
// This is only allowed for v6 key generation. If v6 is not enabled,
// it will return an error.
// If config is nil, sensible defaults will be used.
func NewEntityWithoutId(config *packet.Config) (*Entity, error) {
	return newEntity(nil, config)
}

// NewEntity returns an Entity that contains fresh keys with a for signing and
// encrypting pgp messages. The key is associated with a
// single identity composed of the given full name, comment and email, any of
// which may be empty but must not contain any of "()<>\x00".
// If config is nil, sensible defaults will be used.
//
// The generated entity has the following configuration:
//   - one ed25519 primary key (sign + certify)
//   - one ed25519 signing subkey
//   - one x25519 encryption subkey
//   - one ed25519 authentication subkey
func NewEntity(name, comment, email string, config *packet.Config) (*Entity, error) {
	return newEntity(&userIdData{name, comment, email}, config)
}

// SignerAlgorithm determines the signing key algorithm based on the config.
func SignerAlgorithm(config *packet.Config) packet.PublicKeyAlgorithm {
	algo := config.PublicKeyAlgorithm()
	if !algo.CanSign() {
		// Encryption-only algorithms select a matching signing key.
		if config.V6() {
			return packet.PubKeyAlgoEd25519
		}
		return packet.PubKeyAlgoEdDSA
	}
	if config.V6() && algo == packet.PubKeyAlgoEdDSA {
		// v6 keys must not use the legacy EdDSA encoding.
		return packet.PubKeyAlgoEd25519
	}
	if !config.V6() && algo == packet.PubKeyAlgoEd25519 {
		// v4 ed25519 keys use the legacy EdDSA encoding.
		return packet.PubKeyAlgoEdDSA
	}
	return algo
}

// DecrypterAlgorithm determines the encryption key algorithm based on the config.
func DecrypterAlgorithm(config *packet.Config) packet.PublicKeyAlgorithm {
	if config.V6() {
		// v6 keys use the modern X25519 encoding.
		return packet.PubKeyAlgoX25519
	}
	// v4 keys use ECDH over Curve25519.
	return packet.PubKeyAlgoECDH
}

func selectKeyProperties(creationTime time.Time, config *packet.Config, primary *packet.PrivateKey) *keyProperties {
	return &keyProperties{
		primaryKey:      primary,
		creationTime:    creationTime,
		keyLifetimeSecs: config.KeyLifetime(),
		hash:            config.Hash(),
		cipher:          config.Cipher(),
		aead:            config.AEAD(),
		compression:     config.Compression(),
	}
}

func newEntity(uid *userIdData, config *packet.Config) (*Entity, error) {
	if uid == nil && !config.V6() {
		return nil, errors.InvalidArgumentError("user id has to be set for non-v6 keys")
	}
	creationTime := config.Now()

	// Generate a primary signing key
	primaryPrivRaw, err := NewSigner(config, SignerAlgorithm(config))
	if err != nil {
		return nil, err
	}
	primary := packet.NewSignerPrivateKey(creationTime, primaryPrivRaw)
	if config.V6() {
		if err := primary.UpgradeToV6(); err != nil {
			return nil, err
		}
	}

	keyProperties := selectKeyProperties(creationTime, config, primary)

	e := &Entity{
		PrimaryKey:       &primary.PublicKey,
		PrivateKey:       primary,
		Identities:       make(map[string]*Identity),
		Subkeys:          []Subkey{},
		DirectSignatures: []*packet.VerifiableSignature{},
	}

	if config.V6() {
		if err := e.AddDirectKeySignature(config); err != nil {
			return nil, err
		}
		keyProperties = nil
	}

	if uid != nil {
		err = e.addUserId(*uid, config, keyProperties)
		if err != nil {
			return nil, err
		}
	}

	// NOTE: No key expiry here, but we will not return this subkey in EncryptionKey()
	// if the primary/master key has expired.
	err = e.addEncryptionSubkey(config, creationTime, 0)
	if err != nil {
		return nil, err
	}

	// Add a dedicated signing subkey and an authentication subkey.
	if err := e.AddSigningSubkey(config); err != nil {
		return nil, err
	}
	if err := e.AddAuthenticationSubkey(config); err != nil {
		return nil, err
	}

	return e, nil
}

// AddUserId adds a user-id packet to the given entity.
func (t *Entity) AddUserId(name, comment, email string, config *packet.Config) error {
	var keyProperties *keyProperties
	if !config.V6() {
		keyProperties = selectKeyProperties(config.Now(), config, t.PrivateKey)
	}
	return t.addUserId(userIdData{name, comment, email}, config, keyProperties)
}

// AddDirectKeySignature adds a fresh direct key signature that advertises the
// key preferences derived from the given config. It is only used for v6 keys.
func (t *Entity) AddDirectKeySignature(config *packet.Config) error {
	selectedKeyProperties := selectKeyProperties(config.Now(), config, t.PrivateKey)
	selfSignature := createSignaturePacket(&t.PrivateKey.PublicKey, packet.SigTypeDirectSignature, config)
	err := writeKeyProperties(selfSignature, selectedKeyProperties)
	if err != nil {
		return err
	}
	err = selfSignature.SignDirectKeyBinding(&t.PrivateKey.PublicKey, t.PrivateKey, config)
	if err != nil {
		return err
	}
	t.DirectSignatures = append(t.DirectSignatures, packet.NewVerifiableSig(selfSignature))
	return nil
}

func writeKeyProperties(selfSignature *packet.Signature, selectedKeyProperties *keyProperties) error {
	advertiseAead := selectedKeyProperties.aead != nil

	selfSignature.CreationTime = selectedKeyProperties.creationTime
	selfSignature.KeyLifetimeSecs = &selectedKeyProperties.keyLifetimeSecs
	selfSignature.FlagsValid = true
	selfSignature.FlagSign = true
	selfSignature.FlagCertify = true
	selfSignature.SEIPDv1 = true // true by default, see 5.8 vs. 5.14
	selfSignature.SEIPDv2 = advertiseAead

	// Set the PreferredHash for the SelfSignature from the packet.Config.
	// If it is not the must-implement algorithm from rfc4880bis, append that.
	hash, ok := algorithm.HashToHashId(selectedKeyProperties.hash)
	if !ok {
		return errors.UnsupportedError("unsupported preferred hash function")
	}

	selfSignature.PreferredHash = []uint8{}
	// Ensure that for signing algorithms with higher security level an
	// appropriate a matching hash function is available.
	acceptableHashes := acceptableHashesToWrite(&selectedKeyProperties.primaryKey.PublicKey)
	var match bool
	for _, acceptableHash := range acceptableHashes {
		if acceptableHash == hash {
			match = true
			break
		}
	}
	if !match && len(acceptableHashes) > 0 {
		selfSignature.PreferredHash = []uint8{acceptableHashes[0]}
	}

	selfSignature.PreferredHash = append(selfSignature.PreferredHash, hash)
	if selectedKeyProperties.hash != crypto.SHA256 {
		selfSignature.PreferredHash = append(selfSignature.PreferredHash, hashToHashId(crypto.SHA256))
	}

	// Likewise for DefaultCipher.
	selfSignature.PreferredSymmetric = []uint8{uint8(selectedKeyProperties.cipher)}
	if selectedKeyProperties.cipher != packet.CipherAES128 {
		selfSignature.PreferredSymmetric = append(selfSignature.PreferredSymmetric, uint8(packet.CipherAES128))
	}

	// We set CompressionNone as the preferred compression algorithm because
	// of compression side channel attacks, then append the configured
	// DefaultCompressionAlgo if any is set (to signal support for cases
	// where the application knows that using compression is safe).
	selfSignature.PreferredCompression = []uint8{uint8(packet.CompressionNone)}
	if selectedKeyProperties.compression != packet.CompressionNone {
		selfSignature.PreferredCompression = append(selfSignature.PreferredCompression, uint8(selectedKeyProperties.compression))
	}

	if advertiseAead {
		// Get the preferred AEAD mode from the packet.Config.
		// If it is not the must-implement algorithm from rfc9580, append that.
		modes := []uint8{uint8(selectedKeyProperties.aead.Mode())}
		if selectedKeyProperties.aead.Mode() != packet.AEADModeOCB {
			modes = append(modes, uint8(packet.AEADModeOCB))
		}

		// Generate the cipher suites from the preferred symmetric ciphers
		// and the supported AEAD modes (EAX, OCB).
		for _, cipher := range selfSignature.PreferredSymmetric {
			for _, mode := range modes {
				selfSignature.PreferredCipherSuites = append(selfSignature.PreferredCipherSuites, [2]uint8{cipher, mode})
			}
		}
	}

	return nil
}

func (t *Entity) addUserId(userIdData userIdData, config *packet.Config, selectedKeyProperties *keyProperties) error {
	uid := packet.NewUserId(userIdData.name, userIdData.comment, userIdData.email)
	if uid == nil {
		return errors.InvalidArgumentError("user id field contained invalid characters")
	}

	if _, ok := t.Identities[uid.Id]; ok {
		return errors.InvalidArgumentError("user id exist")
	}

	primary := t.PrivateKey
	isPrimaryId := len(t.Identities) == 0
	selfSignature := createSignaturePacket(&primary.PublicKey, packet.SigTypePositiveCert, config)
	if selectedKeyProperties != nil {
		err := writeKeyProperties(selfSignature, selectedKeyProperties)
		if err != nil {
			return err
		}
	}
	selfSignature.IsPrimaryId = &isPrimaryId

	// User ID binding signature
	err := selfSignature.SignUserId(uid.Id, &primary.PublicKey, primary, config)
	if err != nil {
		return err
	}
	t.Identities[uid.Id] = &Identity{
		Primary:            t,
		Name:               uid.Id,
		UserId:             uid,
		SelfCertifications: []*packet.VerifiableSignature{packet.NewVerifiableSig(selfSignature)},
	}
	return nil
}

// AddSigningSubkey adds an ed25519 signing keypair as a subkey to the Entity.
// If config is nil, sensible defaults will be used.
func (e *Entity) AddSigningSubkey(config *packet.Config) error {
	creationTime := config.Now()
	keyLifetimeSecs := config.KeyLifetime()

	subPrivRaw, err := NewSigner(config, SignerAlgorithm(config))
	if err != nil {
		return err
	}
	sub := packet.NewSignerPrivateKey(creationTime, subPrivRaw)
	sub.IsSubkey = true
	// Every subkey for a v6 primary key MUST be a v6 subkey.
	if e.PrimaryKey.Version == 6 {
		if err := sub.UpgradeToV6(); err != nil {
			return err
		}
	}

	subkey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
	}
	sig := createSignaturePacket(e.PrimaryKey, packet.SigTypeSubkeyBinding, config)
	sig.CreationTime = creationTime
	sig.KeyLifetimeSecs = &keyLifetimeSecs
	sig.FlagsValid = true
	sig.FlagSign = true
	sig.EmbeddedSignature = createSignaturePacket(subkey.PublicKey, packet.SigTypePrimaryKeyBinding, config)
	sig.EmbeddedSignature.CreationTime = creationTime

	err = sig.EmbeddedSignature.CrossSignKey(subkey.PublicKey, e.PrimaryKey, subkey.PrivateKey, config)
	if err != nil {
		return err
	}

	err = sig.SignKey(subkey.PublicKey, e.PrivateKey, config)
	if err != nil {
		return err
	}

	subkey.Bindings = []*packet.VerifiableSignature{packet.NewVerifiableSig(sig)}
	subkey.Primary = e

	e.Subkeys = append(e.Subkeys, subkey)
	return nil
}

// AddAuthenticationSubkey adds an ed25519 keypair as an authentication
// subkey to the Entity. Such subkeys are e.g. used for SSH authentication.
// If config is nil, sensible defaults will be used.
func (e *Entity) AddAuthenticationSubkey(config *packet.Config) error {
	creationTime := config.Now()
	keyLifetimeSecs := config.KeyLifetime()

	subPrivRaw, err := NewSigner(config, SignerAlgorithm(config))
	if err != nil {
		return err
	}
	sub := packet.NewSignerPrivateKey(creationTime, subPrivRaw)
	sub.IsSubkey = true
	// Every subkey for a v6 primary key MUST be a v6 subkey.
	if e.PrimaryKey.Version == 6 {
		if err := sub.UpgradeToV6(); err != nil {
			return err
		}
	}

	subkey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
	}
	sig := createSignaturePacket(e.PrimaryKey, packet.SigTypeSubkeyBinding, config)
	sig.CreationTime = creationTime
	sig.KeyLifetimeSecs = &keyLifetimeSecs
	sig.FlagsValid = true
	sig.FlagAuthenticate = true

	err = sig.SignKey(subkey.PublicKey, e.PrivateKey, config)
	if err != nil {
		return err
	}

	subkey.Bindings = []*packet.VerifiableSignature{packet.NewVerifiableSig(sig)}
	subkey.Primary = e

	e.Subkeys = append(e.Subkeys, subkey)
	return nil
}

// AddEncryptionSubkey adds an encryption keypair as a subkey to the Entity.
// If config is nil, sensible defaults will be used.
func (e *Entity) AddEncryptionSubkey(config *packet.Config) error {
	creationTime := config.Now()
	keyLifetimeSecs := config.KeyLifetime()
	return e.addEncryptionSubkey(config, creationTime, keyLifetimeSecs)
}

func (e *Entity) addEncryptionSubkey(config *packet.Config, creationTime time.Time, keyLifetimeSecs uint32) error {
	subPrivRaw, err := NewDecrypter(config, DecrypterAlgorithm(config))
	if err != nil {
		return err
	}
	sub := packet.NewDecrypterPrivateKey(creationTime, subPrivRaw)
	sub.IsSubkey = true
	// Every subkey for a v6 primary key MUST be a v6 subkey.
	if e.PrimaryKey.Version == 6 {
		if err := sub.UpgradeToV6(); err != nil {
			return err
		}
	}

	subkey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
	}
	sig := createSignaturePacket(e.PrimaryKey, packet.SigTypeSubkeyBinding, config)
	sig.CreationTime = creationTime
	sig.KeyLifetimeSecs = &keyLifetimeSecs
	sig.FlagsValid = true
	sig.FlagEncryptStorage = true
	sig.FlagEncryptCommunications = true

	err = sig.SignKey(subkey.PublicKey, e.PrivateKey, config)
	if err != nil {
		return err
	}

	subkey.Bindings = []*packet.VerifiableSignature{packet.NewVerifiableSig(sig)}

	subkey.Primary = e
	e.Subkeys = append(e.Subkeys, subkey)
	return nil
}

// NewSigner generates an Ed25519 signing key. The key material is read from
// config.Random(), so callers can seed the RNG to derive deterministic keys.
// The returned value is either an *eddsa.PrivateKey or an *ed25519.PrivateKey,
// both of which implement crypto.Signer.
func NewSigner(config *packet.Config, algo packet.PublicKeyAlgorithm) (signer interface{}, err error) {
	switch algo {
	case packet.PubKeyAlgoEdDSA:
		if config.V6() {
			// Implementations MUST NOT accept or generate v6 key material
			// using the deprecated OIDs.
			return nil, errors.InvalidArgumentError("EdDSALegacy cannot be used for v6 keys")
		}
		curve := ecc.FindEdDSAByGenName(string(config.CurveName()))
		if curve == nil {
			return nil, errors.InvalidArgumentError("unsupported curve")
		}

		priv, err := eddsa.GenerateKey(config.Random(), curve)
		if err != nil {
			return nil, err
		}
		return priv, nil
	case packet.PubKeyAlgoEd25519:
		priv, err := ed25519.GenerateKey(config.Random())
		if err != nil {
			return nil, err
		}
		return priv, nil
	default:
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}
}

// NewDecrypter generates an X25519 or ECDH encryption/decryption key. The key
// material is read from config.Random(), so callers can seed the RNG to derive
// deterministic keys. The returned value satisfies the packet.X25519Decrypter
// interface.
func NewDecrypter(config *packet.Config, algo packet.PublicKeyAlgorithm) (decrypter interface{}, err error) {
	switch algo {
	case packet.PubKeyAlgoECDH:
		if config.V6() {
			// Implementations MUST NOT accept or generate v6 key material
			// using the deprecated OIDs.
			return nil, errors.InvalidArgumentError("ECDH with Curve25519 legacy cannot be used for v6 keys")
		}
		var kdf = ecdh.KDF{
			Hash:   algorithm.SHA512,
			Cipher: algorithm.AES256,
		}
		curve := ecc.FindECDHByGenName(string(config.CurveName()))
		if curve == nil {
			return nil, errors.InvalidArgumentError("unsupported curve")
		}
		return ecdh.GenerateKey(config.Random(), curve, kdf)
	case packet.PubKeyAlgoX25519:
		return x25519.GenerateKey(config.Random())
	default:
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}
}
