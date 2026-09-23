// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	stdEd25519 "crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/hkdf"
	"github.com/malivvan/crypto/internal/encoding"
	"github.com/malivvan/crypto/pgp/ecdh"
	"github.com/malivvan/crypto/pgp/eddsa"
	"github.com/malivvan/crypto/pgp/errors"
	"github.com/malivvan/crypto/pgp/s2k"
	"github.com/malivvan/crypto/x25519"
)

// PrivateKey represents a possibly encrypted private key. See RFC 4880,
// section 5.5.3.
type PrivateKey struct {
	PublicKey
	Encrypted     bool // if true then the private key is unavailable until Decrypt has been called.
	encryptedData []byte
	cipher        CipherFunction
	s2k           func(out, in []byte)
	aead          AEADMode // only relevant if S2KAEAD is enabled
	// An *{ecdh|eddsa|ed25519|x25519}.PrivateKey or
	// crypto.Signer/X25519Decrypter (for keys backed by external
	// hardware, e.g. a YubiKey).
	PrivateKey interface{}
	iv         []byte

	// Type of encryption of the S2K packet
	// Allowed values are 0 (Not encrypted), 253 (AEAD), 254 (SHA1), or
	// 255 (2-byte checksum)
	s2kType S2KType
	// Full parameters of the S2K packet
	s2kParams *s2k.Params
}

// S2KType s2k packet type
type S2KType uint8

const (
	// S2KNON unencrypt
	S2KNON S2KType = 0
	// S2KAEAD use authenticated encryption
	S2KAEAD S2KType = 253
	// S2KSHA1 sha1 sum check
	S2KSHA1 S2KType = 254
	// S2KCHECKSUM sum check
	S2KCHECKSUM S2KType = 255
)

// X25519Decrypter is implemented by private keys that are able to compute
// the X25519 shared secret on external hardware, such as a YubiKey. It can
// be used as the PrivateKey value of a packet.PrivateKey to enable
// decryption with hardware-backed keys.
type X25519Decrypter interface {
	// DecryptX25519 computes the X25519 shared secret with the given
	// ephemeral public key (raw, unprefixed format).
	DecryptX25519(ephemeralPublic []byte) (sharedSecret []byte, err error)
}

func NewEdDSAPrivateKey(creationTime time.Time, priv *eddsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewEdDSAPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewECDHPrivateKey(creationTime time.Time, priv *ecdh.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDHPublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewX25519PrivateKey(creationTime time.Time, priv *x25519.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewX25519PublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewEd25519PrivateKey(creationTime time.Time, priv *ed25519.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewEd25519PublicKey(creationTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

// NewSignerPrivateKey creates a PrivateKey from a crypto.Signer that
// implements EdDSA or Ed25519. Hardware-backed signers (e.g. YubiKeys) are
// supported as long as their public key is a crypto/ed25519.PublicKey.
func NewSignerPrivateKey(creationTime time.Time, signer interface{}) *PrivateKey {
	pk := new(PrivateKey)
	// In general, the public Keys should be used as pointers. We still
	// type-switch on the values, for backwards-compatibility.
	switch pubkey := signer.(type) {
	case *eddsa.PrivateKey:
		pk.PublicKey = *NewEdDSAPublicKey(creationTime, &pubkey.PublicKey)
	case eddsa.PrivateKey:
		pk.PublicKey = *NewEdDSAPublicKey(creationTime, &pubkey.PublicKey)
	case *ed25519.PrivateKey:
		pk.PublicKey = *NewEd25519PublicKey(creationTime, &pubkey.PublicKey)
	case ed25519.PrivateKey:
		pk.PublicKey = *NewEd25519PublicKey(creationTime, &pubkey.PublicKey)
	default:
		s, ok := signer.(crypto.Signer)
		if !ok {
			panic("wallet: unknown signer type in NewSignerPrivateKey")
		}
		switch pub := s.Public().(type) {
		case stdEd25519.PublicKey:
			edKey := &ed25519.PublicKey{Point: []byte(pub)}
			pk.PublicKey = *NewEd25519PublicKey(creationTime, edKey)
		default:
			panic("wallet: unsupported public key type in NewSignerPrivateKey")
		}
	}
	pk.PrivateKey = signer
	return pk
}

// NewDecrypterPrivateKey creates a PrivateKey from a *{ecdh|x25519}.PrivateKey.
func NewDecrypterPrivateKey(creationTime time.Time, decrypter interface{}) *PrivateKey {
	pk := new(PrivateKey)
	switch priv := decrypter.(type) {
	case *ecdh.PrivateKey:
		pk.PublicKey = *NewECDHPublicKey(creationTime, &priv.PublicKey)
	case *x25519.PrivateKey:
		pk.PublicKey = *NewX25519PublicKey(creationTime, &priv.PublicKey)
	default:
		panic("wallet: unknown decrypter type in NewDecrypterPrivateKey")
	}
	pk.PrivateKey = decrypter
	return pk
}

func (pk *PrivateKey) parse(r io.Reader) (err error) {
	err = (&pk.PublicKey).parse(r)
	if err != nil {
		return
	}
	v5 := pk.PublicKey.Version == 5
	v6 := pk.PublicKey.Version == 6

	if V5Disabled && v5 {
		return errors.UnsupportedError("support for parsing v5 entities is disabled; build with `-tags v5` if needed")
	}

	var buf [1]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}
	pk.s2kType = S2KType(buf[0])
	var optCount [1]byte
	if v5 || (v6 && pk.s2kType != S2KNON) {
		if _, err = readFull(r, optCount[:]); err != nil {
			return
		}
	}

	switch pk.s2kType {
	case S2KNON:
		pk.s2k = nil
		pk.Encrypted = false
	case S2KSHA1, S2KCHECKSUM, S2KAEAD:
		if (v5 || v6) && pk.s2kType == S2KCHECKSUM {
			return errors.StructuralError(fmt.Sprintf("wrong s2k identifier for version %d", pk.Version))
		}
		_, err = readFull(r, buf[:])
		if err != nil {
			return
		}
		pk.cipher = CipherFunction(buf[0])
		if pk.cipher != 0 && !pk.cipher.IsSupported() {
			return errors.UnsupportedError("unsupported cipher function in private key")
		}
		// [Optional] If string-to-key usage octet was 253,
		// a one-octet AEAD algorithm.
		if pk.s2kType == S2KAEAD {
			_, err = readFull(r, buf[:])
			if err != nil {
				return
			}
			pk.aead = AEADMode(buf[0])
			if !pk.aead.IsSupported() {
				return errors.UnsupportedError("unsupported aead mode in private key")
			}
		}

		// [Optional] Only for a version 6 packet,
		// and if string-to-key usage octet was 255, 254, or 253,
		// an one-octet count of the following field.
		if v6 {
			_, err = readFull(r, buf[:])
			if err != nil {
				return
			}
		}

		pk.s2kParams, err = s2k.ParseIntoParams(r)
		if err != nil {
			return
		}
		if pk.s2kParams.Dummy() {
			return
		}
		pk.s2k, err = pk.s2kParams.Function()
		if err != nil {
			return
		}
		pk.Encrypted = true
	default:
		return errors.UnsupportedError("deprecated s2k function in private key")
	}

	if pk.Encrypted {
		var ivSize int
		// If the S2K usage octet was 253, the IV is of the size expected by the AEAD mode,
		// unless it's a version 5 key, in which case it's the size of the symmetric cipher's block size.
		// For all other S2K modes, it's always the block size.
		if !v5 && pk.s2kType == S2KAEAD {
			ivSize = pk.aead.IvLength()
		} else {
			ivSize = pk.cipher.blockSize()
		}

		if ivSize == 0 {
			return errors.UnsupportedError("unsupported cipher in private key: " + strconv.Itoa(int(pk.cipher)))
		}
		pk.iv = make([]byte, ivSize)
		_, err = readFull(r, pk.iv)
		if err != nil {
			return
		}
		if v5 && pk.s2kType == S2KAEAD {
			pk.iv = pk.iv[:pk.aead.IvLength()]
		}
	}

	var privateKeyData []byte
	if v5 {
		var n [4]byte /* secret material four octet count */
		_, err = readFull(r, n[:])
		if err != nil {
			return
		}
		count := uint32(uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3]))
		if !pk.Encrypted {
			count = count + 2 /* two octet checksum */
		}
		privateKeyData = make([]byte, count)
		_, err = readFull(r, privateKeyData)
		if err != nil {
			return
		}
	} else {
		privateKeyData, err = io.ReadAll(r)
		if err != nil {
			return
		}
	}
	if !pk.Encrypted {
		if len(privateKeyData) < 2 {
			return errors.StructuralError("truncated private key data")
		}
		if pk.Version != 6 {
			// checksum
			var sum uint16
			for i := 0; i < len(privateKeyData)-2; i++ {
				sum += uint16(privateKeyData[i])
			}
			if privateKeyData[len(privateKeyData)-2] != uint8(sum>>8) ||
				privateKeyData[len(privateKeyData)-1] != uint8(sum) {
				return errors.StructuralError("private key checksum failure")
			}
			privateKeyData = privateKeyData[:len(privateKeyData)-2]
			return pk.parsePrivateKey(privateKeyData)
		} else {
			// No checksum
			return pk.parsePrivateKey(privateKeyData)
		}
	}

	pk.encryptedData = privateKeyData
	return
}

// Dummy returns true if the private key is a dummy key. This is a GNU extension.
func (pk *PrivateKey) Dummy() bool {
	return pk.s2kParams.Dummy()
}

func mod64kHash(d []byte) uint16 {
	var h uint16
	for _, b := range d {
		h += uint16(b)
	}
	return h
}

func (pk *PrivateKey) Serialize(w io.Writer) (err error) {
	contents := bytes.NewBuffer(nil)
	err = pk.PublicKey.serializeWithoutHeaders(contents)
	if err != nil {
		return
	}
	if _, err = contents.Write([]byte{uint8(pk.s2kType)}); err != nil {
		return
	}

	optional := bytes.NewBuffer(nil)
	if pk.Encrypted || pk.Dummy() {
		// [Optional] If string-to-key usage octet was 255, 254, or 253,
		// a one-octet symmetric encryption algorithm.
		if _, err = optional.Write([]byte{uint8(pk.cipher)}); err != nil {
			return
		}
		// [Optional] If string-to-key usage octet was 253,
		// a one-octet AEAD algorithm.
		if pk.s2kType == S2KAEAD {
			if _, err = optional.Write([]byte{uint8(pk.aead)}); err != nil {
				return
			}
		}

		s2kBuffer := bytes.NewBuffer(nil)
		if err := pk.s2kParams.Serialize(s2kBuffer); err != nil {
			return err
		}
		// [Optional] Only for a version 6 packet, and if string-to-key
		// usage octet was 255, 254, or 253, an one-octet
		// count of the following field.
		if pk.Version == 6 {
			if _, err = optional.Write([]byte{uint8(s2kBuffer.Len())}); err != nil {
				return
			}
		}
		// [Optional] If string-to-key usage octet was 255, 254, or 253,
		// a string-to-key (S2K) specifier. The length of the string-to-key specifier
		// depends on its type
		if _, err = io.Copy(optional, s2kBuffer); err != nil {
			return
		}

		// IV
		if pk.Encrypted {
			if _, err = optional.Write(pk.iv); err != nil {
				return
			}
			if pk.Version == 5 && pk.s2kType == S2KAEAD {
				// Add padding for version 5
				padding := make([]byte, pk.cipher.blockSize()-len(pk.iv))
				if _, err = optional.Write(padding); err != nil {
					return
				}
			}
		}
	}
	if pk.Version == 5 || (pk.Version == 6 && pk.s2kType != S2KNON) {
		contents.Write([]byte{uint8(optional.Len())})
	}

	if _, err := io.Copy(contents, optional); err != nil {
		return err
	}

	if !pk.Dummy() {
		l := 0
		var priv []byte
		if !pk.Encrypted {
			buf := bytes.NewBuffer(nil)
			err = pk.serializePrivateKey(buf)
			if err != nil {
				return err
			}
			l = buf.Len()
			if pk.Version != 6 {
				checksum := mod64kHash(buf.Bytes())
				buf.Write([]byte{byte(checksum >> 8), byte(checksum)})
			}
			priv = buf.Bytes()
		} else {
			priv, l = pk.encryptedData, len(pk.encryptedData)
		}

		if pk.Version == 5 {
			contents.Write([]byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)})
		}
		contents.Write(priv)
	}

	ptype := packetTypePrivateKey
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	}
	err = serializeHeader(w, ptype, contents.Len())
	if err != nil {
		return
	}
	_, err = io.Copy(w, contents)
	if err != nil {
		return
	}
	return
}

func serializeEdDSAPrivateKey(w io.Writer, priv *eddsa.PrivateKey) error {
	_, err := w.Write(encoding.NewMPI(priv.MarshalByteSecret()).EncodedBytes())
	return err
}

func serializeECDHPrivateKey(w io.Writer, priv *ecdh.PrivateKey) error {
	_, err := w.Write(encoding.NewMPI(priv.MarshalByteSecret()).EncodedBytes())
	return err
}

func serializeX25519PrivateKey(w io.Writer, priv *x25519.PrivateKey) error {
	_, err := w.Write(priv.Secret)
	return err
}

func serializeEd25519PrivateKey(w io.Writer, priv *ed25519.PrivateKey) error {
	_, err := w.Write(priv.MarshalByteSecret())
	return err
}

// decrypt decrypts an encrypted private key using a decryption key.
func (pk *PrivateKey) decrypt(decryptionKey []byte) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}
	block := pk.cipher.new(decryptionKey)
	var data []byte
	switch pk.s2kType {
	case S2KAEAD:
		aead, err := pk.aead.new(block)
		if err != nil {
			return err
		}
		additionalData, err := pk.additionalData()
		if err != nil {
			return err
		}
		// Decrypt the encrypted key material with aead
		data, err = aead.Open(nil, pk.iv, pk.encryptedData, additionalData)
		if err != nil {
			return err
		}
	case S2KSHA1, S2KCHECKSUM:
		cfb := cipher.NewCFBDecrypter(block, pk.iv)
		data = make([]byte, len(pk.encryptedData))
		cfb.XORKeyStream(data, pk.encryptedData)
		if pk.s2kType == S2KSHA1 {
			if len(data) < sha1.Size {
				return errors.StructuralError("truncated private key data")
			}
			h := sha1.New()
			h.Write(data[:len(data)-sha1.Size])
			sum := h.Sum(nil)
			if !bytes.Equal(sum, data[len(data)-sha1.Size:]) {
				return errors.StructuralError("private key checksum failure")
			}
			data = data[:len(data)-sha1.Size]
		} else {
			if len(data) < 2 {
				return errors.StructuralError("truncated private key data")
			}
			var sum uint16
			for i := 0; i < len(data)-2; i++ {
				sum += uint16(data[i])
			}
			if data[len(data)-2] != uint8(sum>>8) ||
				data[len(data)-1] != uint8(sum) {
				return errors.StructuralError("private key checksum failure")
			}
			data = data[:len(data)-2]
		}
	default:
		return errors.InvalidArgumentError("invalid s2k type")
	}

	err := pk.parsePrivateKey(data)
	if _, ok := err.(errors.KeyInvalidError); ok {
		return errors.KeyInvalidError("invalid key parameters")
	}
	if err != nil {
		return err
	}

	// Mark key as unencrypted
	pk.s2kType = S2KNON
	pk.s2k = nil
	pk.Encrypted = false
	pk.encryptedData = nil
	return nil
}

func (pk *PrivateKey) decryptWithCache(passphrase []byte, keyCache *s2k.Cache) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}

	key, err := keyCache.GetOrComputeDerivedKey(passphrase, pk.s2kParams, pk.cipher.KeySize())
	if err != nil {
		return err
	}
	if pk.s2kType == S2KAEAD {
		key = pk.applyHKDF(key)
	}
	return pk.decrypt(key)
}

// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}

	key := make([]byte, pk.cipher.KeySize())
	pk.s2k(key, passphrase)
	if pk.s2kType == S2KAEAD {
		key = pk.applyHKDF(key)
	}
	return pk.decrypt(key)
}

// DecryptPrivateKeys decrypts all encrypted keys with the given config and passphrase.
// Avoids recomputation of similar s2k key derivations.
func DecryptPrivateKeys(keys []*PrivateKey, passphrase []byte) error {
	// Create a cache to avoid recomputation of key derviations for the same passphrase.
	s2kCache := &s2k.Cache{}
	for _, key := range keys {
		if key != nil && !key.Dummy() && key.Encrypted {
			err := key.decryptWithCache(passphrase, s2kCache)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// encrypt encrypts an unencrypted private key.
func (pk *PrivateKey) encrypt(key []byte, params *s2k.Params, s2kType S2KType, cipherFunction CipherFunction, rand io.Reader) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if pk.Encrypted {
		return nil
	}
	// check if encryptionKey has the correct size
	if len(key) != cipherFunction.KeySize() {
		return errors.InvalidArgumentError("supplied encryption key has the wrong size")
	}

	if params.Mode() == s2k.Argon2S2K && s2kType != S2KAEAD {
		return errors.InvalidArgumentError("using Argon2 S2K without AEAD is not allowed")
	}
	if params.Mode() != s2k.Argon2S2K && params.Mode() != s2k.IteratedSaltedS2K && params.Mode() != s2k.SaltedS2K { // only allowed for high-entropy passphrases
		return errors.InvalidArgumentError("insecure S2K mode")
	}

	priv := bytes.NewBuffer(nil)
	err := pk.serializePrivateKey(priv)
	if err != nil {
		return err
	}

	pk.cipher = cipherFunction
	pk.s2kParams = params
	pk.s2k, err = pk.s2kParams.Function()
	if err != nil {
		return err
	}

	privateKeyBytes := priv.Bytes()
	pk.s2kType = s2kType
	block := pk.cipher.new(key)
	switch s2kType {
	case S2KAEAD:
		if pk.aead == 0 {
			return errors.StructuralError("aead mode is not set on key")
		}
		aead, err := pk.aead.new(block)
		if err != nil {
			return err
		}
		additionalData, err := pk.additionalData()
		if err != nil {
			return err
		}
		pk.iv = make([]byte, aead.NonceSize())
		_, err = io.ReadFull(rand, pk.iv)
		if err != nil {
			return err
		}
		// Encrypt the key material with aead
		pk.encryptedData = aead.Seal(nil, pk.iv, privateKeyBytes, additionalData)
	case S2KSHA1, S2KCHECKSUM:
		pk.iv = make([]byte, pk.cipher.blockSize())
		_, err = io.ReadFull(rand, pk.iv)
		if err != nil {
			return err
		}
		cfb := cipher.NewCFBEncrypter(block, pk.iv)
		if s2kType == S2KSHA1 {
			h := sha1.New()
			h.Write(privateKeyBytes)
			sum := h.Sum(nil)
			privateKeyBytes = append(privateKeyBytes, sum...)
		} else {
			var sum uint16
			for _, b := range privateKeyBytes {
				sum += uint16(b)
			}
			privateKeyBytes = append(privateKeyBytes, []byte{uint8(sum >> 8), uint8(sum)}...)
		}
		pk.encryptedData = make([]byte, len(privateKeyBytes))
		cfb.XORKeyStream(pk.encryptedData, privateKeyBytes)
	default:
		return errors.InvalidArgumentError("invalid s2k type for encryption")
	}

	pk.Encrypted = true
	pk.PrivateKey = nil
	return err
}

// EncryptWithConfig encrypts an unencrypted private key using the passphrase and the config.
func (pk *PrivateKey) EncryptWithConfig(passphrase []byte, config *Config) error {
	params, err := s2k.Generate(config.Random(), config.S2K())
	if err != nil {
		return err
	}
	// Derive an encryption key with the configured s2k function.
	key := make([]byte, config.Cipher().KeySize())
	s2k, err := params.Function()
	if err != nil {
		return err
	}
	s2k(key, passphrase)
	s2kType := S2KSHA1
	if config.AEAD() != nil {
		s2kType = S2KAEAD
		pk.aead = config.AEAD().Mode()
		pk.cipher = config.Cipher()
		key = pk.applyHKDF(key)
	}
	// Encrypt the private key with the derived encryption key.
	return pk.encrypt(key, params, s2kType, config.Cipher(), config.Random())
}

// EncryptPrivateKeys encrypts all unencrypted keys with the given config and passphrase.
// Only derives one key from the passphrase, which is then used to encrypt each key.
func EncryptPrivateKeys(keys []*PrivateKey, passphrase []byte, config *Config) error {
	params, err := s2k.Generate(config.Random(), config.S2K())
	if err != nil {
		return err
	}
	// Derive an encryption key with the configured s2k function.
	encryptionKey := make([]byte, config.Cipher().KeySize())
	s2k, err := params.Function()
	if err != nil {
		return err
	}
	s2k(encryptionKey, passphrase)
	for _, key := range keys {
		if key != nil && !key.Dummy() && !key.Encrypted {
			s2kType := S2KSHA1
			if config.AEAD() != nil {
				s2kType = S2KAEAD
				key.aead = config.AEAD().Mode()
				key.cipher = config.Cipher()
				derivedKey := key.applyHKDF(encryptionKey)
				err = key.encrypt(derivedKey, params, s2kType, config.Cipher(), config.Random())
			} else {
				err = key.encrypt(encryptionKey, params, s2kType, config.Cipher(), config.Random())
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Encrypt encrypts an unencrypted private key using a passphrase.
func (pk *PrivateKey) Encrypt(passphrase []byte) error {
	// Default config of private key encryption
	config := &Config{
		S2KConfig: &s2k.Config{
			S2KMode:  s2k.IteratedSaltedS2K,
			S2KCount: 65536,
			Hash:     crypto.SHA256,
		},
		DefaultCipher: CipherAES256,
	}
	return pk.EncryptWithConfig(passphrase, config)
}

func (pk *PrivateKey) serializePrivateKey(w io.Writer) (err error) {
	switch priv := pk.PrivateKey.(type) {
	case *eddsa.PrivateKey:
		err = serializeEdDSAPrivateKey(w, priv)
	case *ecdh.PrivateKey:
		err = serializeECDHPrivateKey(w, priv)
	case *x25519.PrivateKey:
		err = serializeX25519PrivateKey(w, priv)
	case *ed25519.PrivateKey:
		err = serializeEd25519PrivateKey(w, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	return
}

func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) {
	switch pk.PublicKey.PubKeyAlgo {
	case PubKeyAlgoECDH:
		return pk.parseECDHPrivateKey(data)
	case PubKeyAlgoEdDSA:
		return pk.parseEdDSAPrivateKey(data)
	case PubKeyAlgoX25519:
		return pk.parseX25519PrivateKey(data)
	case PubKeyAlgoEd25519:
		return pk.parseEd25519PrivateKey(data)
	default:
		err = errors.StructuralError("unknown private key type")
		return
	}
}

func (pk *PrivateKey) parseECDHPrivateKey(data []byte) (err error) {
	ecdhPub := pk.PublicKey.PublicKey.(*ecdh.PublicKey)
	ecdhPriv := ecdh.NewPrivateKey(*ecdhPub)

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	if err := ecdhPriv.UnmarshalByteSecret(d.Bytes()); err != nil {
		return err
	}

	if err := ecdh.Validate(ecdhPriv); err != nil {
		return err
	}

	pk.PrivateKey = ecdhPriv

	return nil
}

func (pk *PrivateKey) parseX25519PrivateKey(data []byte) (err error) {
	publicKey := pk.PublicKey.PublicKey.(*x25519.PublicKey)
	privateKey := x25519.NewPrivateKey(*publicKey)
	privateKey.PublicKey = *publicKey

	privateKey.Secret = make([]byte, x25519.KeySize)

	if len(data) != x25519.KeySize {
		err = errors.StructuralError("wrong x25519 key size")
		return err
	}
	subtle.ConstantTimeCopy(1, privateKey.Secret, data)
	if err = x25519.Validate(privateKey); err != nil {
		return err
	}
	pk.PrivateKey = privateKey
	return nil
}

func (pk *PrivateKey) parseEd25519PrivateKey(data []byte) (err error) {
	publicKey := pk.PublicKey.PublicKey.(*ed25519.PublicKey)
	privateKey := ed25519.NewPrivateKey(*publicKey)
	privateKey.PublicKey = *publicKey

	if len(data) != ed25519.SeedSize {
		err = errors.StructuralError("wrong ed25519 key size")
		return err
	}
	err = privateKey.UnmarshalByteSecret(data)
	if err != nil {
		return err
	}
	err = ed25519.Validate(privateKey)
	if err != nil {
		return err
	}
	pk.PrivateKey = privateKey
	return nil
}

func (pk *PrivateKey) parseEdDSAPrivateKey(data []byte) (err error) {
	eddsaPub := pk.PublicKey.PublicKey.(*eddsa.PublicKey)
	eddsaPriv := eddsa.NewPrivateKey(*eddsaPub)
	eddsaPriv.PublicKey = *eddsaPub

	buf := bytes.NewBuffer(data)
	d := new(encoding.MPI)
	if _, err := d.ReadFrom(buf); err != nil {
		return err
	}

	if err = eddsaPriv.UnmarshalByteSecret(d.Bytes()); err != nil {
		return err
	}

	if err := eddsa.Validate(eddsaPriv); err != nil {
		return err
	}

	pk.PrivateKey = eddsaPriv

	return nil
}

func (pk *PrivateKey) additionalData() ([]byte, error) {
	additionalData := bytes.NewBuffer(nil)
	// Write additional data prefix based on packet type
	var packetByte byte
	if pk.PublicKey.IsSubkey {
		packetByte = 0xc7
	} else {
		packetByte = 0xc5
	}
	// Write public key to additional data
	_, err := additionalData.Write([]byte{packetByte})
	if err != nil {
		return nil, err
	}
	err = pk.PublicKey.serializeWithoutHeaders(additionalData)
	if err != nil {
		return nil, err
	}
	return additionalData.Bytes(), nil
}

func (pk *PrivateKey) applyHKDF(inputKey []byte) []byte {
	var packetByte byte
	if pk.PublicKey.IsSubkey {
		packetByte = 0xc7
	} else {
		packetByte = 0xc5
	}
	associatedData := []byte{packetByte, byte(pk.Version), byte(pk.cipher), byte(pk.aead)}
	hkdfReader := hkdf.New(sha256.New, inputKey, []byte{}, associatedData)
	encryptionKey := make([]byte, pk.cipher.KeySize())
	_, _ = readFull(hkdfReader, encryptionKey)
	return encryptionKey
}
