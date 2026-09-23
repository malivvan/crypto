package packet

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/internal/algorithm"
	"github.com/malivvan/crypto/internal/ecc"
	"github.com/malivvan/crypto/pgp/ecdh"
	"github.com/malivvan/crypto/pgp/eddsa"
	"github.com/malivvan/crypto/pgp/s2k"
	"github.com/malivvan/crypto/x25519"
)

func testConfig() *Config {
	return &Config{
		DefaultCipher: CipherAES256,
		DefaultHash:   crypto.SHA256,
		Rand:          rand.Reader,
	}
}

// keyGen produces a private key of the requested version.
type keyGen struct {
	name  string
	gen   func(creationTime time.Time, config *Config) (*PrivateKey, error)
	check func(t *testing.T, pk *PrivateKey)
}

func v4EdDSAKey(creationTime time.Time, config *Config) (*PrivateKey, error) {
	priv, err := eddsa.GenerateKey(config.Random(), ecc.FindEdDSAByGenName(ecc.Curve25519GenName))
	if err != nil {
		return nil, err
	}
	return NewEdDSAPrivateKey(creationTime, priv), nil
}

func v4ECDHKey(creationTime time.Time, config *Config) (*PrivateKey, error) {
	priv, err := ecdh.GenerateKey(config.Random(), ecc.FindECDHByGenName(ecc.Curve25519GenName), ecdh.KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	})
	if err != nil {
		return nil, err
	}
	return NewECDHPrivateKey(creationTime, priv), nil
}

func v6Ed25519Key(creationTime time.Time, config *Config) (*PrivateKey, error) {
	priv, err := ed25519.GenerateKey(config.Random())
	if err != nil {
		return nil, err
	}
	pk := NewEd25519PrivateKey(creationTime, priv)
	if err := pk.UpgradeToV6(); err != nil {
		return nil, err
	}
	return pk, nil
}

func v6X25519Key(creationTime time.Time, config *Config) (*PrivateKey, error) {
	priv, err := x25519.GenerateKey(config.Random())
	if err != nil {
		return nil, err
	}
	pk := NewX25519PrivateKey(creationTime, priv)
	if err := pk.UpgradeToV6(); err != nil {
		return nil, err
	}
	return pk, nil
}

func TestKeySerializeParseRoundtrip(t *testing.T) {
	creationTime := time.Unix(1710000000, 0)
	tests := []keyGen{
		{"eddsa-v4", v4EdDSAKey, func(t *testing.T, pk *PrivateKey) {
			if pk.Version != 4 || pk.PubKeyAlgo != PubKeyAlgoEdDSA {
				t.Fatalf("unexpected version/algo: %d/%d", pk.Version, pk.PubKeyAlgo)
			}
		}},
		{"ecdh-v4", v4ECDHKey, func(t *testing.T, pk *PrivateKey) {
			if pk.Version != 4 || pk.PubKeyAlgo != PubKeyAlgoECDH {
				t.Fatalf("unexpected version/algo: %d/%d", pk.Version, pk.PubKeyAlgo)
			}
			if pk.PublicKey.PublicKey.(*ecdh.PublicKey).KDF.Hash != algorithm.SHA512 {
				t.Fatal("unexpected KDF hash")
			}
		}},
		{"ed25519-v6", v6Ed25519Key, func(t *testing.T, pk *PrivateKey) {
			if pk.Version != 6 || pk.PubKeyAlgo != PubKeyAlgoEd25519 {
				t.Fatalf("unexpected version/algo: %d/%d", pk.Version, pk.PubKeyAlgo)
			}
			if len(pk.Fingerprint) != 32 {
				t.Fatal("v6 fingerprint must be 32 bytes")
			}
		}},
		{"x25519-v6", v6X25519Key, func(t *testing.T, pk *PrivateKey) {
			if pk.Version != 6 || pk.PubKeyAlgo != PubKeyAlgoX25519 {
				t.Fatalf("unexpected version/algo: %d/%d", pk.Version, pk.PubKeyAlgo)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig()
			priv, err := tt.gen(creationTime, config)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			tt.check(t, priv)

			// Serialize the public key and parse it back.
			var pubBuf bytes.Buffer
			if err := priv.PublicKey.Serialize(&pubBuf); err != nil {
				t.Fatalf("public serialize: %v", err)
			}
			pubPkt, err := Read(&pubBuf)
			if err != nil {
				t.Fatalf("public read: %v", err)
			}
			parsedPub := pubPkt.(*PublicKey)
			if parsedPub.Version != priv.Version || parsedPub.PubKeyAlgo != priv.PubKeyAlgo {
				t.Fatalf("public key mismatch after parse: %+v", parsedPub)
			}
			if !bytes.Equal(parsedPub.Fingerprint, priv.Fingerprint) {
				t.Fatalf("fingerprint mismatch: %x != %x", parsedPub.Fingerprint, priv.Fingerprint)
			}

			// Serialize the private key and parse it back.
			var privBuf bytes.Buffer
			if err := priv.Serialize(&privBuf); err != nil {
				t.Fatalf("private serialize: %v", err)
			}
			privPkt, err := Read(&privBuf)
			if err != nil {
				t.Fatalf("private read: %v", err)
			}
			parsedPriv := privPkt.(*PrivateKey)
			if parsedPriv.Version != priv.Version || parsedPriv.PubKeyAlgo != priv.PubKeyAlgo {
				t.Fatalf("private key mismatch after parse")
			}
			if !bytes.Equal(parsedPriv.Fingerprint, priv.Fingerprint) {
				t.Fatalf("private key fingerprint mismatch")
			}
			if parsedPriv.Encrypted {
				t.Fatal("private key should not be encrypted")
			}
		})
	}
}

func signAndVerifyRoundtrip(t *testing.T, priv *PrivateKey, config *Config) {
	t.Helper()
	msg := []byte("hello world")
	sig := &Signature{
		Version:      priv.Version,
		SigType:      SigTypeBinary,
		PubKeyAlgo:   priv.PubKeyAlgo,
		Hash:         config.Hash(),
		CreationTime: config.Now(),
	}
	h, err := sig.PrepareSign(config)
	if err != nil {
		t.Fatalf("PrepareSign: %v", err)
	}
	if _, err := h.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, config); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var buf bytes.Buffer
	if err := sig.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	parsed, ok := p.(*Signature)
	if !ok {
		t.Fatal("not a signature packet")
	}

	verifyHash, err := parsed.PrepareVerify()
	if err != nil {
		t.Fatalf("PrepareVerify: %v", err)
	}
	if _, err := verifyHash.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.PublicKey.VerifySignature(verifyHash, parsed); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	// Tampered message must fail.
	verifyHash, err = parsed.PrepareVerify()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyHash.Write([]byte("hello worle")); err != nil {
		t.Fatal(err)
	}
	if err := priv.PublicKey.VerifySignature(verifyHash, parsed); err == nil {
		t.Fatal("tampered signature verified")
	}
}

func TestSignatureRoundtrip(t *testing.T) {
	creationTime := time.Unix(1710000000, 0)
	config := testConfig()
	config.Time = func() time.Time { return creationTime }

	eddsaPriv, err := v4EdDSAKey(creationTime, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("eddsa-v4", func(t *testing.T) { signAndVerifyRoundtrip(t, eddsaPriv, config) })

	ed25519Priv, err := v6Ed25519Key(creationTime, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ed25519-v6", func(t *testing.T) { signAndVerifyRoundtrip(t, ed25519Priv, config) })
}

func TestPrivateKeyEncryptionRoundtrip(t *testing.T) {
	creationTime := time.Unix(1710000000, 0)
	passphrase := []byte("correct horse battery staple")

	tests := []struct {
		name   string
		s2kcfg *s2k.Config
		cipher CipherFunction
		aead   *AEADConfig
	}{
		{"iterated-sha256-aes256", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256}, CipherAES256, nil},
		{"iterated-sha512-aes128", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA512}, CipherAES128, nil},
		{"salted-sha512-high-entropy", &s2k.Config{S2KMode: s2k.SaltedS2K, Hash: crypto.SHA512, PassphraseIsHighEntropy: true}, CipherAES256, nil},
		{"aead-ocb", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256}, CipherAES256, &AEADConfig{DefaultMode: AEADModeOCB}},
		{"aead-eax", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA512}, CipherAES128, &AEADConfig{DefaultMode: AEADModeEAX}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DefaultCipher = tt.cipher
			cfg.S2KConfig = tt.s2kcfg
			cfg.AEADConfig = tt.aead
			key, err := v4EdDSAKey(creationTime, testConfig())
			if err != nil {
				t.Fatal(err)
			}
			if err := key.EncryptWithConfig(passphrase, cfg); err != nil {
				t.Fatalf("EncryptWithConfig: %v", err)
			}
			if !key.Encrypted {
				t.Fatal("key not encrypted")
			}

			// Roundtrip through serialization.
			var buf bytes.Buffer
			if err := key.Serialize(&buf); err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			serialized := buf.Bytes()
			p, err := Read(bytes.NewReader(serialized))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			parsed := p.(*PrivateKey)
			if !parsed.Encrypted {
				t.Fatal("parsed key not encrypted")
			}
			if err := parsed.Decrypt(passphrase); err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if parsed.Encrypted {
				t.Fatal("key still encrypted after decrypt")
			}
			if !bytes.Equal(parsed.Fingerprint, key.Fingerprint) {
				t.Fatal("fingerprint mismatch after decrypt")
			}
			if _, ok := parsed.PrivateKey.(*eddsa.PrivateKey); !ok {
				t.Fatalf("unexpected private key type: %T", parsed.PrivateKey)
			}

			// Wrong passphrase must fail: re-parse to get a clean copy.
			p2, err := Read(bytes.NewReader(serialized))
			if err != nil {
				t.Fatal(err)
			}
			if err := p2.(*PrivateKey).Decrypt([]byte("wrong")); err == nil {
				t.Fatal("wrong passphrase decrypted")
			}
		})
	}
}

func sessionKeyFor(cipher CipherFunction) []byte {
	key := make([]byte, cipher.KeySize())
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestEncryptedKeyRoundtrip(t *testing.T) {
	creationTime := time.Unix(1710000000, 0)
	config := testConfig()

	// v4 ECDH over x25519 with a v3 PKESK.
	ecdhPriv, err := v4ECDHKey(creationTime, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ecdh-v4", func(t *testing.T) {
		key := sessionKeyFor(CipherAES256)
		var buf bytes.Buffer
		if err := SerializeEncryptedKeyAEAD(&buf, &ecdhPriv.PublicKey, CipherAES256, false, key, config); err != nil {
			t.Fatalf("SerializeEncryptedKeyAEAD: %v", err)
		}
		p, err := Read(&buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		ek := p.(*EncryptedKey)
		if ek.Algo != PubKeyAlgoECDH {
			t.Fatalf("unexpected algo %d", ek.Algo)
		}
		if err := ek.Decrypt(ecdhPriv, config); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(ek.Key, key) {
			t.Fatal("session key mismatch")
		}
	})

	// v6 X25519 with a v6 PKESK.
	xPriv, err := v6X25519Key(creationTime, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("x25519-v6", func(t *testing.T) {
		key := sessionKeyFor(CipherAES128)
		var buf bytes.Buffer
		if err := SerializeEncryptedKeyAEAD(&buf, &xPriv.PublicKey, CipherAES128, true, key, config); err != nil {
			t.Fatalf("SerializeEncryptedKeyAEAD: %v", err)
		}
		p, err := Read(&buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		ek := p.(*EncryptedKey)
		if err := ek.Decrypt(xPriv, config); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(ek.Key, key) {
			t.Fatal("session key mismatch")
		}
	})
}

func symmetricRoundtrip(t *testing.T, cipherFunc CipherFunction, suite CipherSuite, aeadSupported bool) {
	t.Helper()
	config := testConfig()
	key := sessionKeyFor(cipherFunc)
	var buf bytes.Buffer
	contents, err := SerializeSymmetricallyEncrypted(&buf, cipherFunc, aeadSupported, suite, key, config)
	if err != nil {
		t.Fatalf("SerializeSymmetricallyEncrypted: %v", err)
	}
	msg := []byte("secret data")
	if _, err := contents.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := contents.Close(); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	se, ok := p.(*SymmetricallyEncrypted)
	if !ok {
		t.Fatalf("unexpected packet type %T", p)
	}
	r, err := se.Decrypt(cipherFunc, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, msg)
	}
}

func TestSymmetricallyEncryptedRoundtrip(t *testing.T) {
	t.Run("mdc-aes256", func(t *testing.T) {
		symmetricRoundtrip(t, CipherAES256, CipherSuite{Cipher: CipherAES256}, false)
	})
	t.Run("mdc-aes128", func(t *testing.T) {
		symmetricRoundtrip(t, CipherAES128, CipherSuite{Cipher: CipherAES128}, false)
	})
	t.Run("aead-aes256-ocb", func(t *testing.T) {
		symmetricRoundtrip(t, CipherAES256, CipherSuite{Cipher: CipherAES256, Mode: AEADModeOCB}, true)
	})
	t.Run("aead-aes256-eax", func(t *testing.T) {
		symmetricRoundtrip(t, CipherAES256, CipherSuite{Cipher: CipherAES256, Mode: AEADModeEAX}, true)
	})
	t.Run("aead-aes128-eax", func(t *testing.T) {
		symmetricRoundtrip(t, CipherAES128, CipherSuite{Cipher: CipherAES128, Mode: AEADModeEAX}, true)
	})
}

func TestSymmetricKeyEncryptedRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		s2kcfg *s2k.Config
		aead   *AEADConfig
	}{
		{"iterated-sha256", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256}, nil},
		{"iterated-sha512", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA512}, nil},
		{"salted-sha512", &s2k.Config{S2KMode: s2k.SaltedS2K, Hash: crypto.SHA512, PassphraseIsHighEntropy: true}, nil},
		{"aead-ocb", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256}, &AEADConfig{DefaultMode: AEADModeOCB}},
	}
	passphrase := []byte("super secret")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.S2KConfig = tt.s2kcfg
			cfg.AEADConfig = tt.aead
			var buf bytes.Buffer
			key, err := SerializeSymmetricKeyEncrypted(&buf, passphrase, cfg)
			if err != nil {
				t.Fatalf("SerializeSymmetricKeyEncrypted: %v", err)
			}
			p, err := Read(&buf)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			ske := p.(*SymmetricKeyEncrypted)
			got, cipherFunc, err := ske.Decrypt(passphrase)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, key) {
				t.Fatal("session key mismatch")
			}
			if cipherFunc != 0 && cipherFunc != cfg.Cipher() {
				t.Fatalf("cipher mismatch: %d != %d", cipherFunc, cfg.Cipher())
			}
		})
	}
}
