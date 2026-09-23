package pgp

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	pgped "github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/pgp/armor"
	"github.com/malivvan/crypto/pgp/packet"
	"github.com/malivvan/crypto/pgp/s2k"
	"github.com/malivvan/crypto/x25519"
)

func testConfig() *packet.Config {
	return &packet.Config{
		DefaultCipher: packet.CipherAES256,
		DefaultHash:   crypto.SHA256,
		AEADConfig:    &packet.AEADConfig{},
	}
}

func newTestEntity(t *testing.T, name string, config *packet.Config) *Entity {
	t.Helper()
	e, err := NewEntity(name, "", name+"@example.com", config)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}

func checkEntityConfiguration(t *testing.T, e *Entity, wantVersion int, wantPrimary, wantEnc packet.PublicKeyAlgorithm) {
	t.Helper()
	if e.PrimaryKey.Version != wantVersion {
		t.Fatalf("primary version %d, want %d", e.PrimaryKey.Version, wantVersion)
	}
	if e.PrimaryKey.PubKeyAlgo != wantPrimary {
		t.Fatalf("primary algo %d, want %d", e.PrimaryKey.PubKeyAlgo, wantPrimary)
	}
	if len(e.Subkeys) != 3 {
		t.Fatalf("got %d subkeys, want 3 (encryption, signing, authentication)", len(e.Subkeys))
	}
	var enc, sign, auth bool
	for _, sk := range e.Subkeys {
		if sk.PublicKey.Version != wantVersion {
			t.Fatalf("subkey version %d, want %d", sk.PublicKey.Version, wantVersion)
		}
		if len(sk.Bindings) != 1 {
			t.Fatalf("subkey has %d bindings, want 1", len(sk.Bindings))
		}
		sig := sk.Bindings[0].Packet
		switch {
		case sig.FlagEncryptCommunications:
			enc = true
			if sk.PublicKey.PubKeyAlgo != wantEnc {
				t.Fatalf("encryption subkey algo %d, want %d", sk.PublicKey.PubKeyAlgo, wantEnc)
			}
		case sig.FlagSign:
			sign = true
			if sk.PublicKey.PubKeyAlgo != wantPrimary {
				t.Fatalf("signing subkey algo %d, want %d", sk.PublicKey.PubKeyAlgo, wantPrimary)
			}
		case sig.FlagAuthenticate:
			auth = true
			if sk.PublicKey.PubKeyAlgo != wantPrimary {
				t.Fatalf("authentication subkey algo %d, want %d", sk.PublicKey.PubKeyAlgo, wantPrimary)
			}
		}
		// The binding signature must verify.
		if err := e.PrimaryKey.VerifyKeySignature(sk.PublicKey, sig); err != nil {
			t.Fatalf("subkey binding signature does not verify: %v", err)
		}
	}
	if !enc || !sign || !auth {
		t.Fatalf("missing subkeys: enc=%v sign=%v auth=%v", enc, sign, auth)
	}
}

func TestNewEntityConfiguration(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		checkEntityConfiguration(t, newTestEntity(t, "alice", testConfig()), 4, packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoECDH)
	})
	t.Run("v6", func(t *testing.T) {
		config := testConfig()
		config.V6Keys = true
		checkEntityConfiguration(t, newTestEntity(t, "bob", config), 6, packet.PubKeyAlgoEd25519, packet.PubKeyAlgoX25519)
	})
}

func encryptDecryptRoundtrip(t *testing.T, e *Entity, config *packet.Config, msg string, withSignature bool) {
	t.Helper()
	var buf bytes.Buffer
	var signers []*Entity
	if withSignature {
		signers = []*Entity{e}
	}
	w, err := Encrypt(&buf, []*Entity{e}, nil, signers, nil, config)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	md, err := ReadMessage(&buf, EntityList{e}, nil, config)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	pt, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("roundtrip mismatch: %q != %q", pt, msg)
	}
	if withSignature {
		if md.SignedBy == nil {
			t.Fatal("message not signed")
		}
		if err := md.SignatureError; err != nil {
			t.Fatalf("SignatureError: %v", err)
		}
		if md.SignedBy.PublicKey.KeyId != e.PrimaryKey.KeyId && !isSubkeyOf(md.SignedBy, e) {
			t.Fatal("signed by unexpected key")
		}
	}
}

func isSubkeyOf(key *Key, e *Entity) bool {
	if key.Entity != e {
		return false
	}
	for _, sk := range e.Subkeys {
		if sk.PublicKey == key.PublicKey {
			return true
		}
	}
	return false
}

func TestEncryptDecryptMatrix(t *testing.T) {
	// A nil config must not panic anywhere (defaults are used).
	t.Run("nil-config", func(t *testing.T) {
		e := newTestEntity(t, "nilcfg", testConfig())
		var buf bytes.Buffer
		w, err := Encrypt(&buf, []*Entity{e}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if _, err := w.Write([]byte("nil config message")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		md, err := ReadMessage(&buf, EntityList{e}, nil, nil)
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		pt, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != "nil config message" {
			t.Fatalf("roundtrip mismatch: %q", pt)
		}
	})

	tests := []struct {
		name   string
		v6     bool
		cipher packet.CipherFunction
		mode   packet.AEADMode
	}{
		{"v4-aes256-ocb", false, packet.CipherAES256, packet.AEADModeOCB},
		{"v4-aes256-eax", false, packet.CipherAES256, packet.AEADModeEAX},
		{"v4-aes128-ocb", false, packet.CipherAES128, packet.AEADModeOCB},
		{"v4-aes128-eax", false, packet.CipherAES128, packet.AEADModeEAX},
		{"v6-aes256-ocb", true, packet.CipherAES256, packet.AEADModeOCB},
		{"v6-aes256-eax", true, packet.CipherAES256, packet.AEADModeEAX},
		{"v6-aes128-ocb", true, packet.CipherAES128, packet.AEADModeOCB},
		{"v6-aes128-eax", true, packet.CipherAES128, packet.AEADModeEAX},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig()
			config.V6Keys = tt.v6
			config.DefaultCipher = tt.cipher
			config.AEADConfig = &packet.AEADConfig{DefaultMode: tt.mode}
			e := newTestEntity(t, tt.name, config)
			encryptDecryptRoundtrip(t, e, config, "hello "+tt.name, true)
		})
	}
}

func TestSymmetricPassphraseMatrix(t *testing.T) {
	tests := []struct {
		name   string
		s2kcfg *s2k.Config
		cipher packet.CipherFunction
		mode   packet.AEADMode
	}{
		{"iterated-sha256-aes256-ocb", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256}, packet.CipherAES256, packet.AEADModeOCB},
		{"iterated-sha512-aes256-eax", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA512}, packet.CipherAES256, packet.AEADModeEAX},
		{"iterated-sha512-aes128-ocb", &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA512}, packet.CipherAES128, packet.AEADModeOCB},
		{"salted-sha512-aes256-ocb", &s2k.Config{S2KMode: s2k.SaltedS2K, Hash: crypto.SHA512, PassphraseIsHighEntropy: true}, packet.CipherAES256, packet.AEADModeOCB},
	}
	passphrase := []byte("passphrase test")
	msg := "passphrase encrypted message"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig()
			config.DefaultCipher = tt.cipher
			config.AEADConfig = &packet.AEADConfig{DefaultMode: tt.mode}
			config.S2KConfig = tt.s2kcfg

			var buf bytes.Buffer
			w, err := SymmetricallyEncrypt(&buf, passphrase, nil, config)
			if err != nil {
				t.Fatalf("SymmetricallyEncrypt: %v", err)
			}
			if _, err := w.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			md, err := ReadMessage(&buf, nil, func(keys []Key, symmetric bool) ([]byte, error) {
				return passphrase, nil
			}, config)
			if err != nil {
				t.Fatalf("ReadMessage: %v", err)
			}
			pt, err := io.ReadAll(md.UnverifiedBody)
			if err != nil {
				t.Fatal(err)
			}
			if string(pt) != msg {
				t.Fatalf("roundtrip mismatch: %q", pt)
			}
		})
	}
}

func TestDetachedSignatures(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v4", true: "v6"}[v6], func(t *testing.T) {
			config := testConfig()
			config.V6Keys = v6
			e := newTestEntity(t, "signer", config)
			msg := []byte("detached message")

			var sig bytes.Buffer
			if err := DetachSign(&sig, []*Entity{e}, bytes.NewReader(msg), config); err != nil {
				t.Fatalf("DetachSign: %v", err)
			}
			parsed, signer, err := VerifyDetachedSignature(EntityList{e}, bytes.NewReader(msg), &sig, config)
			if err != nil {
				t.Fatalf("VerifyDetachedSignature: %v", err)
			}
			if parsed == nil || signer == nil {
				t.Fatal("no signature returned")
			}

			var armored bytes.Buffer
			if err := ArmoredDetachSign(&armored, []*Entity{e}, bytes.NewReader(msg), &SignParams{Config: config}); err != nil {
				t.Fatalf("ArmoredDetachSign: %v", err)
			}
			if _, _, err := VerifyArmoredDetachedSignature(EntityList{e}, bytes.NewReader(msg), &armored, config); err != nil {
				t.Fatalf("VerifyArmoredDetachedSignature: %v", err)
			}
		})
	}
}

func TestArmoredKeyRingRoundtrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v4", true: "v6"}[v6], func(t *testing.T) {
			config := testConfig()
			config.V6Keys = v6
			e := newTestEntity(t, "keyring", config)

			// Serialize private key, armored.
			var armoredPriv bytes.Buffer
			w, err := armor.Encode(&armoredPriv, PrivateKeyType, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.SerializePrivate(w, config); err != nil {
				t.Fatalf("SerializePrivate: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			list, err := ReadArmoredKeyRing(bytes.NewReader(armoredPriv.Bytes()))
			if err != nil {
				t.Fatalf("ReadArmoredKeyRing: %v", err)
			}
			if len(list) != 1 {
				t.Fatalf("got %d entities, want 1", len(list))
			}
			re := list[0]
			if re.PrimaryKey.KeyId != e.PrimaryKey.KeyId {
				t.Fatal("key id mismatch")
			}
			if len(re.Subkeys) != 3 {
				t.Fatalf("got %d subkeys, want 3", len(re.Subkeys))
			}

			// Serialize public key and read it back.
			var pubBuf bytes.Buffer
			if err := e.Serialize(&pubBuf); err != nil {
				t.Fatal(err)
			}
			plist, err := ReadKeyRing(bytes.NewReader(pubBuf.Bytes()))
			if err != nil {
				t.Fatalf("ReadKeyRing: %v", err)
			}
			if len(plist) != 1 || plist[0].PrimaryKey.KeyId != e.PrimaryKey.KeyId {
				t.Fatal("public key ring mismatch")
			}
		})
	}
}

func TestPrivateKeyPassphraseEncryption(t *testing.T) {
	config := testConfig()
	config.S2KConfig = &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256}
	e := newTestEntity(t, "passphrase", config)
	passphrase := []byte("key passphrase")

	if err := e.EncryptPrivateKeys(passphrase, config); err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}
	if !e.PrivateKey.Encrypted {
		t.Fatal("primary key not encrypted")
	}
	for _, sk := range e.Subkeys {
		if !sk.PrivateKey.Encrypted {
			t.Fatal("subkey not encrypted")
		}
	}
	if err := e.DecryptPrivateKeys(passphrase); err != nil {
		t.Fatalf("DecryptPrivateKeys: %v", err)
	}
	encryptDecryptRoundtrip(t, e, config, "decrypted keys work", false)
}

// TestMDCLegacyDecryption builds an MDC-encrypted (SEIPD v1) message with the
// packet layer and checks that the v2 API can still decrypt it.
func TestMDCLegacyDecryption(t *testing.T) {
	config := testConfig()
	config.AEADConfig = nil
	e := newTestEntity(t, "mdc", config)
	encKey, _ := e.EncryptionKey(config.Now(), config)
	if encKey.PrivateKey == nil {
		t.Skip("no encryption subkey")
	}

	msg := "legacy mdc message"
	sessionKey := make([]byte, packet.CipherAES256.KeySize())
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := packet.SerializeEncryptedKeyAEAD(&buf, encKey.PublicKey, packet.CipherAES256, false, sessionKey, config); err != nil {
		t.Fatalf("SerializeEncryptedKeyAEAD: %v", err)
	}
	contents, err := packet.SerializeSymmetricallyEncrypted(&buf, packet.CipherAES256, false,
		packet.CipherSuite{Cipher: packet.CipherAES256}, sessionKey, config)
	if err != nil {
		t.Fatalf("SerializeSymmetricallyEncrypted: %v", err)
	}
	literal, err := packet.SerializeLiteral(contents, true, "", uint32(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := literal.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	// Closing the literal writer also closes the underlying encrypted
	// data writer (and emits the MDC trailer).
	if err := literal.Close(); err != nil {
		t.Fatal(err)
	}

	md, err := ReadMessage(&buf, EntityList{e}, nil, config)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	pt, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("roundtrip mismatch: %q", pt)
	}
}

// hardwareSigner simulates a YubiKey-backed ed25519 signer.
type hardwareSigner struct {
	pub  ed25519.PublicKey
	seed []byte
}

func (h *hardwareSigner) Public() crypto.PublicKey { return h.pub }
func (h *hardwareSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(ed25519.NewKeyFromSeed(h.seed), digest), nil
}

// hardwareDecrypter simulates a YubiKey-backed x25519 decrypter.
type hardwareDecrypter struct {
	secret []byte
}

func (h *hardwareDecrypter) DecryptX25519(ephemeral []byte) ([]byte, error) {
	var e, s, shared x25519.Key
	copy(e[:], ephemeral)
	copy(s[:], h.secret)
	if !x25519.Shared(&shared, &s, &e) {
		return nil, io.ErrUnexpectedEOF
	}
	return shared[:], nil
}

func TestHardwareBackedKeys(t *testing.T) {
	config := testConfig()
	config.V6Keys = true
	now := config.Now()

	// Build a v6 entity with a hardware-backed primary signing key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs := &hardwareSigner{pub: pub, seed: priv.Seed()}
	pk := packet.NewSignerPrivateKey(now, hs)
	if err := pk.UpgradeToV6(); err != nil {
		t.Fatal(err)
	}
	e := &Entity{PrimaryKey: &pk.PublicKey, PrivateKey: pk}

	ds := &packet.Signature{Version: 6, SigType: packet.SigTypeDirectSignature, PubKeyAlgo: packet.PubKeyAlgoEd25519, Hash: crypto.SHA256, CreationTime: now}
	ds.FlagsValid = true
	ds.FlagSign = true
	ds.FlagCertify = true
	if err := ds.SignDirectKeyBinding(&pk.PublicKey, pk, config); err != nil {
		t.Fatal(err)
	}
	e.DirectSignatures = []*packet.VerifiableSignature{packet.NewVerifiableSig(ds)}

	// Hardware x25519 decryption subkey.
	xk, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sub := packet.NewX25519PrivateKey(now, xk)
	sub.IsSubkey = true
	if err := sub.UpgradeToV6(); err != nil {
		t.Fatal(err)
	}
	sub.PrivateKey = &hardwareDecrypter{secret: xk.Secret} // replace with hardware backend
	subkey := Subkey{PublicKey: &sub.PublicKey, PrivateKey: sub, Primary: e}
	sig := &packet.Signature{Version: 6, SigType: packet.SigTypeSubkeyBinding, PubKeyAlgo: packet.PubKeyAlgoEd25519, Hash: crypto.SHA256, CreationTime: now}
	sig.FlagsValid = true
	sig.FlagEncryptCommunications = true
	sig.FlagEncryptStorage = true
	if err := sig.SignKey(subkey.PublicKey, e.PrivateKey, config); err != nil {
		t.Fatal(err)
	}
	subkey.Bindings = []*packet.VerifiableSignature{packet.NewVerifiableSig(sig)}
	e.Subkeys = []Subkey{subkey}

	encryptDecryptRoundtrip(t, e, config, "hardware hello", true)
}

// TestSeedsCompatibility checks that fixed 32-byte seeds deterministically
// derive ed25519 and x25519 key material. This is the same raw key material
// used by ed25519/x25519 in other packages (e.g. SSH), so one seed can back
// both an OpenPGP key and an SSH key.
func TestSeedsCompatibility(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)

	// ed25519: public key must equal ed25519.NewKeyFromSeed(seed).Public().
	stdPriv := ed25519.NewKeyFromSeed(seed)
	pgpPriv, err := pgped.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pgpPriv.PublicKey.Point, stdPriv.Public().(ed25519.PublicKey)) {
		t.Fatal("ed25519 public key derived from seed does not match stdlib")
	}
	sig := ed25519.Sign(stdPriv, []byte("seed test"))
	if !pgped.Verify(&pgpPriv.PublicKey, []byte("seed test"), sig) {
		t.Fatal("signature made with stdlib key does not verify with pgp-derived key")
	}

	// x25519: the public key is deterministic for the given scalar seed.
	priv1, err := x25519.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("x25519 from seed: %v", err)
	}
	priv2, err := x25519.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv1.PublicKey.Point, priv2.PublicKey.Point) {
		t.Fatal("x25519 keys derived from the same seed differ")
	}
}
