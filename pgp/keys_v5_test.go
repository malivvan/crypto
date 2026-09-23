//go:build v5

package pgp

import (
	"bytes"
	"crypto"
	"io"
	"testing"

	"github.com/malivvan/crypto/pgp/packet"
)

// TestV5EntityRoundtrip checks that v5 keys can be generated, serialized,
// parsed, and used for signing/encryption when built with -tags v5.
func TestV5EntityRoundtrip(t *testing.T) {
	config := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		DefaultHash:   crypto.SHA512,
		AEADConfig:    &packet.AEADConfig{},
	}
	e, err := NewEntity("v5 user", "", "v5@example.com", config)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	// Upgrade all keys to v5.
	keys := []*packet.PrivateKey{e.PrivateKey}
	for _, sk := range e.Subkeys {
		keys = append(keys, sk.PrivateKey)
	}
	for _, k := range keys {
		k.UpgradeToV5()
		if k.Version != 5 {
			t.Fatalf("key version %d, want 5", k.Version)
		}
	}

	// Re-certify the identities with v5 signatures.
	for id := range e.Identities {
		selfSig := createSignaturePacket(&e.PrivateKey.PublicKey, packet.SigTypePositiveCert, config)
		selfSig.CreationTime = config.Now()
		if err := selfSig.SignUserId(id, &e.PrivateKey.PublicKey, e.PrivateKey, config); err != nil {
			t.Fatalf("SignUserId: %v", err)
		}
		e.Identities[id].SelfCertifications = append(e.Identities[id].SelfCertifications, packet.NewVerifiableSig(selfSig))
	}

	// Re-bind the subkeys with v5 signatures.
	for i := range e.Subkeys {
		sk := &e.Subkeys[i]
		old := sk.Bindings[len(sk.Bindings)-1].Packet
		sig := createSignaturePacket(e.PrimaryKey, packet.SigTypeSubkeyBinding, config)
		sig.CreationTime = config.Now()
		sig.FlagsValid = true
		sig.FlagSign = old.FlagSign
		sig.FlagCertify = old.FlagCertify
		sig.FlagEncryptCommunications = old.FlagEncryptCommunications
		sig.FlagEncryptStorage = old.FlagEncryptStorage
		sig.FlagAuthenticate = old.FlagAuthenticate
		if old.FlagSign {
			sig.EmbeddedSignature = createSignaturePacket(sk.PublicKey, packet.SigTypePrimaryKeyBinding, config)
			sig.EmbeddedSignature.CreationTime = config.Now()
			if err := sig.EmbeddedSignature.CrossSignKey(sk.PublicKey, e.PrimaryKey, sk.PrivateKey, config); err != nil {
				t.Fatalf("CrossSignKey: %v", err)
			}
		}
		if err := sig.SignKey(sk.PublicKey, e.PrivateKey, config); err != nil {
			t.Fatalf("SignKey: %v", err)
		}
		sk.Bindings = append(sk.Bindings, packet.NewVerifiableSig(sig))
	}

	// Serialize and re-read the private key ring.
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, config); err != nil {
		t.Fatalf("SerializePrivate: %v", err)
	}
	list, err := ReadKeyRing(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadKeyRing: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d entities, want 1", len(list))
	}
	re := list[0]
	if re.PrimaryKey.Version != 5 {
		t.Fatalf("re-read primary version %d, want 5", re.PrimaryKey.Version)
	}

	// Roundtrip a signed+encrypted message.
	var ct bytes.Buffer
	w, err := Encrypt(&ct, []*Entity{e}, nil, []*Entity{e}, nil, config)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write([]byte("v5 message")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	md, err := ReadMessage(&ct, EntityList{e}, nil, config)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	pt, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "v5 message" {
		t.Fatalf("roundtrip mismatch: %q", pt)
	}
	if md.SignedBy == nil || md.SignatureError != nil {
		t.Fatalf("signature not verified: %v", md.SignatureError)
	}
}
