package ed25519

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

const messageDigestSize = 32

func TestGenerate(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv.Key) != ed25519.SeedSize+ed25519.PublicKeySize && len(priv.Point) != ed25519.PublicKeySize {
		t.Error("generated wrong key sizes")
	}
}

func TestSignVerify(t *testing.T) {
	digest := make([]byte, messageDigestSize)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := Sign(priv, digest)
	if err != nil {
		t.Errorf("error signing: %s", err)
	}

	result := Verify(&priv.PublicKey, digest, signature)

	if !result {
		t.Error("unable to verify message")
	}

	digest[0] += 1
	result = Verify(&priv.PublicKey, digest, signature)

	if result {
		t.Error("signature should be invalid")
	}
}

func TestValidation(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	priv.Key[0] += 1
	if err := Validate(priv); err == nil {
		t.Fatal("failed to detect invalid key")
	}
}

func TestPrivateKeyImplementsSigner(t *testing.T) {
	// A *PrivateKey must satisfy crypto.Signer so consumers such as the ssh
	// stack can wrap a wallet key without reaching for crypto/ed25519.
	var s crypto.Signer = &PrivateKey{}
	_ = s

	priv, err := GenerateKeyFromSeed(seedRepeat(0x5e))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	point, ok := pub.(*PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *PublicKey", pub)
	}

	msg := []byte("signer message")
	sig, err := priv.Sign(bytes.NewReader(nil), msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign via crypto.Signer: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("len(sig)=%d, want %d", len(sig), SignatureSize)
	}
	if !Verify(point, msg, sig) {
		t.Fatal("signer signature failed verification")
	}

	// Deterministic: a second call yields identical bytes.
	sig2, err := priv.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != string(sig2) {
		t.Fatal("crypto.Signer signatures differ across calls")
	}

	// Reject pre-hashed requests (ed25519 is pure).
	if _, err := priv.Sign(nil, msg, crypto.SHA256); err == nil {
		t.Fatal("expected an error when signing a pre-hashed digest")
	}
}

func seedRepeat(b byte) []byte {
	s := make([]byte, SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}
