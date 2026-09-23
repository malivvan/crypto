package wallet

import (
	"bytes"
	"testing"

	"github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/pgp/eddsa"
)

// seedOfEntitySigningKey returns the raw RFC 8032 32-byte seed of the
// entity's signing key, normalizing across the v4 (EdDSA) and v6 (Ed25519)
// encodings. It mirrors the reconstruction performed by (*wallet).SigningKey.
func seedOfEntitySigningKey(t *testing.T, wl *wallet) []byte {
	t.Helper()
	key, ok := wl.entity.SigningKeyById(wl.config.Now(), wl.config.SigningKey(), wl.config)
	if !ok {
		t.Fatal("no signing key in entity")
	}
	pk := key.PrivateKey
	if pk == nil {
		t.Fatal("no private key material")
	}
	switch raw := pk.PrivateKey.(type) {
	case *eddsa.PrivateKey:
		return raw.D
	case *ed25519.PrivateKey:
		return raw.Seed()
	default:
		t.Fatalf("unexpected signing key material %T", pk.PrivateKey)
	}
	return nil
}

// newWalletKeyed builds a wallet for the given v4/v6 config preference with a
// locked clone that can be reloaded, or returns the live wallet for the
// non-v6/v6 mnemonic case as needed by each test.
func v6Wallet(t *testing.T, mnemonic string) Wallet {
	t.Helper()
	cfg := testConfig()
	cfg.V6Keys = true
	password := []byte("test-password")
	wl, err := NewWallet("Alice", "alice@example.com", mnemonic, password, cfg)
	if err != nil {
		t.Fatalf("NewWallet(v6): %v", err)
	}
	return wl
}

// TestSigningKeyMatchesEntitySigningKey ensures Wallet.SigningKey() returns
// the key used for OpenPGP/GPG-style detached signing: same seed as the
// entity's signing subkey, across both the v4 (EdDSA) and v6 (Ed25519)
// encodings.
func TestSigningKeyMatchesEntitySigningKey(t *testing.T) {
	cases := map[string]Wallet{
		"v4": newTestWallet(t, "Alice", "alice@example.com", testMnemonic),
		"v6": v6Wallet(t, testMnemonic),
	}
	for name, wl := range cases {
		sk, err := wl.SigningKey()
		if err != nil {
			t.Fatalf("%s SigningKey: %v", name, err)
		}
		seed := seedOfEntitySigningKey(t, internal(wl))
		if !bytes.Equal(sk.Seed(), seed) {
			t.Fatalf("%s: SigningKey seed %x != entity signing seed %x", name, sk.Seed(), seed)
		}
	}
}

// TestSigningKeyFileReload exercises the reconstruction path in
// (*wallet).SigningKey used when the SLIP-10 master node is absent (a wallet
// loaded from a file). A loaded wallet is locked and has no SLIP-10 node, so
// SigningKey must refuse while locked (c18) and, after unlock, rebuild the
// very same signing key that the mnemonic-derived wallet yields (c17).
func TestSigningKeyFileReload(t *testing.T) {
	orig := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	origSeed, err := orig.SigningKey()
	if err != nil {
		t.Fatalf("orig SigningKey: %v", err)
	}

	const pass = "reload-pass"
	if err := orig.Lock(pass); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	var buf bytes.Buffer
	if err := orig.Save(&buf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	internal(loaded).config.Time = testConfig().Time

	// While locked, SigningKey must report the lock instead of exposing
	// ciphertext material.
	if _, err := loaded.SigningKey(); err == nil {
		t.Fatal("expected SigningKey to fail on a locked loaded wallet")
	}
	if err := loaded.Unlock(pass); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	reloaded, err := loaded.SigningKey()
	if err != nil {
		t.Fatalf("loaded SigningKey: %v", err)
	}
	if !bytes.Equal(reloaded.Seed(), origSeed.Seed()) {
		t.Fatalf("reloaded SigningKey seed %x != original %x", reloaded.Seed(), origSeed.Seed())
	}
}
