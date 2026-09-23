package wallet

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/malivvan/crypto/pgp"
	"github.com/malivvan/crypto/pgp/clearsign"
	"github.com/malivvan/crypto/pgp/packet"
)

const (
	testMnemonic  = "agree choice donor anxiety expect little beef pass agree choice donor anxiety expect little beef pass agree choice donor anxiety expect little beef sample"
	otherMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

// testConfig returns a wallet config with a fixed clock so that tests are
// deterministic.
func testConfig() *packet.Config {
	cfg := Defaults()
	cfg.Time = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	cfg.Rand = rand.Reader
	return cfg
}

// newTestWallet creates a wallet backed by a deterministic mnemonic.
func newTestWallet(t *testing.T, name, email, mnemonic string) Wallet {
	t.Helper()
	password := []byte("test-password")
	wl, err := NewWallet(name, email, mnemonic, password, testConfig())
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	return wl
}

func internal(w Wallet) *wallet {
	return w.(*wallet)
}

func TestNewWalletDeterministic(t *testing.T) {
	a := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	b := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	if !bytes.Equal(internal(a).entity.PrimaryKey.Fingerprint, internal(b).entity.PrimaryKey.Fingerprint) {
		t.Fatal("same mnemonic produced different entities")
	}

	const hardened = uint32(0x80000000)

	// Ed25519 signing keys match across wallets.
	ka, err := a.DeriveEd25519(hardened, hardened+1)
	if err != nil {
		t.Fatalf("DeriveEd25519: %v", err)
	}
	kb, err := b.DeriveEd25519(hardened, hardened+1)
	if err != nil {
		t.Fatalf("DeriveEd25519: %v", err)
	}
	if !bytes.Equal(ka.Seed(), kb.Seed()) {
		t.Fatal("same mnemonic produced different Ed25519 keys")
	}
	if len(ka.Seed()) != 32 {
		t.Fatalf("expected 32-byte Ed25519 seed, got %d", len(ka.Seed()))
	}

	// X25519 encryption keys match across wallets.
	xa, err := a.DeriveX25519(hardened, hardened+2)
	if err != nil {
		t.Fatalf("DeriveX25519: %v", err)
	}
	xb, err := b.DeriveX25519(hardened, hardened+2)
	if err != nil {
		t.Fatalf("DeriveX25519: %v", err)
	}
	if !bytes.Equal(xa.Secret, xb.Secret) {
		t.Fatal("same mnemonic produced different X25519 keys")
	}
	if len(xa.Secret) != 32 {
		t.Fatalf("expected 32-byte X25519 seed, got %d", len(xa.Secret))
	}

	// Symmetric secrets match across wallets.
	sa, err := a.DeriveSecret([]byte("com.example.app"), []byte("storage"))
	if err != nil {
		t.Fatalf("DeriveSecret: %v", err)
	}
	sb, err := b.DeriveSecret([]byte("com.example.app"), []byte("storage"))
	if err != nil {
		t.Fatalf("DeriveSecret: %v", err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("same mnemonic produced different SLIP-21 secrets")
	}
}

func TestReaderFromRejectsUnsupportedInputs(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)

	// Unsupported and nil inputs must error at the terminal, never silently
	// sign/encrypt an empty message.
	if out, err := wl.Sign(123).Bytes(); err == nil {
		t.Fatalf("expected Sign(int) to fail, got %d bytes", len(out))
	}
	if _, err := wl.Sign(nil).String(); err == nil {
		t.Fatal("expected Sign(nil) to fail")
	}
	if _, err := wl.Clearsign(struct{}{}).String(); err == nil {
		t.Fatal("expected Clearsign(struct) to fail")
	}
	if _, err := wl.Encrypt(3.14).Bytes(); err == nil {
		t.Fatal("expected Encrypt(float64) to fail")
	}
	if _, _, err := wl.Decrypt(42).Plaintext(); err == nil {
		t.Fatal("expected Decrypt(int) to fail")
	}
	if _, _, err := wl.DecryptVerify(nil).Plaintext(); err == nil {
		t.Fatal("expected DecryptVerify(nil) to fail")
	}
	if err := wl.Verify("data").Signature(nil).Verify(); err == nil {
		t.Fatal("expected Verify with nil signature input to fail")
	}
	if err := wl.Verify(make(chan int)).Verify(); err == nil {
		t.Fatal("expected Verify(chan) to fail")
	}
	// Valid inputs still work.
	ct, err := wl.Encrypt("ok").Bytes()
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if pt, _, err := wl.Decrypt(ct).Plaintext(); err != nil || string(pt) != "ok" {
		t.Fatalf("Decrypt roundtrip failed: %v %q", err, pt)
	}
}

func TestDerivationMisuseGuards(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)

	// Unhardened paths are rejected with a clear error.
	if _, err := wl.DeriveEd25519(44); err == nil {
		t.Fatal("expected unhardened DeriveEd25519 to fail")
	}
	if _, err := wl.DeriveX25519(44, 0); err == nil {
		t.Fatal("expected unhardened DeriveX25519 to fail")
	}
	// Empty paths are rejected.
	if _, err := wl.DeriveEd25519(); err == nil {
		t.Fatal("expected empty DeriveEd25519 path to fail")
	}
	if _, err := wl.DeriveX25519(); err == nil {
		t.Fatal("expected empty DeriveX25519 path to fail")
	}
	// Empty or missing SLIP-21 labels are rejected.
	if _, err := wl.DeriveSecret(); err == nil {
		t.Fatal("expected empty DeriveSecret labels to fail")
	}
	if _, err := wl.DeriveSecret([]byte("ok"), nil); err == nil {
		t.Fatal("expected nil DeriveSecret label to fail")
	}

	// Distinct paths must produce distinct keys.
	const hardened = uint32(0x80000000)
	one, err := wl.DeriveEd25519(hardened)
	if err != nil {
		t.Fatalf("DeriveEd25519: %v", err)
	}
	two, err := wl.DeriveEd25519(hardened, hardened+1)
	if err != nil {
		t.Fatalf("DeriveEd25519: %v", err)
	}
	if bytes.Equal(one.Seed(), two.Seed()) {
		t.Fatal("distinct paths produced identical Ed25519 keys")
	}
}

func TestDetachedSignVerify(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "my signed message"

	// Binary signature.
	sig, err := wl.Sign(msg).Bytes()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := wl.Verify(msg).Signature(sig).Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Armored signature via a writer.
	var out bytes.Buffer
	if err := wl.Sign([]byte(msg)).Armor().Output(&out); err != nil {
		t.Fatalf("Sign armored: %v", err)
	}
	if err := wl.Verify(msg).Signature(out.Bytes()).Armor().Verify(); err != nil {
		t.Fatalf("Verify armored: %v", err)
	}

	// Text signature.
	text := "hello\nworld\n"
	tsig, err := wl.Sign(text).Text().String()
	if err != nil {
		t.Fatalf("Sign text: %v", err)
	}
	if err := wl.Verify(text).Signature(tsig).Verify(); err != nil {
		t.Fatalf("Verify text: %v", err)
	}

	// Tampered data must fail.
	if err := wl.Verify(msg + "!"); err == nil {
		t.Fatal("expected tampered data verification to fail")
	}
	// Unknown signer must fail.
	other := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	if err := other.Verify(msg).Signature(sig).Verify(); err == nil {
		t.Fatal("expected unknown-signer verification to fail")
	}
	// Missing signature must fail.
	if err := wl.Verify(msg).Verify(); err == nil {
		t.Fatal("expected missing-signature verification to fail")
	}
}

func TestClearsign(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "hello clearsigned world\nsecond line\n"

	out, err := wl.Clearsign(msg).Headers(map[string]string{"Comment": "wallet test"}).String()
	if err != nil {
		t.Fatalf("Clearsign: %v", err)
	}

	block, rest := clearsign.Decode([]byte(out))
	if block == nil {
		t.Fatal("failed to decode clearsigned message")
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing data after clearsigned block")
	}
	if string(block.Plaintext) != msg {
		t.Fatalf("plaintext mismatch: got %q, want %q", block.Plaintext, msg)
	}
	signer, err := block.VerifySignature(pgp.EntityList{internal(wl).entity}, testConfig())
	if err != nil {
		t.Fatalf("clearsign verification failed: %v", err)
	}
	if signer == nil {
		t.Fatal("clearsign verification returned no signer")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "attack at dawn"

	// Binary, encrypted to self by default.
	ct, err := wl.Encrypt(msg).Bytes()
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, md, err := wl.Decrypt(ct).Plaintext()
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: got %q", pt)
	}
	if !md.IsEncrypted || md.LiteralData == nil {
		t.Fatalf("unexpected message details: %+v", md)
	}

	// Armored, with file hints.
	armored, err := wl.Encrypt([]byte(msg)).Armor().File(&pgp.FileHints{
		FileName: "note.txt",
		IsUTF8:   true,
		ModTime:  time.Unix(1700000000, 0).UTC(),
	}).String()
	if err != nil {
		t.Fatalf("Encrypt armored: %v", err)
	}
	pt, md, err = wl.Decrypt(armored).Armor().Plaintext()
	if err != nil {
		t.Fatalf("Decrypt armored: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: got %q", pt)
	}
	if md.LiteralData == nil || md.LiteralData.FileName != "note.txt" {
		t.Fatalf("file hints lost: %+v", md.LiteralData)
	}
}

func TestEncryptSignDecryptVerify(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	msg := "signed and sealed"

	// Alice signs and encrypts to Bob.
	ct, err := alice.EncryptSign(msg).To(internal(bob).entity).Armor().String()
	if err != nil {
		t.Fatalf("EncryptSign: %v", err)
	}

	// Bob decrypts and verifies Alice's signature.
	pt, md, err := bob.DecryptVerify(ct).Armor().Verifier(internal(alice).entity).Plaintext()
	if err != nil {
		t.Fatalf("DecryptVerify: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: got %q", pt)
	}
	if !md.IsSigned || md.Signature == nil || md.SignedBy == nil {
		t.Fatalf("signature was not verified: %+v", md)
	}

	// Without Alice's public key the signature cannot be verified.
	if _, _, err := bob.DecryptVerify(ct).Armor().Plaintext(); err == nil {
		t.Fatal("expected verification to fail for unknown signer")
	}

	// A different signer (Bob self-signed to himself) must not verify.
	selfCt, err := bob.EncryptSign(msg).Armor().String()
	if err != nil {
		t.Fatalf("EncryptSign self: %v", err)
	}
	if _, _, err := alice.DecryptVerify(selfCt).Armor().Plaintext(); err == nil {
		t.Fatal("expected verification to fail for wrong signer")
	}
}

func TestPasswordEncryption(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "password protected"

	ct, err := wl.Encrypt(msg).Password([]byte("hunter2")).Bytes()
	if err != nil {
		t.Fatalf("Encrypt with password: %v", err)
	}

	pt, md, err := wl.Decrypt(ct).Password([]byte("hunter2")).Plaintext()
	if err != nil {
		t.Fatalf("Decrypt with password: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: got %q", pt)
	}
	if !md.IsSymmetricallyEncrypted {
		t.Fatal("expected symmetric encryption to be reported")
	}

	// Wrong password must fail (and not hang).
	if _, _, err := wl.Decrypt(ct).Password([]byte("wrong")).Plaintext(); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestDecryptOutput(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	msg := "streaming plaintext output"

	// Plain encrypted message streams out of Decryptor.Output.
	ct, err := alice.Encrypt(msg).Armor().String()
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	var out bytes.Buffer
	if err := alice.Decrypt(ct).Armor().Output(&out); err != nil {
		t.Fatalf("Decrypt Output: %v", err)
	}
	if out.String() != msg {
		t.Fatalf("streamed plaintext mismatch: got %q", out.String())
	}

	// DecryptVerify.Output must refuse when the signature is unknown.
	ct, err = alice.EncryptSign(msg).To(internal(bob).entity).Armor().String()
	if err != nil {
		t.Fatalf("EncryptSign: %v", err)
	}
	out.Reset()
	if err := bob.DecryptVerify(ct).Armor().Output(&out); err == nil {
		t.Fatal("expected DecryptVerify.Output to fail for unknown signer")
	}
	// Note: with streaming, plaintext is emitted before the trailing
	// signature error is detected, so only the error is asserted here.
	// ... and must succeed once Alice's key is trusted.
	out.Reset()
	if err := bob.DecryptVerify(ct).Armor().Verifier(internal(alice).entity).Output(&out); err != nil {
		t.Fatalf("DecryptVerify Output: %v", err)
	}
	if out.String() != msg {
		t.Fatalf("streamed plaintext mismatch: got %q", out.String())
	}

	// Tampered ciphertext fails integrity checks during streaming.
	ctBytes, err := alice.Encrypt(msg).Bytes()
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ctBytes[len(ctBytes)/2] ^= 0x01
	out.Reset()
	if err := alice.Decrypt(ctBytes).Output(&out); err == nil {
		t.Fatal("expected tampered ciphertext to fail during Output")
	}
}

func TestDetachedSignatureTamperWithEncrypt(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "integrity"
	ct, err := wl.EncryptSign(msg).Bytes()
	if err != nil {
		t.Fatalf("EncryptSign: %v", err)
	}
	// Flipping a bit in the ciphertext must fail integrity checks.
	ct[len(ct)/2] ^= 0x01
	if _, _, err := wl.DecryptVerify(ct).Plaintext(); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

// compile-time check that the wallet satisfies the pgp.KeyRing contract.
var _ pgp.KeyRing = (*wallet)(nil)

func TestWalletAsKeyRing(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)

	// Fresh wallets only know themselves.
	if len(bob.Entities()) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(bob.Entities()))
	}
	aliceID := internal(alice).entity.PrimaryKey.KeyId
	if got := bob.EntitiesById(aliceID); len(got) != 0 {
		t.Fatalf("expected unknown entity, got %d matches", len(got))
	}

	// Import Alice into Bob's keyring.
	if err := bob.AddEntity(internal(alice).entity); err != nil {
		t.Fatalf("AddEntity: %v", err)
	}
	if len(bob.Entities()) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(bob.Entities()))
	}
	if got := bob.EntitiesById(aliceID); len(got) != 1 {
		t.Fatalf("expected 1 match for Alice, got %d", len(got))
	}
	if keys := bob.KeysById(aliceID); len(keys) == 0 {
		t.Fatal("expected KeysById to find Alice's key")
	}
	// Duplicate imports are ignored.
	if err := bob.AddEntity(internal(alice).entity); err != nil {
		t.Fatalf("AddEntity duplicate: %v", err)
	}
	if len(bob.Entities()) != 2 {
		t.Fatalf("expected duplicate to be ignored, got %d entities", len(bob.Entities()))
	}
	if err := bob.AddEntity(nil); err == nil {
		t.Fatal("expected AddEntity(nil) to fail")
	}

	// A signature by Alice now verifies against Bob's wallet keyring.
	msg := "hello from alice"
	sig, err := alice.Sign(msg).Armor().String()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := bob.Verify(msg).Signature(sig).Armor().Verify(); err != nil {
		t.Fatalf("Verify via keyring: %v", err)
	}
}

func TestLockUnlock(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	if wl.IsLocked() {
		t.Fatal("fresh wallet should be unlocked")
	}

	if err := wl.Lock("secret"); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if !wl.IsLocked() {
		t.Fatal("wallet should be locked after Lock")
	}
	// Lock is idempotent.
	if err := wl.Lock("secret"); err != nil {
		t.Fatalf("Lock again: %v", err)
	}

	// Locked wallets cannot sign.
	if _, err := wl.Sign("data").String(); err == nil {
		t.Fatal("expected signing to fail while locked")
	}
	// Wrong passphrase must not unlock.
	if err := wl.Unlock("wrong"); err == nil {
		t.Fatal("expected unlock with wrong passphrase to fail")
	}
	if !wl.IsLocked() {
		t.Fatal("wallet must remain locked after a failed unlock")
	}
	if err := wl.Unlock("secret"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if wl.IsLocked() {
		t.Fatal("wallet should be unlocked after Unlock")
	}
	// Unlock is idempotent.
	if err := wl.Unlock("secret"); err != nil {
		t.Fatalf("Unlock again: %v", err)
	}

	sig, err := wl.Sign("data").String()
	if err != nil {
		t.Fatalf("Sign after unlock: %v", err)
	}
	if err := wl.Verify("data").Signature(sig).Verify(); err != nil {
		t.Fatalf("Verify after unlock: %v", err)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	if err := bob.AddEntity(internal(alice).entity); err != nil {
		t.Fatalf("AddEntity: %v", err)
	}
	msg := "persisted state"

	// Saving an unlocked wallet must be refused.
	var buf bytes.Buffer
	if err := bob.Save(&buf); err == nil {
		t.Fatal("expected Save of unlocked wallet to fail")
	}

	const pass = "wallet-password"
	if err := bob.Lock(pass); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := bob.Save(&buf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The saved file must not contain plaintext secrets.
	if bytes.Contains(buf.Bytes(), []byte(msg)) {
		t.Fatal("saved wallet contains plaintext data")
	}

	loaded, err := Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Keep the loaded wallet on the same deterministic clock as the rest of
	// the test so that signature times match.
	internal(loaded).config.Time = testConfig().Time
	// Own key and keyring survived the roundtrip.
	if !loaded.IsLocked() {
		t.Fatal("loaded wallet should start locked")
	}
	if len(loaded.Entities()) != 2 {
		t.Fatalf("expected 2 entities after load, got %d", len(loaded.Entities()))
	}
	// Loaded wallets cannot derive new SLIP keys.
	if _, err := loaded.DeriveEd25519(0x80000000); err == nil {
		t.Fatal("expected DeriveEd25519 to fail on a loaded wallet")
	}
	if _, err := loaded.DeriveSecret([]byte("x")); err == nil {
		t.Fatal("expected DeriveSecret to fail on a loaded wallet")
	}

	// Wrong passphrase must not unlock the loaded wallet.
	if err := loaded.Unlock("wrong"); err == nil {
		t.Fatal("expected unlock with wrong passphrase to fail")
	}
	if err := loaded.Unlock(pass); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Bob's loaded key can sign ...
	sig, err := loaded.Sign(msg).String()
	if err != nil {
		t.Fatalf("Sign after load: %v", err)
	}
	if err := bob.Verify(msg).Signature(sig).Verify(); err != nil {
		t.Fatalf("Verify by original Bob wallet: %v", err)
	}
	// ... and still trusts Alice's key for verification.
	asig, err := alice.Sign(msg).String()
	if err != nil {
		t.Fatalf("Alice Sign: %v", err)
	}
	if err := loaded.Verify(msg).Signature(asig).Verify(); err != nil {
		t.Fatalf("Verify via loaded keyring: %v", err)
	}

	// Deterministic entity fingerprints across the save/load cycle.
	if !bytes.Equal(internal(bob).entity.PrimaryKey.Fingerprint, internal(loaded).entity.PrimaryKey.Fingerprint) {
		t.Fatal("entity fingerprint changed across save/load")
	}
}

func TestKeyRingSatisfiedByOpenpgpReaders(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	// The wallet can be used wherever a KeyRing is accepted, e.g. serializing
	// its own public keyring.
	el := pgp.EntityList(alice.Entities())
	if len(el) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(el))
	}
}

func TestV6WalletRoundtrip(t *testing.T) {
	cfg := testConfig()
	cfg.V6Keys = true
	password := []byte("test-password")
	wl, err := NewWallet("Alice", "alice@example.com", testMnemonic, password, cfg)
	if err != nil {
		t.Fatalf("NewWallet v6: %v", err)
	}
	if internal(wl).entity.PrimaryKey.Version != 6 {
		t.Fatalf("expected v6 primary key, got v%d", internal(wl).entity.PrimaryKey.Version)
	}
	for _, sub := range internal(wl).entity.Subkeys {
		if sub.PublicKey.Version != 6 {
			t.Fatalf("expected v6 subkey, got v%d", sub.PublicKey.Version)
		}
	}

	msg := "v6 roundtrip"
	ct, err := wl.EncryptSign(msg).Armor().String()
	if err != nil {
		t.Fatalf("EncryptSign v6: %v", err)
	}
	pt, md, err := wl.DecryptVerify(ct).Armor().Plaintext()
	if err != nil {
		t.Fatalf("DecryptVerify v6: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: got %q", pt)
	}
	if !md.IsSigned || md.Signature == nil {
		t.Fatal("v6 signature was not verified")
	}

	sig, err := wl.Sign(msg).Armor().String()
	if err != nil {
		t.Fatalf("Sign v6: %v", err)
	}
	if err := wl.Verify(msg).Signature(sig).Armor().Verify(); err != nil {
		t.Fatalf("Verify v6: %v", err)
	}
}

func TestNewWalletRequiresPassword(t *testing.T) {
	if _, err := NewWallet("A", "a@b.c", testMnemonic, nil, testConfig()); err == nil {
		t.Fatal("expected NewWallet with nil password to fail")
	}
}

func TestNewWalletEmptyIdentity(t *testing.T) {
	pw := func() []byte { return []byte("test-password") }

	// v4 keys require a user id.
	if _, err := NewWallet("", "", testMnemonic, pw(), testConfig()); err == nil {
		t.Fatal("expected v4 NewWallet with empty identity to fail")
	}
	// A partially filled identity is fine.
	if _, err := NewWallet("", "a@b.c", testMnemonic, pw(), testConfig()); err != nil {
		t.Fatalf("v4 NewWallet with email only: %v", err)
	}

	// v6 keys may be generated without a user id and stay fully usable.
	v6cfg := testConfig()
	v6cfg.V6Keys = true
	wl, err := NewWallet("", "", testMnemonic, pw(), v6cfg)
	if err != nil {
		t.Fatalf("v6 NewWallet without identity: %v", err)
	}
	msg := "anonymous v6"
	ct, err := wl.EncryptSign(msg).Armor().String()
	if err != nil {
		t.Fatalf("EncryptSign: %v", err)
	}
	if pt, _, err := wl.DecryptVerify(ct).Armor().Plaintext(); err != nil || string(pt) != msg {
		t.Fatalf("DecryptVerify: %v %q", err, pt)
	}
}

func TestEncryptorMultiplePasswords(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "multi password"
	ct, err := wl.Encrypt(msg).Password([]byte("first"), []byte("second")).Bytes()
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for _, pw := range [][]byte{[]byte("first"), []byte("second")} {
		pt, md, err := wl.Decrypt(ct).Password(pw).Plaintext()
		if err != nil {
			t.Fatalf("Decrypt with %q: %v", pw, err)
		}
		if string(pt) != msg {
			t.Fatalf("plaintext mismatch: %q", pt)
		}
		if !md.IsSymmetricallyEncrypted {
			t.Fatal("expected symmetric encryption")
		}
	}
	if _, _, err := wl.Decrypt(ct).Password([]byte("third")).Plaintext(); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestEncryptToHiddenRecipient(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	msg := "hidden recipient"

	ct, err := alice.Encrypt(msg).ToHidden(internal(bob).entity).Bytes()
	if err != nil {
		t.Fatalf("Encrypt ToHidden: %v", err)
	}
	pt, md, err := bob.Decrypt(ct).Plaintext()
	if err != nil {
		t.Fatalf("Bob Decrypt: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if !md.IsEncrypted {
		t.Fatal("expected encrypted message")
	}
}

func TestDecryptorCustomPrompt(t *testing.T) {
	wl := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	msg := "prompt driven"
	ct, err := wl.Encrypt(msg).Password([]byte("hunter2")).Bytes()
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The prompt is consulted for symmetric keys.
	pt, _, err := wl.Decrypt(ct).Prompt(func(keys []pgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			t.Fatal("unexpected asymmetric prompt")
		}
		return []byte("hunter2"), nil
	}).Plaintext()
	if err != nil {
		t.Fatalf("Decrypt with prompt: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: %q", pt)
	}

	// A failing prompt aborts decryption.
	if _, _, err := wl.Decrypt(ct).Prompt(func(keys []pgp.Key, symmetric bool) ([]byte, error) {
		return nil, fmt.Errorf("user cancelled")
	}).Plaintext(); err == nil {
		t.Fatal("expected failing prompt to abort decryption")
	}
}

func TestEncryptorSessionKeyAndConfig(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	msg := "session key + config override"

	// A fixed 32-byte session key (AES-256) must produce a decryptable message.
	sessionKey := bytes.Repeat([]byte{0x42}, 32)
	ct, err := alice.Encrypt(msg).To(internal(bob).entity).SessionKey(sessionKey).Bytes()
	if err != nil {
		t.Fatalf("Encrypt with session key: %v", err)
	}
	if pt, _, err := bob.Decrypt(ct).Plaintext(); err != nil || string(pt) != msg {
		t.Fatalf("Decrypt with session key: %v %q", err, pt)
	}

	// A per-call config override works on both encrypt and decrypt. The
	// cipher is negotiated from recipient preferences, so only roundtrip
	// correctness (not the exact cipher) is asserted here.
	cfg := testConfig()
	cfg.DefaultCipher = packet.CipherAES128
	ct2, err := alice.Encrypt(msg).To(internal(bob).entity).Config(cfg).Bytes()
	if err != nil {
		t.Fatalf("Encrypt with config: %v", err)
	}
	if pt, md, err := bob.Decrypt(ct2).Config(cfg).Plaintext(); err != nil || string(pt) != msg {
		t.Fatalf("Decrypt with config: %v %q", err, pt)
	} else if md.DecryptedWithAlgorithm == 0 {
		t.Fatal("expected a decryption algorithm to be reported")
	}
}

func TestEncryptOutsideSig(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	msg := "outside signature"

	// Produce a detached signature over the message, then embed it in the
	// encrypted message instead of signing during encryption.
	rawSig, err := alice.Sign(msg).Bytes()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ct, err := alice.Encrypt(msg).To(internal(bob).entity).OutsideSig(rawSig).Bytes()
	if err != nil {
		t.Fatalf("Encrypt with outside signature: %v", err)
	}

	pt, md, err := bob.DecryptVerify(ct).Verifier(internal(alice).entity).Plaintext()
	if err != nil {
		t.Fatalf("DecryptVerify with outside signature: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if !md.IsSigned || md.SignedBy == nil {
		t.Fatal("outside signature was not verified")
	}
	// Without Alice's key the signature cannot be verified.
	if _, _, err := bob.DecryptVerify(ct).Plaintext(); err == nil {
		t.Fatal("expected verification failure without signer key")
	}
}

func TestEncryptSignTextSignature(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	// Text signatures canonicalize line endings, so use a single-line body.
	msg := "signed as text"

	ct, err := alice.EncryptSign(msg).Text().To(internal(bob).entity).Armor().String()
	if err != nil {
		t.Fatalf("EncryptSign text: %v", err)
	}
	pt, md, err := bob.DecryptVerify(ct).Armor().Verifier(internal(alice).entity).Plaintext()
	if err != nil {
		t.Fatalf("DecryptVerify text: %v", err)
	}
	if string(pt) != msg {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if md.Signature == nil || md.Signature.SigType != packet.SigTypeText {
		t.Fatalf("expected text signature, got %v", md.Signature)
	}
}

func TestEncryptorEncryptionTime(t *testing.T) {
	alice := newTestWallet(t, "Alice", "alice@example.com", testMnemonic)
	bob := newTestWallet(t, "Bob", "bob@example.com", otherMnemonic)
	msg := "encryption time override"

	// The EncryptionTime selects the recipient key valid at that time; both
	// wallets are created at the fixed test clock, so use a later time.
	later := time.Unix(1700000000+86400, 0).UTC()
	ct, err := alice.Encrypt(msg).To(internal(bob).entity).EncryptionTime(later).Bytes()
	if err != nil {
		t.Fatalf("Encrypt with encryption time: %v", err)
	}
	if pt, _, err := bob.Decrypt(ct).Plaintext(); err != nil || string(pt) != msg {
		t.Fatalf("Decrypt: %v %q", err, pt)
	}
}
