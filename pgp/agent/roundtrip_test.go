package gpg_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/malivvan/crypto/ed25519"
	walletgpg "github.com/malivvan/crypto/pgp/agent"
	assuan "github.com/malivvan/crypto/pgp/agent/client"
	"github.com/malivvan/crypto/x25519"
)

func testKeys(t *testing.T) (sign *ed25519.PrivateKey, dec *x25519.PrivateKey) {
	sign, err := ed25519.GenerateKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	dec, err = x25519.GenerateKeyFromSeed(bytes.Repeat([]byte{2}, x25519.KeySize))
	if err != nil {
		t.Fatalf("decryption key: %v", err)
	}
	return sign, dec
}

// startStandalone spins up a Server in a temp dir and returns its path, a close
// func, and the constructed keyring keys.
func startStandalone(t *testing.T) (path string, closefn func(), sign *walletgpg.Key, dec *walletgpg.Key) {
	t.Helper()
	sk, dk := testKeys(t)
	signKey := walletgpg.SignKey(sk, "primary-signing")
	decKey := walletgpg.DecryptKey(dk, "primary-decryption")
	kr := walletgpg.NewKeyring(signKey, decKey)

	dir := t.TempDir()
	sock := filepath.Join(dir, "S.gpg-agent.wallet")
	srv, err := walletgpg.Listen(sock, kr, false)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		_ = srv.Serve()
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, func() { _ = srv.Close() }, signKey, decKey
}

func awaitDial(t *testing.T, path string) *assuan.Session {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", path)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	ses, err := assuan.Init(conn)
	if err != nil {
		t.Fatalf("assuan init: %v", err)
	}
	t.Cleanup(func() { _ = ses.Close() })
	return ses
}

func TestStandaloneKeygripsAndKeyinfo(t *testing.T) {
	sock, _, sign, dec := startStandalone(t)
	ses := awaitDial(t, sock)

	// HAVEKEY must be OK for our grips specifically.
	if _, err := ses.SimpleCmd("HAVEKEY", sign.GripHex); err != nil {
		t.Fatalf("HAVEKEY(sign): %v", err)
	}
	if _, err := ses.SimpleCmd("HAVEKEY", dec.GripHex); err != nil {
		t.Fatalf("HAVEKEY(dec): %v", err)
	}
	// HAVEKEY of an unknown grip must error.
	if _, err := ses.SimpleCmd("HAVEKEY", "AB"); err == nil {
		t.Fatalf("HAVEKEY(unknown) unexpectedly succeeded")
	}

	// KEYINFO --list must mention both grips (payload is hex-encoded).
	out, err := ses.SimpleCmd("KEYINFO", "--list")
	if err != nil {
		t.Fatalf("KEYINFO --list: %v", err)
	}
	out, err = hex.DecodeString(string(bytes.TrimSpace(out)))
	if err != nil {
		t.Fatalf("KEYINFO isn't hex payload: %v (raw %q)", err, out)
	}
	if !bytes.Contains(out, []byte(sign.GripHex)) || !bytes.Contains(out, []byte(dec.GripHex)) {
		t.Fatalf("KEYINFO --list missing grips: %q", out)
	}
}

func TestPksignRoundtrip(t *testing.T) {
	sock, _, sign, _ := startStandalone(t)
	ses := awaitDial(t, sock)

	// Deterministic digest that equals what the signer should sign.
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	var selOK = func() {
		if _, err := ses.SimpleCmd("SIGKEY", sign.GripHex); err != nil {
			t.Fatalf("SIGKEY: %v", err)
		}
	}
	selOK()

	resp, err := ses.Transact("PKSIGN", "", map[string]interface{}{
		"HASHVAL": []byte(hex.EncodeToString(digest)),
	})
	if err != nil {
		t.Fatalf("PKSIGN transact: %v", err)
	}
	sigHex := string(bytes.TrimSpace(resp))
	if sigHex == "" {
		t.Fatalf("empty signature response")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	// Deterministic vector: the signature must verify against the same digest
	// under the module's own ed25519.Verify.
	pub := sign.Ed25519.PublicKey
	if !ed25519.Verify(&pub, digest, sig) {
		t.Fatalf("signature did not verify against digest")
	}
	// And must not verify against a corrupted digest (sanity).
	if ed25519.Verify(&pub, []byte("x"), sig) {
		t.Fatalf("signature verified against wrong message")
	}
}

func TestPkdecryptRoundtrip(t *testing.T) {
	sock, _, _, dec := startStandalone(t)
	ses := awaitDial(t, sock)

	if _, err := ses.SimpleCmd("SIGKEY", dec.GripHex); err != nil {
		t.Fatalf("SIGKEY: %v", err)
	}

	// Produce a session key block the module itself can generate.
	sessionKey := []byte("0123456789abcdef") // 16-byte session secret
	ephemeral, ciphertext, err := x25519.Encrypt(rand.Reader, &dec.X25519.PublicKey, sessionKey)
	if err != nil {
		t.Fatalf("x25519.Encrypt: %v", err)
	}

	payload := make([]byte, 0, len(ephemeral)+len(ciphertext))
	payload = append(payload, ephemeral...)
	payload = append(payload, ciphertext...)

	resp, err := ses.Transact("PKDECRYPT", "", map[string]interface{}{
		"DATA": []byte(hex.EncodeToString(payload)),
	})
	if err != nil {
		t.Fatalf("PKDECRYPT transact: %v", err)
	}
	skHex := string(bytes.TrimSpace(resp))
	got, err := hex.DecodeString(skHex)
	if err != nil {
		t.Fatalf("decode session key: %v", err)
	}
	if !bytes.Equal(got, sessionKey) {
		t.Fatalf("decrypted session key mismatch: got %x want %x", got, sessionKey)
	}
}

// TestStandaloneSocketPermissions enforces the owner-only socket permission.
func TestStandaloneSocketPermissions(t *testing.T) {
	path, _, _, _ := startStandalone(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket mode %o: not owner-only (%o)", perm, fi.Mode().Perm())
	}
}
