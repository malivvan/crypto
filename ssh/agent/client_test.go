package agent_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	walletEd "github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/ssh/agent"
)

// sshED25519Blob re-derives the RFC-style public key blob (string "ssh-ed25519"
// followed by string <32-byte point>) that the agent advertises, so this test
// is independent of any ssh library.
func sshED25519Blob(pub []byte) []byte {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(agent.KeyAlgoED25519)))
	out := append([]byte{}, lb[:]...)
	out = append(out, agent.KeyAlgoED25519...)
	binary.BigEndian.PutUint32(lb[:], uint32(len(pub)))
	out = append(out, lb[:]...)
	return append(out, pub...)
}

// TestClientRoundtrip uses our dependency-free Client against our own Server,
// proving the two first-party halves interlock without any external ssh library.
func TestClientRoundtrip(t *testing.T) {
	path, _ := startServer(t, 0x2a)
	c, err := agent.DialUnix(path)
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	defer c.Close()

	ids, err := c.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("len(ids)=%d, want 1", len(ids))
	}

	// Determinism / identity cross-check against the same key.
	expectedPriv := mustKey(t, seedOf(0x2a))
	want := sshED25519Blob(expectedPriv.PublicKey.Point)
	if !bytes.Equal(ids[0].Blob, want) {
		t.Fatalf("advertised key differs from the ssh-ed25519 encoding of the served key")
	}

	data := []byte("our first-party client challenges the wallet agent")
	sig, err := c.Sign(ids[0].Blob, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != walletEd.SignatureSize {
		t.Fatalf("raw signature len %d, want %d", len(sig), walletEd.SignatureSize)
	}
	if !walletEd.Verify(&walletEd.PublicKey{Point: expectedPriv.PublicKey.Point}, data, sig) {
		t.Fatalf("ed25519 verification of the agent signature failed")
	}
}

func TestServerRefusesUnknownKey(t *testing.T) {
	path, _ := startServer(t, 0x2a) // server holds seed 0x2a
	c, err := agent.DialUnix(path)
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	defer c.Close()

	// Sign with a point the server does not hold (seed 0x2b).
	foreignPriv := mustKey(t, seedOf(0x2b))
	blob := sshED25519Blob(foreignPriv.PublicKey.Point)
	if _, err := c.Sign(blob, []byte("hi")); err == nil {
		t.Fatalf("expected an error when signing with a key the server lacks")
	}
}
