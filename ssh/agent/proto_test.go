package agent_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	walletEd "github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/ssh/agent"
)

// servePairs starts an in-memory OpenSSH agent: ServeAgent runs on serverConn
// backed by an in-memory Ed25519 keyring; the returned ExtendedAgent talks to
// it over clientConn.
func servePairs(t *testing.T, seedByte byte) agent.ExtendedAgent {
	t.Helper()
	kr := agent.NewKeyring()
	seed := make([]byte, walletEd.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	kr.Add(agent.AddedKey{Seed: seed, Comment: "proto-key"})

	srv, cli := net.Pipe()
	go func() {
		_ = agent.ServeAgent(kr, srv)
		_ = srv.Close()
	}()
	t.Cleanup(func() { _ = cli.Close() })
	return agent.NewClient(cli)
}

func blobFor(t *testing.T, pub []byte) []byte {
	t.Helper()
	// "ssh-ed25519" string followed by a <32-byte point> string, the standard
	// agent public blob encoding.
	out := writeSSHString(nil, []byte(agent.KeyAlgoED25519))
	return writeSSHString(out, pub)
}

func writeSSHString(b, v []byte) []byte {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(v)))
	b = append(b, lb[:]...)
	return append(b, v...)
}

func TestProtoAgentListAndSign(t *testing.T) {
	cl := servePairs(t, 0x51)
	keys, err := cl.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys)=%d, want 1", len(keys))
	}
	if keys[0].Format != agent.KeyAlgoED25519 {
		t.Fatalf("format %q", keys[0].Format)
	}

	// The advertised blob must be the ssh-ed25519 encoding of the seed's point.
	seed := make([]byte, walletEd.SeedSize)
	for i := range seed {
		seed[i] = 0x51
	}
	walletPriv := mustKey(t, seed)
	point := walletPriv.PublicKey.Point

	blob := blobFor(t, point)
	if !bytes.Equal(keys[0].Blob, blob) {
		t.Fatalf("advertised blob differs from expected ssh-ed25519 blob")
	}

	data := []byte("sign me through the wire")
	sig, err := cl.Sign(keys[0].Blob, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != walletEd.SignatureSize {
		t.Fatalf("signature len %d, want %d", len(sig), walletEd.SignatureSize)
	}
	if !walletEd.Verify(&walletEd.PublicKey{Point: walletPriv.PublicKey.Point}, data, sig) {
		t.Fatalf("signature failed verification")
	}

	// Determinism: same data, fresh call yields identical signature bytes.
	sig2, err := cl.Sign(keys[0].Blob, data)
	if err != nil {
		t.Fatalf("Sign(2): %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Fatalf("ed25519 signatures differ across calls")
	}
}

func TestProtoAgentKeyringMutate(t *testing.T) {
	kr := agent.NewKeyring()
	if _, err := kr.Sign(nil, []byte("x")); err == nil {
		t.Fatalf("expected error signing before any key added")
	}

	seed0 := make([]byte, walletEd.SeedSize)
	for i := range seed0 {
		seed0[i] = 0x01
	}
	if err := kr.Add(agent.AddedKey{Seed: seed0, Comment: "one"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	keys, err := kr.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len=%d want 1", len(keys))
	}

	// Remove unknown -> error; real -> OK.
	if err := kr.Remove(blobFor(t, []byte("nope"))); err == nil {
		t.Fatalf("expected remove error for unknown key")
	}

	// Sign then remove.
	walletPriv := mustKey(t, seed0)
	pubBlob := blobFor(t, walletPriv.PublicKey.Point)
	if _, err := kr.Sign(pubBlob, []byte("d")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := kr.Remove(pubBlob); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if n, _ := kr.List(); len(n) != 0 {
		t.Fatalf("expected empty list after remove, got %d", len(n))
	}
}

func TestProtoAgentLock(t *testing.T) {
	kr := agent.NewKeyring()
	seed := make([]byte, walletEd.SeedSize)
	for i := range seed {
		seed[i] = 0x02
	}
	kr.Add(agent.AddedKey{Seed: seed})

	pubBlob := blobFor(t, mustKey(t, seed).PublicKey.Point)
	if _, err := kr.Sign(pubBlob, []byte("d")); err != nil {
		t.Fatalf("Sign before lock: %v", err)
	}
	if err := kr.Lock([]byte("sekret")); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := kr.Sign(pubBlob, []byte("d")); err == nil {
		t.Fatalf("expected Sign to fail while locked")
	}
	if ks, _ := kr.List(); ks != nil {
		t.Fatalf("expected empty list while locked")
	}
	if err := kr.Unlock([]byte("wrong")); err == nil {
		t.Fatalf("expected unlock error for wrong passphrase")
	}
	if err := kr.Unlock([]byte("sekret")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := kr.Sign(pubBlob, []byte("d")); err != nil {
		t.Fatalf("Sign after unlock: %v", err)
	}
}

func TestProtoWireLockUnlock(t *testing.T) {
	cl := servePairs(t, 0x53)
	blob := blobFor(t, mustKey(t, repeat(0x53)).PublicKey.Point)
	if _, err := cl.Sign(blob, []byte("data")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Lock over the wire, then sign should fail, unlock to restore.
	if err := cl.Lock([]byte("p")); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if keys, _ := cl.List(); len(keys) != 0 {
		t.Fatalf("expected empty list while locked")
	}
	if err := cl.Unlock([]byte("p")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := cl.Sign(blob, []byte("data")); err != nil {
		t.Fatalf("sign after unlock: %v", err)
	}
}

func TestProtoKeyEqualsListedKey(t *testing.T) {
	cl := servePairs(t, 0x7a)
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	// Identity must be a *Key that round-trips.
	k0 := keys[0]
	if !reflect.DeepEqual(k0.Blob, blobFor(t, mustKey(t, repeat(0x7a)).PublicKey.Point)) {
		t.Fatalf("listed blob does not equal its wire form")
	}
	_ = k0.String()
}

func repeat(b byte) []byte {
	s := make([]byte, walletEd.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}
