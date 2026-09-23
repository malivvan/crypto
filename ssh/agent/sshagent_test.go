package agent_test

import (
	"path/filepath"
	"testing"

	walletEd "github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/ssh/agent"
)

func seedOf(o byte) []byte {
	s := make([]byte, walletEd.SeedSize)
	for i := range s {
		s[i] = o
	}
	return s
}

// mustKey derives the wallet Ed25519 key for the given uniform seed byte,
// failing the test on any error.
func mustKey(t *testing.T, seed []byte) *walletEd.PrivateKey {
	t.Helper()
	k, err := walletEd.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("wallet key: %v", err)
	}
	return k
}

func startServer(t *testing.T, seedByte byte, addComment ...bool) (path string, walletKey *walletEd.PrivateKey) {
	t.Helper()
	walletKey = mustKey(t, seedOf(seedByte))
	path = filepath.Join(t.TempDir(), "agent.sock")
	srv, err := agent.Listen(path, agent.NewServerKeyring(), false)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.AddKey(walletKey, "wallet-key")
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })
	return path, walletKey
}
