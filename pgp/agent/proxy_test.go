package gpg_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/malivvan/crypto/ed25519"
	walletgpg "github.com/malivvan/crypto/pgp/agent"
	assuan "github.com/malivvan/crypto/pgp/agent/client"
	"github.com/malivvan/crypto/pgp/agent/common"
)

func mustSign(t *testing.T, seed byte) *ed25519.PrivateKey {
	t.Helper()
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedB {
		seedB[i] = seed
	}
	sk, err := ed25519.GenerateKeyFromSeed(seedB)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	return sk
}

// serverWithKR binds a standalone agent Server holding exactly kr and returns
// its unix socket path.
func serverWithKR(t *testing.T, kr *walletgpg.Keyring) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "S.gpg-agent")
	srv, err := walletgpg.Listen(sock, kr, false)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// TestDialComm us the high-level Dial connector against a real standalone
// server and drives a trivial NOP over it.
func TestDialComm(t *testing.T) {
	remote := walletgpg.SignKey(mustSign(t, 0xa0), "remote")
	localTmpPos := serverWithKR(t, walletgpg.NewKeyring(remote))
	ses, err := walletgpg.Dial(localTmpPos)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer ses.Close()
	if _, err := ses.SimpleCmd("NOP", ""); err != nil {
		t.Fatalf("NOP: %v", err)
	}
}

func TestLocalKeyguardRoutesByGrip(t *testing.T) {
	keyA := walletgpg.SignKey(mustSign(t, 0x11), "local")
	keyB := walletgpg.SignKey(mustSign(t, 0x22), "remote")
	guard := walletgpg.LocalKeyguard(walletgpg.NewKeyring(keyA))

	if local, err := guard("HAVEKEY", keyA.GripHex); err != nil || !local {
		t.Fatalf("local key A should stay local (local=%v err=%v)", local, err)
	}
	if local, err := guard("HAVEKEY", keyB.GripHex); err != nil || local {
		t.Fatalf("foreign key B should route remote (local=%v err=%v)", local, err)
	}
	// A mixed grip list that includes a foreign key must route remote.
	if local, err := guard("HAVEKEY", keyA.GripHex+" "+keyB.GripHex); err != nil || local {
		t.Fatalf("mixed list routing wrong: local=%v err=%v (expect remote=false)", local, err)
	}
}

// TestMergeModeRelaysForeignHavekey wires the local wire to an upstream that
// actually holds a foreign key and verifies ReadAndRelay tunnels the request so
// an unmodified downstream client gets the upstream "have key" answer.
func TestMergeModeRelaysForeignHavekey(t *testing.T) {
	keyB := walletgpg.SignKey(mustSign(t, 0x33), "upstream-held")
	upstreamSock := serverWithKR(t, walletgpg.NewKeyring(keyB))

	up, err := walletgpg.Dial(upstreamSock)
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}
	defer up.Close()

	// Sanity: upstream really holds B.
	if err := checkHavekey(up, keyB.GripHex); err != nil {
		t.Fatalf("upstream does not hold B: %v", err)
	}

	// "down" models the downstream client's already-open pipe that issued
	// HAVEKEY B; its input is closed for this non-inquire command.
	var relayed bytes.Buffer
	down := common.NewPipe(bytes.NewBufferString(""), &relayed)

	if err := walletgpg.ReadAndRelay(&down, up, "HAVEKEY", keyB.GripHex); err != nil {
		t.Fatalf("ReadAndRelay: %v", err)
	}
	if bytes.Contains(relayed.Bytes(), []byte("ERR")) {
		t.Fatalf("relay surfaced upstream error: %q", relayed.String())
	}
	if !bytes.Contains(relayed.Bytes(), []byte("OK")) {
		t.Fatalf("relay did not relay upstream OK: %q", relayed.String())
	}
}

func checkHavekey(ses *assuan.Session, grip string) error {
	_, err := ses.SimpleCmd("HAVEKEY", grip)
	return err
}
