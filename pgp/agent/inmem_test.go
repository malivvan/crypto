package gpg_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/malivvan/crypto/ed25519"
	walletgpg "github.com/malivvan/crypto/pgp/agent"
	assuan "github.com/malivvan/crypto/pgp/agent/client"
	"github.com/malivvan/crypto/pgp/agent/server"
)

// TestAssuanServeInMemory bypasses the socket by wiring a ProtoInfo server to a
// net.Pipe and talking to it over the Assuan client. It verifies HAVEKEY and
// RESET machinery without depending on the transport.
func TestAssuanServeInMemory(t *testing.T) {
	sk, _ := ed25519.GenerateKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if sk == nil {
		t.Fatal("no key")
	}
	sign := walletgpg.SignKey(sk, "in-memory")
	kr := walletgpg.NewKeyring(sign)

	serverSide, clientSide := net.Pipe()
	defer func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	}()
	go func() {
		_ = server.Serve(serverSide, walletgpg.ProtoInfo(kr))
	}()

	ses, err := assuan.Init(clientSide)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer ses.Close()

	if _, err := ses.SimpleCmd("HAVEKEY", sign.GripHex); err != nil {
		t.Fatalf("HAVEKEY via ProvoInfo: %v", err)
	}
	if _, err := ses.SimpleCmd("HAVEKEY", "ZZ0000"); err == nil {
		t.Fatalf("HAVEKEY(unknown) unexpectedly ok")
	}
}
