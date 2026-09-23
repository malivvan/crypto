package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hostCertSigner returns a self-signed Ed25519 host certificate signer plus the
// plain signer that acts as its authority. It mirrors what a Server generates
// when no host key is configured, but keeps the authority key available for
// host key verification in tests.
func hostCertSigner(t *testing.T) (Signer, Signer) {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &Certificate{
		Key:         authority.PublicKey(),
		CertType:    HostCert,
		KeyId:       "test",
		ValidBefore: CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		t.Fatal(err)
	}
	signer, err := NewCertSigner(cert, authority)
	if err != nil {
		t.Fatal(err)
	}
	return signer, authority
}

// serveOne starts srv on a fresh local listener, serving a single connection,
// and returns the address to dial.
func serveOne(t *testing.T, srv *Server) net.Addr {
	t.Helper()

	l := newLocalListener()
	t.Cleanup(func() { l.Close() })
	go func() {
		// The error is reported by the dialing side, which fails when the
		// server cannot complete the handshake.
		_ = srv.serveOnce(l)
	}()
	return l.Addr()
}

// testClientConfig returns a ClientConfig for the test server with sensible
// defaults for the fields under test.
func testClientConfig() *ClientConfig {
	return &ClientConfig{
		User:            "testuser",
		Auth:            []AuthMethod{Password("testpass")},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
}

func TestClientDialRunCommand(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s ServerSession) {
			fmt.Fprintf(s, "hello %s\n", s.User())
			s.Exit(0)
		},
		PasswordHandler: func(_ Context, password string) bool { return password == "testpass" },
	}
	addr := serveOne(t, srv)

	client, err := Dial("tcp", addr.String(), testClientConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := client.User(); got != "testuser" {
		t.Errorf("client.User() = %q; want %q", got, "testuser")
	}
	if got := client.RemoteAddr(); got == nil {
		t.Error("client.RemoteAddr() = nil; want the server address")
	}
	meta, ok := client.Conn.(AlgorithmsConnMetadata)
	if !ok {
		t.Fatal("client connection does not expose negotiated algorithms")
	}
	if got := meta.Algorithms().HostKey; got != CertAlgoED25519v01 {
		t.Errorf("negotiated host key algorithm = %q; want %q", got, CertAlgoED25519v01)
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	out, err := session.Output("")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if want := "hello testuser\n"; string(out) != want {
		t.Errorf("Output = %q; want %q", out, want)
	}
}

func TestClientExitError(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler:         func(s ServerSession) { s.Exit(3) },
		PasswordHandler: func(_ Context, password string) bool { return password == "testpass" },
	}
	addr := serveOne(t, srv)

	client, err := Dial("tcp", addr.String(), testClientConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	err = session.Run("")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run error = %v; want *ExitError", err)
	}
	if got := exitErr.ExitStatus(); got != 3 {
		t.Errorf("ExitStatus = %d; want 3", got)
	}
}

func TestClientDialContext(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler:         func(s ServerSession) { s.Exit(0) },
		PasswordHandler: func(_ Context, password string) bool { return password == "testpass" },
	}
	addr := serveOne(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := DialContext(ctx, "tcp", addr.String(), testClientConfig())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := session.Run(""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	session.Close()

	cancel()
	if _, err := DialContext(ctx, "tcp", addr.String(), testClientConfig()); !errors.Is(err, context.Canceled) {
		t.Errorf("DialContext with canceled context = %v; want context.Canceled", err)
	}
}

func TestClientDialContextHandshakeTimeout(t *testing.T) {
	t.Parallel()

	// A listener that accepts connections but never speaks SSH, so the
	// handshake can only end when the context expires.
	l := newLocalListener()
	t.Cleanup(func() { l.Close() })
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-done
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if _, err := DialContext(ctx, "tcp", l.Addr().String(), testClientConfig()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("DialContext error = %v; want context.DeadlineExceeded", err)
	}
}

func TestClientNewClientConn(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler:         func(s ServerSession) { io.WriteString(s, "via raw conn") },
		PasswordHandler: func(_ Context, password string) bool { return password == "testpass" },
	}
	addr := serveOne(t, srv)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}

	c, chans, reqs, err := NewClientConn(conn, addr.String(), testClientConfig())
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	client := NewClient(c, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	var stdout strings.Builder
	session.Stdout = &stdout
	if err := session.Run(""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := "via raw conn"; stdout.String() != want {
		t.Errorf("stdout = %q; want %q", stdout.String(), want)
	}
}

func TestClientPublicKeyAuth(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := MarshalPrivateKey(priv, "test key")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)

	signer, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	authorized, _, _, _, err := ParseAuthorizedKey(MarshalAuthorizedKey(signer.PublicKey()))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if !KeysEqual(authorized, signer.PublicKey()) {
		t.Error("authorized key does not match the parsed private key")
	}
	if got := authorized.Type(); got != KeyAlgoED25519 {
		t.Errorf("public key type = %q; want %q", got, KeyAlgoED25519)
	}
	if FingerprintSHA256(authorized) == "" {
		t.Error("FingerprintSHA256 returned an empty fingerprint")
	}

	srv := &Server{
		Handler: func(s ServerSession) { io.WriteString(s, "signed in") },
		PublicKeyHandler: func(_ Context, key PublicKey) bool {
			return KeysEqual(authorized, key)
		},
	}
	addr := serveOne(t, srv)

	cfg := testClientConfig()
	cfg.Auth = []AuthMethod{PublicKeys(signer), PasswordCallback(func() (string, error) {
		return "", errors.New("password should not be needed")
	})}
	client, err := Dial("tcp", addr.String(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if err := session.Run(""); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestClientPassphraseProtectedKey(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := MarshalPrivateKeyWithPassphrase(priv, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)

	_, err = ParsePrivateKey(pemBytes)
	var missing *PassphraseMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("ParsePrivateKey error = %v; want *PassphraseMissingError", err)
	}
	if _, err := ParsePrivateKeyWithPassphrase(pemBytes, []byte("hunter2")); err != nil {
		t.Errorf("ParsePrivateKeyWithPassphrase: %v", err)
	}
}

func TestClientHostKeyVerification(t *testing.T) {
	t.Parallel()

	host, authority := hostCertSigner(t)
	other, _ := hostCertSigner(t)

	// A fresh server (and listener) per subtest: each test server serves a
	// single connection.
	newServer := func() net.Addr {
		return serveOne(t, &Server{
			HostSigners:     []Signer{host},
			Handler:         func(s ServerSession) { s.Exit(0) },
			PasswordHandler: func(_ Context, password string) bool { return password == "testpass" },
		})
	}

	t.Run("pinned", func(t *testing.T) {
		addr := newServer()
		cfg := testClientConfig()
		cfg.HostKeyCallback = FixedHostKey(host.PublicKey())
		client, err := Dial("tcp", addr.String(), cfg)
		if err != nil {
			t.Fatalf("Dial with pinned host key: %v", err)
		}
		client.Close()
	})

	t.Run("mismatch", func(t *testing.T) {
		addr := newServer()
		cfg := testClientConfig()
		cfg.HostKeyCallback = FixedHostKey(other.PublicKey())
		if _, err := Dial("tcp", addr.String(), cfg); err == nil {
			t.Fatal("Dial with a mismatched host key succeeded; want an error")
		}
	})

	t.Run("certchecker", func(t *testing.T) {
		addr := newServer()
		checker := &CertChecker{
			IsHostAuthority: func(auth PublicKey, _ string) bool {
				return KeysEqual(auth, authority.PublicKey())
			},
		}
		cfg := testClientConfig()
		cfg.HostKeyCallback = checker.CheckHostKey
		client, err := Dial("tcp", addr.String(), cfg)
		if err != nil {
			t.Fatalf("Dial with CertChecker host key callback: %v", err)
		}
		client.Close()
	})
}

func TestClientPortForwarding(t *testing.T) {
	t.Parallel()

	destination := sampleSocketServer()
	defer destination.Close()

	srv := &Server{
		Handler: func(ServerSession) {},
		PasswordHandler: func(_ Context, password string) bool {
			return password == "testpass"
		},
		LocalPortForwardingCallback: func(_ Context, host string, port uint32) bool {
			want := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
			return want == destination.Addr().String()
		},
	}
	addr := serveOne(t, srv)

	client, err := Dial("tcp", addr.String(), testClientConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial("tcp", destination.Addr().String())
	if err != nil {
		t.Fatalf("Client.Dial: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(sampleServerResponse) {
		t.Errorf("forwarded read = %q; want %q", got, sampleServerResponse)
	}
}

func TestClientNilConfig(t *testing.T) {
	t.Parallel()

	if _, err := Dial("tcp", "127.0.0.1:0", nil); err == nil {
		t.Error("Dial with a nil ClientConfig succeeded; want an error")
	}
	if _, err := DialContext(context.Background(), "tcp", "127.0.0.1:0", nil); err == nil {
		t.Error("DialContext with a nil ClientConfig succeeded; want an error")
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, _, _, err := NewClientConn(c1, "127.0.0.1:0", nil); err == nil {
		t.Error("NewClientConn with a nil ClientConfig succeeded; want an error")
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	t.Parallel()

	algs := SupportedAlgorithms()
	if len(algs.Ciphers) == 0 || len(algs.KeyExchanges) == 0 ||
		len(algs.MACs) == 0 || len(algs.HostKeys) == 0 || len(algs.PublicKeyAuths) == 0 {
		t.Fatalf("SupportedAlgorithms() returned an incomplete set: %+v", algs)
	}
	if algs.Ciphers[0] != CipherChaCha20Poly1305 {
		t.Errorf("preferred cipher = %q; want %q", algs.Ciphers[0], CipherChaCha20Poly1305)
	}
	if algs.KeyExchanges[0] != KeyExchangeMLKEM768X25519 {
		t.Errorf("preferred key exchange = %q; want %q", algs.KeyExchanges[0], KeyExchangeMLKEM768X25519)
	}
	if algs.HostKeys[0] != CertAlgoED25519v01 {
		t.Errorf("preferred host key algorithm = %q; want %q", algs.HostKeys[0], CertAlgoED25519v01)
	}
}
