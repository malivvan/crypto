// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

// fakeConn implements ConnMetadata for use in tests.
type fakeConn struct{}

func (c *fakeConn) User() string          { return "gopher" }
func (c *fakeConn) SessionID() []byte     { return nil }
func (c *fakeConn) ClientVersion() []byte { return nil }
func (c *fakeConn) ServerVersion() []byte { return nil }
func (c *fakeConn) RemoteAddr() net.Addr  { return nil }
func (c *fakeConn) LocalAddr() net.Addr   { return nil }

func testHostKeyCert(t *testing.T, key Signer) *Certificate {
	t.Helper()
	cert := &Certificate{
		Nonce:           []byte{},
		Key:             key.PublicKey(),
		Serial:          42,
		CertType:        HostCert,
		KeyId:           "test",
		ValidPrincipals: []string{"localhost"},
		ValidAfter:      0,
		ValidBefore:     CertTimeInfinity,
		Permissions: Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
		Reserved: []byte{},
	}
	if err := cert.SignCert(rand.Reader, key); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return cert
}

func TestParseCert(t *testing.T) {
	key := testSigners["ed25519"]
	cert := testHostKeyCert(t, key)
	wire := cert.Marshal()

	parsed, err := ParsePublicKey(wire)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	parsedCert, ok := parsed.(*Certificate)
	if !ok {
		t.Fatalf("expected *Certificate, got %T", parsed)
	}
	if parsedCert.Type() != CertAlgoED25519v01 {
		t.Errorf("unexpected cert type %q", parsedCert.Type())
	}
	if !bytes.Equal(parsedCert.Marshal(), wire) {
		t.Error("certificate did not round trip")
	}
	if parsedCert.Serial != cert.Serial ||
		parsedCert.CertType != cert.CertType ||
		parsedCert.KeyId != cert.KeyId ||
		!reflect.DeepEqual(parsedCert.ValidPrincipals, cert.ValidPrincipals) ||
		parsedCert.ValidAfter != cert.ValidAfter ||
		parsedCert.ValidBefore != cert.ValidBefore {
		t.Errorf("parsed certificate fields do not match: %+v", parsedCert)
	}
	if !bytes.Equal(parsedCert.SignatureKey.Marshal(), key.PublicKey().Marshal()) {
		t.Error("parsed certificate signature key does not match")
	}
}

func TestParseCertNestedSignatureKey(t *testing.T) {
	key := testSigners["ed25519"]
	cert := testHostKeyCert(t, key)
	// Make the signature key itself a certificate: parsing must reject it.
	cert.SignatureKey = testPublicKeys["cert"]
	_, err := ParsePublicKey(cert.Marshal())
	if err == nil {
		t.Error("ParsePublicKey of cert with cert signature key succeeded, expected error")
	}
}

func TestParseCertWithOptions(t *testing.T) {
	key := testSigners["ed25519"]
	cert := &Certificate{
		Key:      key.PublicKey(),
		CertType: UserCert,
		Permissions: Permissions{
			CriticalOptions: map[string]string{
				"force-command":  "/bin/sh",
				"source-address": "127.0.0.1",
			},
			Extensions: map[string]string{
				"permit-ptyallocate": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, key); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	parsed, err := ParsePublicKey(cert.Marshal())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	parsedCert := parsed.(*Certificate)
	if !reflect.DeepEqual(parsedCert.CriticalOptions, cert.CriticalOptions) {
		t.Errorf("critical options mismatch: got %v, want %v", parsedCert.CriticalOptions, cert.CriticalOptions)
	}
	if !reflect.DeepEqual(parsedCert.Extensions, cert.Extensions) {
		t.Errorf("extensions mismatch: got %v, want %v", parsedCert.Extensions, cert.Extensions)
	}
}

func TestValidateCert(t *testing.T) {
	key := testSigners["ed25519"]
	cert := &Certificate{
		Key:             key.PublicKey(),
		CertType:        UserCert,
		ValidPrincipals: []string{"gopher"},
		ValidAfter:      uint64(time.Now().Unix() - 100),
		ValidBefore:     uint64(time.Now().Unix() + 100),
		Permissions: Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}
	if err := cert.SignCert(rand.Reader, key); err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	checker := CertChecker{
		IsUserAuthority: func(k PublicKey) bool { return bytes.Equal(k.Marshal(), key.PublicKey().Marshal()) },
	}
	if err := checker.CheckCert("gopher", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}

	// Unknown principal.
	if err := checker.CheckCert("not-gopher", cert); err == nil {
		t.Error("CheckCert with unknown principal succeeded, expected error")
	}

	// Expired.
	expired := *cert
	expired.ValidBefore = uint64(time.Now().Unix() - 100)
	expired.Signature = nil
	if err := expired.SignCert(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckCert("gopher", &expired); err == nil {
		t.Error("CheckCert with expired cert succeeded, expected error")
	}

	// Not yet valid.
	future := *cert
	future.ValidAfter = uint64(time.Now().Unix() + 3600)
	future.Signature = nil
	if err := future.SignCert(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckCert("gopher", &future); err == nil {
		t.Error("CheckCert with not-yet-valid cert succeeded, expected error")
	}

	// Revoked.
	revoked := *cert
	checker.IsRevoked = func(c *Certificate) bool { return c.Serial == cert.Serial }
	if err := checker.CheckCert("gopher", &revoked); err == nil {
		t.Error("CheckCert with revoked cert succeeded, expected error")
	}
	checker.IsRevoked = nil

	// Unsupported critical option.
	optCert := *cert
	optCert.CriticalOptions = map[string]string{"force-command": "/bin/sh"}
	optCert.Signature = nil
	if err := optCert.SignCert(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckCert("gopher", &optCert); err == nil {
		t.Error("CheckCert with unsupported critical option succeeded, expected error")
	}

	// Supported critical option.
	checker.SupportedCriticalOptions = []string{"force-command"}
	if err := checker.CheckCert("gopher", &optCert); err != nil {
		t.Errorf("CheckCert with supported critical option: %v", err)
	}

	// Corrupted signature.
	tampered := *cert
	tampered.Signature = &Signature{Format: KeyAlgoED25519, Blob: []byte("bogus")}
	if err := checker.CheckCert("gopher", &tampered); err == nil {
		t.Error("CheckCert with corrupted signature succeeded, expected error")
	}
}

func newTestSigner(t *testing.T) Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestHostKeyCert(t *testing.T) {
	key := testSigners["ed25519"]
	cert := testHostKeyCert(t, key)

	checker := CertChecker{
		IsHostAuthority: func(k PublicKey, addr string) bool {
			return bytes.Equal(k.Marshal(), key.PublicKey().Marshal())
		},
	}
	if err := checker.CheckHostKey("localhost:22", nil, cert); err != nil {
		t.Errorf("CheckHostKey: %v", err)
	}
	// Principals are ["localhost"]; otherhost must fail.
	if err := checker.CheckHostKey("otherhost:22", nil, cert); err == nil {
		t.Error("CheckHostKey for otherhost succeeded, expected error")
	}

	// A non-certificate key is passed to the fallback.
	fallbackCalled := false
	checker.HostKeyFallback = func(addr string, remote net.Addr, key PublicKey) error {
		fallbackCalled = true
		return errors.New("fallback")
	}
	if err := checker.CheckHostKey("localhost:22", nil, key.PublicKey()); err == nil || !fallbackCalled {
		t.Error("HostKeyFallback was not invoked for non-certificate key")
	}
}

func TestCertTypes(t *testing.T) {
	key := testSigners["ed25519"]

	// A user certificate presented as a host key must be rejected.
	userCert := &Certificate{
		Key:      key.PublicKey(),
		CertType: UserCert,
	}
	if err := userCert.SignCert(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	checker := CertChecker{
		IsHostAuthority: func(k PublicKey, addr string) bool { return true },
		IsUserAuthority: func(k PublicKey) bool { return true },
	}
	if err := checker.CheckHostKey("localhost:22", nil, userCert); err == nil {
		t.Error("CheckHostKey with user cert succeeded, expected error")
	}

	// A host certificate used for user authentication must be rejected.
	hostCert := testHostKeyCert(t, key)
	if _, err := checker.Authenticate(ConnMetadata(&fakeConn{}), hostCert); err == nil {
		t.Error("Authenticate with host cert succeeded, expected error")
	}

	// A plain key is passed to the fallback.
	fallbackCalled := false
	checker.UserKeyFallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		fallbackCalled = true
		return nil, nil
	}
	if _, err := checker.Authenticate(ConnMetadata(&fakeConn{}), key.PublicKey()); err != nil || !fallbackCalled {
		t.Error("UserKeyFallback was not invoked for plain key")
	}
}

func TestCertSignerWrongKey(t *testing.T) {
	s1 := newTestSigner(t)
	s2 := newTestSigner(t)
	cert := testHostKeyCert(t, s1)
	if _, err := NewCertSigner(cert, s2); err == nil {
		t.Error("NewCertSigner with mismatched key succeeded, expected error")
	}
	signer, err := NewCertSigner(cert, s1)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}
	sig, err := signer.Sign(rand.Reader, []byte("data"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify([]byte("data"), sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSignCertWithCertificate(t *testing.T) {
	key := testSigners["ed25519"]
	cert := &Certificate{Key: key.PublicKey()}
	// The authority must not be a certificate signer.
	if err := cert.SignCert(rand.Reader, testSigners["cert"]); err == nil {
		t.Error("SignCert with certificate authority succeeded, expected error")
	}
}
