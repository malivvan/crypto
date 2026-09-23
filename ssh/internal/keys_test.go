// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
)

func TestKeyMarshalParse(t *testing.T) {
	for _, tt := range []struct {
		key PublicKey
	}{
		{testPublicKeys["ed25519"]},
		{testPublicKeys["cert"]},
	} {
		wire := tt.key.Marshal()
		parsed, err := ParsePublicKey(wire)
		if err != nil {
			t.Errorf("ParsePublicKey(%T): %v", tt.key, err)
			continue
		}
		if !bytes.Equal(parsed.Marshal(), wire) {
			t.Errorf("ParsePublicKey(%T) result is not equal to original", tt.key)
		}
	}
}

func TestNewPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey(ed25519): %v", err)
	}
	if key.Type() != KeyAlgoED25519 {
		t.Errorf("unexpected key type %q", key.Type())
	}
	if _, err := NewPublicKey(ed25519.PublicKey(make([]byte, 16))); err == nil {
		t.Error("NewPublicKey with short ed25519 key succeeded, expected error")
	}
	if _, err := NewPublicKey(nil); err == nil {
		t.Error("NewPublicKey(nil) succeeded, expected error")
	}
}

func TestKeySignVerify(t *testing.T) {
	signer := testSigners["ed25519"]
	msg := []byte("data to be signed")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Format != KeyAlgoED25519 {
		t.Errorf("unexpected signature format %q", sig.Format)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if err := signer.PublicKey().Verify([]byte("other data"), sig); err == nil {
		t.Error("Verify with wrong data succeeded, expected error")
	}
	sig2 := *sig
	sig2.Format = "bogus"
	if err := signer.PublicKey().Verify(msg, &sig2); err == nil {
		t.Error("Verify with wrong signature format succeeded, expected error")
	}
}

func TestMarshalPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := MarshalPrivateKey(priv, "comment")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	signer, err := ParsePrivateKey(pem.EncodeToMemory(block))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if signer.PublicKey().Type() != KeyAlgoED25519 {
		t.Errorf("unexpected public key type %q", signer.PublicKey().Type())
	}

	// Encrypted with a passphrase.
	block, err = MarshalPrivateKeyWithPassphrase(priv, "comment", []byte("passphrase"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	_, err = ParsePrivateKey(pem.EncodeToMemory(block))
	if _, ok := err.(*PassphraseMissingError); !ok {
		t.Fatalf("expected PassphraseMissingError, got %v", err)
	}
	signer, err = ParsePrivateKeyWithPassphrase(pem.EncodeToMemory(block), []byte("passphrase"))
	if err != nil {
		t.Fatalf("ParsePrivateKeyWithPassphrase: %v", err)
	}
	if signer.PublicKey().Type() != KeyAlgoED25519 {
		t.Errorf("unexpected public key type %q", signer.PublicKey().Type())
	}
	if _, err := ParsePrivateKeyWithPassphrase(pem.EncodeToMemory(block), []byte("wrong")); err == nil {
		t.Error("ParsePrivateKeyWithPassphrase with wrong passphrase succeeded, expected error")
	}
}

func TestParseEncryptedPrivateKeyExcessiveBcryptRounds(t *testing.T) {
	// Build an OpenSSH private key by hand with an excessive bcrypt round
	// count, mirroring what a malicious key file could contain.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := signer.PublicKey().Marshal()

	pk1 := openSSHPrivateKey{
		Check1:  12345,
		Check2:  12345,
		Keytype: KeyAlgoED25519,
		Rest: Marshal(openSSHEd25519PrivateKey{
			Pub:     priv.Public().(ed25519.PublicKey),
			Priv:    []byte(priv),
			Comment: "comment",
		}),
	}
	keyBlock := Marshal(&openSSHEncryptedPrivateKey{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       pubKey,
		PrivKeyBlock: generateOpenSSHPadding(Marshal(pk1), 8),
	})
	blob := Marshal(&openSSHEncryptedPrivateKey{
		CipherName: "aes256-ctr",
		KdfName:    "bcrypt",
		KdfOpts: string(Marshal(struct {
			Salt   []byte
			Rounds uint32
		}{make([]byte, 16), 4096})),
		NumKeys:      1,
		PubKey:       pubKey,
		PrivKeyBlock: keyBlock,
	})
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(privateKeyAuthMagic), blob...),
	}
	_, err = ParsePrivateKeyWithPassphrase(pem.EncodeToMemory(block), []byte("passphrase"))
	if err == nil || !strings.Contains(err.Error(), "exceed maximum") {
		t.Fatalf("expected excessive rounds error, got %v", err)
	}
}

func TestAuthorizedKeyBasic(t *testing.T) {
	authorizedKeyBytes := MarshalAuthorizedKey(testPublicKeys["ed25519"])
	key, comment, options, rest, err := ParseAuthorizedKey(authorizedKeyBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if !bytes.Equal(key.Marshal(), testPublicKeys["ed25519"].Marshal()) {
		t.Error("ParseAuthorizedKey returned the wrong key")
	}
	if comment != "" || len(options) != 0 || len(rest) != 0 {
		t.Errorf("unexpected comment %q, options %q or rest %q", comment, options, rest)
	}

	// With a comment.
	authorizedKeyBytes = append(bytes.TrimSuffix(MarshalAuthorizedKey(testPublicKeys["ed25519"]), []byte("\n")), []byte(" user@host\n")...)
	key, comment, _, _, err = ParseAuthorizedKey(authorizedKeyBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey with comment: %v", err)
	}
	if comment != "user@host" {
		t.Errorf("unexpected comment %q", comment)
	}

	// With options and a comment.
	authorizedKeyBytes = append([]byte("no-port-forwarding,permitopen=\"10.0.0.1:22\" "), MarshalAuthorizedKey(testPublicKeys["ed25519"])...)
	key, comment, options, _, err = ParseAuthorizedKey(authorizedKeyBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey with options: %v", err)
	}
	if !reflect.DeepEqual(options, []string{"no-port-forwarding", `permitopen="10.0.0.1:22"`}) {
		t.Errorf("unexpected options %q", options)
	}
	if comment != "" {
		t.Errorf("unexpected comment %q", comment)
	}
}

func TestAuthorizedKeyTypeMismatch(t *testing.T) {
	// If the declared key type does not match the type embedded in the key
	// blob, parsing must fail.
	line := bytes.TrimSuffix(MarshalAuthorizedKey(testPublicKeys["ed25519"]), []byte("\n"))
	line = bytes.Replace(line, []byte("ssh-ed25519 "), []byte("ssh-ed25519-cert-v01@openssh.com "), 1)
	if _, _, _, _, err := ParseAuthorizedKey(append(line, '\n')); err == nil {
		t.Error("ParseAuthorizedKey with mismatched type succeeded, expected error")
	}
}

func TestAuthorizedKeyCertificate(t *testing.T) {
	line := MarshalAuthorizedKey(testPublicKeys["cert"])
	key, _, _, _, err := ParseAuthorizedKey(line)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if key.Type() != CertAlgoED25519v01 {
		t.Errorf("unexpected type %q", key.Type())
	}
}

func TestKnownHostsParsing(t *testing.T) {
	hosts := "hostname"
	pubKeyLine := MarshalAuthorizedKey(testPublicKeys["ed25519"])
	line := hosts + " " + string(pubKeyLine)
	marker, gotHosts, pubKey, comment, rest, err := ParseKnownHosts([]byte(line))
	if err != nil {
		t.Fatalf("ParseKnownHosts: %v", err)
	}
	if marker != "" {
		t.Errorf("unexpected marker %q", marker)
	}
	if !reflect.DeepEqual(gotHosts, []string{hosts}) {
		t.Errorf("unexpected hosts %q", gotHosts)
	}
	if !bytes.Equal(pubKey.Marshal(), testPublicKeys["ed25519"].Marshal()) {
		t.Error("wrong public key parsed")
	}
	if comment != "" || len(rest) != 0 {
		t.Errorf("unexpected comment %q or rest %q", comment, rest)
	}

	// Cert-authority entry.
	line = "@cert-authority " + hosts + " " + string(MarshalAuthorizedKey(testPublicKeys["cert"]))
	marker, _, pubKey, _, _, err = ParseKnownHosts([]byte(line))
	if err != nil {
		t.Fatalf("ParseKnownHosts cert-authority: %v", err)
	}
	if marker != "cert-authority" {
		t.Errorf("unexpected marker %q", marker)
	}
	if pubKey.Type() != CertAlgoED25519v01 {
		t.Errorf("unexpected type %q", pubKey.Type())
	}

	if _, _, _, _, _, err := ParseKnownHosts(nil); err == nil {
		t.Error("ParseKnownHosts(nil) succeeded, expected error")
	}
}

func TestFingerprintLegacyMD5(t *testing.T) {
	// The fingerprint is documented as colon-separated lowercase hex of the
	// MD5 of the marshaled key.
	fp := FingerprintLegacyMD5(testPublicKeys["ed25519"])
	if len(strings.Split(fp, ":")) != 16 {
		t.Errorf("unexpected MD5 fingerprint %q", fp)
	}
}

func TestFingerprintSHA256(t *testing.T) {
	fp := FingerprintSHA256(testPublicKeys["ed25519"])
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("unexpected SHA256 fingerprint %q", fp)
	}
	if len(fp) != len("SHA256:")+43 {
		t.Errorf("unexpected SHA256 fingerprint length %q", fp)
	}
}

func TestInvalidKeys(t *testing.T) {
	keyTypes := []string{
		"",
		"bogus",
		"ssh-rsa",
		"ecdsa-sha2-nistp256",
		"sk-ecdsa-sha2-nistp256@openssh.com",
	}
	for _, typ := range keyTypes {
		blob := Marshal(&struct {
			Name string
		}{Name: typ})
		if _, err := ParsePublicKey(blob); err == nil {
			t.Errorf("ParsePublicKey(%q) succeeded, expected error", typ)
		}
	}
}

// skTestKey is an sk-ssh-ed25519 key blob and a matching signature with the
// user-presence flag set, generated by OpenSSH.
var skTestKey = []byte("sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIJjzc2a20RjCvN/0ibH6UpGuN9F9hDvD7x182bOesNhHAAAABHNzaDo= user@host")

var skTestData = []byte("000000204CFE6EA65CCB99B69348339165C7F38E359D95807A377EEE8E603C71DC3316FA3200000006736B696E6E650000000E7373682D636F6E6E656374696F6E000000097075626C69636B6579010000001A736B2D7373682D65643235353139406F70656E7373682E636F6D0000004A0000001A736B2D7373682D65643235353139406F70656E7373682E636F6D0000002098F37366B6D118C2BCDFF489B1FA5291AE37D17D843BC3EF1D7CD9B39EB0D847000000047373683A")

var skTestSignature = []byte("000000670000001A736B2D7373682D65643235353139406F70656E7373682E636F6D000000404BF5CA0CAA553099306518732317B3FE4BA6C75365BC0CB02019FBE65A1647016CBD7A682C26928DF234C378ADDBC5077B47F72381144840BF00FB2DA2FB6A0A010000009E")

func TestSKEd25519(t *testing.T) {
	key, _, _, _, err := ParseAuthorizedKey(skTestKey)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if key.Type() != KeyAlgoSKED25519 {
		t.Fatalf("unexpected key type %q", key.Type())
	}
	skKey, ok := key.(*skEd25519PublicKey)
	if !ok {
		t.Fatalf("expected *skEd25519PublicKey, got %T", key)
	}
	if skKey.application != "ssh:" {
		t.Errorf("unexpected application %q", skKey.application)
	}

	// Re-marshal and parse again: must round trip.
	parsed, err := ParsePublicKey(key.Marshal())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !bytes.Equal(parsed.Marshal(), key.Marshal()) {
		t.Error("sk-ed25519 key did not round trip")
	}

	// Verify a valid signature with the user presence flag set.
	data, err := hex.DecodeString(string(skTestData))
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := hex.DecodeString(string(skTestSignature))
	if err != nil {
		t.Fatal(err)
	}
	var sig Signature
	sigBlob, _, ok := parseString(sigBytes)
	if !ok {
		t.Fatal("failed to parse signature blob")
	}
	parsedSig, trailing, ok := parseSignatureBody(sigBlob)
	if !ok || len(trailing) > 0 {
		t.Fatal("failed to parse signature body")
	}
	sig = *parsedSig
	if err := key.Verify(data, &sig); err != nil {
		t.Errorf("Verify: %v", err)
	}

	// A signature without the user presence flag must be rejected.
	noUP := sig
	noUP.Rest = []byte{0x00, 0x00, 0x00, 0x00, 0x00} // flags=0, counter=0
	verifyErr := key.Verify(data, &noUP)
	if verifyErr == nil {
		t.Error("Verify with missing user presence succeeded, expected error")
	}
	if verifyErr != errSKMissingUserPresence {
		t.Errorf("expected errSKMissingUserPresence, got %v", verifyErr)
	}

	// skKeyWithoutUP disables the check on a clone.
	cloned := skKeyWithoutUP(key)
	if err := cloned.Verify(data, &sig); err != nil {
		t.Errorf("Verify with UP on cloned key: %v", err)
	}
}

func TestNewSignerWithAlgos(t *testing.T) {
	restricted, err := NewSignerWithAlgorithms(testSigners["ed25519"].(AlgorithmSigner), []string{KeyAlgoED25519})
	if err != nil {
		t.Fatalf("NewSignerWithAlgorithms: %v", err)
	}
	if _, err := restricted.SignWithAlgorithm(rand.Reader, []byte("x"), KeyAlgoED25519); err != nil {
		t.Errorf("SignWithAlgorithm: %v", err)
	}
	if _, err := restricted.SignWithAlgorithm(rand.Reader, []byte("x"), KeyAlgoSKED25519); err == nil {
		t.Error("SignWithAlgorithm with unsupported algo succeeded, expected error")
	}
	if _, err := NewSignerWithAlgorithms(testSigners["ed25519"].(AlgorithmSigner), nil); err == nil {
		t.Error("NewSignerWithAlgorithms with empty list succeeded, expected error")
	}
}

func TestCryptoPublicKey(t *testing.T) {
	if _, ok := testPublicKeys["ed25519"].(CryptoPublicKey); !ok {
		t.Error("ed25519 public key does not implement CryptoPublicKey")
	}
	pub := testPublicKeys["ed25519"].(CryptoPublicKey).CryptoPublicKey()
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("unexpected crypto public key type %T", pub)
	}
}

func TestParseCertWithCertSignatureKey(t *testing.T) {
	// A certificate signed by a certificate is invalid and must be rejected
	// without recursing.
	key, _, _, _, err := ParseAuthorizedKey(MarshalAuthorizedKey(testPublicKeys["cert"]))
	if err != nil {
		t.Fatal(err)
	}
	cert := key.(*Certificate)
	cert.SignatureKey = testPublicKeys["cert"]
	cert.Signature = &Signature{
		Format: KeyAlgoED25519,
		Blob:   []byte{1, 2, 3},
	}
	if _, err := ParsePublicKey(cert.Marshal()); err == nil {
		t.Error("ParsePublicKey of cert with cert signature key succeeded, expected error")
	}
}
