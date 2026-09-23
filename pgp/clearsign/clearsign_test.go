// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clearsign

import (
	"bytes"
	"crypto"
	"testing"
	"time"

	wallet "github.com/malivvan/crypto/pgp"
	"github.com/malivvan/crypto/pgp/packet"
)

func newEntity(t *testing.T, v6 bool) *wallet.Entity {
	t.Helper()
	config := &packet.Config{
		DefaultHash: crypto.SHA512,
		V6Keys:      v6,
	}
	e, err := wallet.NewEntity("Clearsign Test", "", "clearsign@example.com", config)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}

func TestClearsignRoundtrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v4", true: "v6"}[v6], func(t *testing.T) {
			config := &packet.Config{DefaultHash: crypto.SHA512, V6Keys: v6}
			e := newEntity(t, v6)
			msg := []byte("Hello, clearsigned world!\nSecond line.\n")

			var buf bytes.Buffer
			w, err := Encode(&buf, e.PrivateKey, config)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if _, err := w.Write(msg); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			block, rest := Decode(buf.Bytes())
			if block == nil {
				t.Fatal("Decode returned nil")
			}
			if len(rest) != 0 {
				t.Fatalf("unexpected rest: %q", rest)
			}
			// Cleartext is normalized to CRLF line endings.
			want := bytes.ReplaceAll(msg, []byte("\n"), []byte("\r\n"))
			if !bytes.Equal(block.Bytes, want) {
				t.Fatalf("cleartext mismatch: %q != %q", block.Bytes, want)
			}

			signer, err := block.VerifySignature(wallet.EntityList{e}, config)
			if err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
			if signer == nil || signer.PrimaryKey.KeyId != e.PrimaryKey.KeyId {
				t.Fatal("unexpected signer")
			}

			// Tampering must fail.
			tampered := append([]byte(nil), buf.Bytes()...)
			idx := bytes.Index(tampered, []byte("clearsigned world"))
			if idx == -1 {
				t.Fatal("marker not found")
			}
			tampered[idx] = 'X'
			block2, _ := Decode(tampered)
			if block2 == nil {
				t.Fatal("Decode of tampered message returned nil")
			}
			if _, err := block2.VerifySignature(wallet.EntityList{e}, config); err == nil {
				t.Fatal("tampered signature verified")
			}
		})
	}
}

func TestDecodeWithHashHeaders(t *testing.T) {
	// SHA1 headers from legacy messages are tolerated; unknown ones are not.
	valid := []byte("\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA1\n\nHello\n-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n")
	if b, _ := Decode(valid); b == nil {
		t.Fatal("legacy SHA1 hash header should be accepted")
	}
	invalid := []byte("\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: MD5\n\nHello\n-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n")
	if b, _ := Decode(invalid); b != nil {
		t.Fatal("MD5 hash header should be rejected")
	}
}

func TestDashEscaping(t *testing.T) {
	config := &packet.Config{DefaultHash: crypto.SHA512}
	e := newEntity(t, false)
	msg := []byte("- leading dash\nmiddle\n- another\n")

	var buf bytes.Buffer
	w, err := Encode(&buf, e.PrivateKey, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	block, _ := Decode(buf.Bytes())
	if block == nil {
		t.Fatal("Decode returned nil")
	}
	want := bytes.ReplaceAll(msg, []byte("\n"), []byte("\r\n"))
	if !bytes.Equal(block.Bytes, want) {
		t.Fatalf("dash escaping roundtrip mismatch: %q != %q", block.Bytes, want)
	}
	if _, err := block.VerifySignature(wallet.EntityList{e}, config); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestEncodeRejectsEncryptedKey(t *testing.T) {
	config := &packet.Config{DefaultHash: crypto.SHA512}
	e := newEntity(t, false)
	if err := e.EncryptPrivateKeys([]byte("pass"), config); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Encode(&buf, e.PrivateKey, config); err == nil {
		t.Fatal("Encode accepted an encrypted key")
	}
}

var _ = time.Now
