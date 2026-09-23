// Copyright 2026 malivvan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package minisign

import "testing"

// testSignature returns a Signature with all fields populated, used by the
// marshal tests.
func testSignature() Signature {
	return Signature{
		Algorithm:        EdDSA,
		KeyID:            0xe7620f1842b4e81f,
		UntrustedComment: "test untrusted comment",
		TrustedComment:   "test trusted comment",
		Signature:        [64]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		CommentSignature: [64]byte{10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
}

func TestSignatureMarshalUnmarshalRoundtrip(t *testing.T) {
	s := testSignature()
	text, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var got Signature
	if err := got.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if !got.Equal(s) {
		t.Fatalf("roundtrip mismatch:\n got %#v\nwant %#v", got, s)
	}
}

func TestSignatureUnmarshalKnownEncoding(t *testing.T) {
	// The on-disk reference signature produced by the reference minisign tool
	// must decode cleanly to the expected human-readable pieces (see
	// minisign_test.go's TestInteropReferenceVector which completes the
	// verification).
	sig, err := SignatureFromFile("./testdata/message.txt.minisig")
	if err != nil {
		t.Fatalf("SignatureFromFile: %v", err)
	}
	if sig.Algorithm != HashEdDSA && sig.Algorithm != EdDSA {
		t.Fatalf("unexpected algorithm %d", sig.Algorithm)
	}
	if sig.UntrustedComment != "signature from minisign secret key" {
		t.Fatalf("unexpected untrusted comment %q", sig.UntrustedComment)
	}
	if sig.TrustedComment != "timestamp:1614549543\tfile:message.txt" {
		t.Fatalf("unexpected trusted comment %q", sig.TrustedComment)
	}
}

func TestSignatureRejectsInvalidAlgorithm(t *testing.T) {
	bad := testSignature()
	bad.Algorithm = 0x9999
	if _, err := bad.MarshalText(); err == nil {
		t.Fatal("MarshalText accepted an invalid algorithm")
	}
}

func TestSignatureRejectsMalformed(t *testing.T) {
	var sig Signature
	for _, in := range [][]byte{
		nil,
		[]byte("garbage without comment lines"),
		[]byte("untrusted comment: x\na\nb\nc:d"), // bad sig base64 length
	} {
		if err := sig.UnmarshalText(in); err == nil {
			t.Fatalf("UnmarshalText accepted %q", in)
		}
	}
}
