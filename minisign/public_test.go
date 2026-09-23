// Copyright 2026 malivvan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package minisign

import (
	"testing"

	"github.com/malivvan/crypto/ed25519"
)

func TestPublicKeyMarshalUnmarshalRoundtrip(t *testing.T) {
	p := PublicKey{
		id:    0xe7620f1842b4e81f,
		bytes: [32]byte{121, 165, 97, 231, 14, 224, 140, 211, 231, 84, 198, 62, 155, 214, 185, 195, 82, 10, 29, 66, 4, 205, 16, 77, 162, 231, 239, 118, 59, 24, 83, 183},
	}

	text, err := p.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var got PublicKey
	if err := got.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if !p.Equal(got) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPublicKeyUnmarshalReferenceVector(t *testing.T) {
	// Decode a key produced by the reference minisign tool.
	ref := "untrusted comment: minisign public key C373193807678450\n" +
		"RWRQhGcHOBlzw4CoKyugkk4ioDfoxlXxC9LBx+VNhJ3w9w+cAxgvPsuo"
	var p PublicKey
	if err := p.UnmarshalText([]byte(ref)); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if p.ID() != 0xc373193807678450 {
		t.Fatalf("unexpected key ID %#x", p.ID())
	}

	// MarshalText writes a colon after "public key"; the key bytes are the
	// same. Re-parsing our own output must decode the same key ID + bytes.
	text, err := p.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var round PublicKey
	if err := round.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText(own): %v", err)
	}
	if !p.Equal(round) {
		t.Fatal("own re-encode did not round-trip the key")
	}
}

func TestPublicKeyFromEd25519(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := ed25519.GenerateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed: %v", err)
	}

	p := PublicKeyFromEd25519(&key.PublicKey)
	if got := p.Bytes(); len(got) != ed25519.PublicKeySize {
		t.Fatalf("Bytes length %d", len(got))
	}
	for i := range p.Bytes() {
		if p.Bytes()[i] != key.PublicKey.Point[i] {
			t.Fatal("public key does not match source point")
		}
	}
	// ID must equal the current derivation (blake2b-256 of the point).
	wantID := keyIDFromPublicKey(key.PublicKey.Point)
	if p.ID() != wantID {
		t.Fatalf("ID mismatch: got %#x want %#x", p.ID(), wantID)
	}

	// Round-trip through its text form.
	text, err := p.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var dec PublicKey
	if err := dec.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if !p.Equal(dec) {
		t.Fatal("text round-trip mismatch")
	}
}

func TestPublicKeyRejectsMalformed(t *testing.T) {
	var p PublicKey
	if err := p.UnmarshalText([]byte("not base64 public key")); err == nil {
		t.Fatal("UnmarshalText accepted garbage")
	}
}
