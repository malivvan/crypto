// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"testing"
)

func TestDefaultCiphersExist(t *testing.T) {
	for _, cipherAlgo := range supportedCiphers {
		if _, ok := cipherModes[cipherAlgo]; !ok {
			t.Errorf("supported cipher %q is not registered in cipherModes", cipherAlgo)
		}
	}
	for _, macAlgo := range supportedMACs {
		if _, ok := macModes[macAlgo]; !ok {
			t.Errorf("supported MAC %q is not registered in macModes", macAlgo)
		}
	}
}

// TestPacketCiphers tests the supported packet ciphers with random
// packets of various sizes.
func TestPacketCiphers(t *testing.T) {
	for cipher := range cipherModes {
		t.Run(cipher, func(t *testing.T) {
			kr := &kexResult{Hash: crypto.SHA256}
			algs := DirectionAlgorithms{Cipher: cipher}
			// The writer and reader sides of the transport have distinct
			// packetCipher instances.
			writer, err := newPacketCipher(direction{}, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher: %v", err)
			}
			reader, err := newPacketCipher(direction{}, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher: %v", err)
			}
			for i := 0; i < 100; i++ {
				size := 1 + i*7
				payload := make([]byte, size)
				if _, err := rand.Read(payload); err != nil {
					t.Fatal(err)
				}
				var buf bytes.Buffer
				if err := writer.writeCipherPacket(uint32(i), &buf, rand.Reader, payload); err != nil {
					t.Fatalf("writeCipherPacket: %v", err)
				}
				plain, err := reader.readCipherPacket(uint32(i), &buf)
				if err != nil {
					t.Fatalf("readCipherPacket: %v", err)
				}
				if !bytes.Equal(plain, payload) {
					t.Fatalf("round trip failed: got %d bytes, want %d", len(plain), len(payload))
				}
			}
		})
	}
}
