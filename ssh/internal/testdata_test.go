// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
)

// testKeys holds the signers and public keys shared across the test suite.
// All plain key fixtures are ed25519 keys; "cert" is an ed25519 host
// certificate signer, since this package only negotiates ed25519 host key
// certificates.
var (
	testPrivateKeys map[string]interface{}
	testSigners     map[string]Signer
	testPublicKeys  map[string]PublicKey
)

func init() {
	testPrivateKeys = make(map[string]interface{})
	testSigners = make(map[string]Signer)
	testPublicKeys = make(map[string]PublicKey)

	for _, name := range []string{"rsa", "ecdsa", "dsa", "ed25519"} {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		signer, err := NewSignerFromKey(priv)
		if err != nil {
			panic(err)
		}
		testPrivateKeys[name] = priv
		testSigners[name] = signer
		testPublicKeys[name] = signer.PublicKey()
	}

	// Create a host certificate signed by the ed25519 key for use as a host
	// key fixture.
	testCert := &Certificate{
		Nonce:           []byte{},
		ValidPrincipals: []string{"gopher1", "gopher2"},
		ValidAfter:      0,
		ValidBefore:     CertTimeInfinity,
		Reserved:        []byte{},
		Key:             testPublicKeys["ed25519"],
		SignatureKey:    testPublicKeys["ed25519"],
		Permissions: Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}
	if err := testCert.SignCert(rand.Reader, testSigners["ed25519"]); err != nil {
		panic(err)
	}
	certSigner, err := NewCertSigner(testCert, testSigners["ed25519"])
	if err != nil {
		panic(err)
	}
	testSigners["cert"] = certSigner
	testPublicKeys["cert"] = certSigner.PublicKey()

	// Legacy fixture names used by the client auth tests.
	testSigners["keyA"] = testSigners["rsa"]
	testPublicKeys["keyA"] = testPublicKeys["rsa"]
	testSigners["keyB"] = testSigners["ecdsa"]
	testPublicKeys["keyB"] = testPublicKeys["ecdsa"]
}
