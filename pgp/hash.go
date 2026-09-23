// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pgp

import (
	"crypto"

	"github.com/malivvan/crypto/internal/algorithm"
)

// HashIdToHash returns a crypto.Hash which corresponds to the given OpenPGP
// hash id.
func HashIdToHash(id byte) (h crypto.Hash, ok bool) {
	return algorithm.HashIdToHash(id)
}

// HashIdToString returns the name of the hash function corresponding to the
// given OpenPGP hash id.
func HashIdToString(id byte) (name string, ok bool) {
	return algorithm.HashIdToString(id)
}

// HashToHashId returns an OpenPGP hash id which corresponds the given Hash.
func HashToHashId(h crypto.Hash) (id byte, ok bool) {
	return algorithm.HashToHashId(h)
}
