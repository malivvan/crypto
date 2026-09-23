// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

// Message authentication support.
//
// The negotiated ciphers are AEAD, so no MAC is ever instantiated on the
// wire; only the key size of a configured MAC is used, for key derivation.

type macMode struct {
	keySize int
}

// macModes defines the supported MACs. MACs not included are not supported
// and will not be negotiated, even if explicitly configured.
var macModes = map[string]*macMode{
	HMACSHA512ETM: {keySize: 64},
	HMACSHA256ETM: {keySize: 32},
}
