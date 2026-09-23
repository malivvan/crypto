// Copyright 2025 malivvan

package algorithm

import (
	"crypto/cipher"
	"strconv"

	"github.com/malivvan/crypto/internal/eax"
	"github.com/malivvan/crypto/internal/ocb"
	"github.com/malivvan/crypto/pgp/errors"
)

// AEADMode defines the Authenticated Encryption with Associated Data mode of
// operation.
type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253).
// GCM is intentionally not supported.
const (
	AEADModeEAX = AEADMode(1)
	AEADModeOCB = AEADMode(2)
)

// TagLength returns the length in bytes of authentication tags.
func (mode AEADMode) TagLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 16
	default:
		return 0
	}
}

// NonceLength returns the length in bytes of nonces.
func (mode AEADMode) NonceLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 15
	default:
		return 0
	}
}

// New returns a fresh instance of the given mode
func (mode AEADMode) New(block cipher.Block) (alg cipher.AEAD, err error) {
	switch mode {
	case AEADModeEAX:
		alg, err = eax.NewEAX(block)
	case AEADModeOCB:
		alg, err = ocb.NewOCB(block)
	default:
		err = errors.UnsupportedError("unknown aead mode: " + strconv.Itoa(int(mode)))
	}
	return alg, err
}
