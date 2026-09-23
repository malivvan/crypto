// Package ecc implements a generic interface for ECDH and EdDSA.
package ecc

import (
	"io"
)

type Curve interface {
	GetCurveName() string
}

type EdDSACurve interface {
	Curve
	MarshalBytePoint(x []byte) []byte
	UnmarshalBytePoint([]byte) (x []byte)
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	MarshalSignature(sig []byte) (r, s []byte)
	UnmarshalSignature(r, s []byte) (sig []byte)
	GenerateEdDSA(rand io.Reader) (pub, priv []byte, err error)
	GenerateEdDSAFromSeed(seed []byte) (pub, priv []byte, err error)
	Sign(publicKey, privateKey, message []byte) (sig []byte, err error)
	Verify(publicKey, message, sig []byte) bool
	ValidateEdDSA(publicKey, privateKey []byte) (err error)
}
type ECDHCurve interface {
	Curve
	MarshalBytePoint([]byte) (encoded []byte)
	UnmarshalBytePoint(encoded []byte) []byte
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	GenerateECDH(rand io.Reader) (point []byte, secret []byte, err error)
	Encaps(rand io.Reader, point []byte) (ephemeral, sharedSecret []byte, err error)
	Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error)
	ValidateECDH(public []byte, secret []byte) error
}
