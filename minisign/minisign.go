// Copyright 2026 malivvan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package minisign implements the minisign signature format on top of the
// wallet's Ed25519 signing key.
//
// Minisign signatures are interoperable with the reference minisign tool:
// the wire formats for public keys and signatures (including the "untrusted
// comment:"/"trusted comment:" text encoding) are unchanged.
//
// The package deliberately does not generate or store standalone minisign
// keys. Signing reuses the wallet's OpenPGP Ed25519 signing key (the same
// key used for GPG detached signing, see Wallet.SigningKey), so a message
// signed here can be verified with the corresponding minisign public key and
// vice versa. Public keys are derived from the wallet key on the fly via
// PublicKeyFromEd25519.
package minisign

import (
	"bytes"
	"encoding/binary"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/malivvan/crypto/blake2b"
	"github.com/malivvan/crypto/ed25519"
)

const (
	// EdDSA refers to the Ed25519 signature scheme.
	//
	// Minisign uses this signature scheme to sign and
	// verify (non-hashed) messages.
	EdDSA uint16 = 0x6445

	// HashEdDSA refers to an Ed25519 signature scheme
	// with pre-hashed messages.
	//
	// Minisign uses this signature scheme to sign and
	// verify messages that don't fit into memory.
	HashEdDSA uint16 = 0x4445
)

// Reader is an io.Reader that reads a message while, at the same time,
// computing its digest.
//
// At any point, typically at the end of the message, Reader can sign the
// message digest with the wallet's Ed25519 signing key or try to verify the
// message with a public key and signature.
type Reader struct {
	message io.Reader
	hash    hash.Hash
}

// NewReader returns a new Reader that reads from r and computes a digest of
// the read data.
func NewReader(r io.Reader) *Reader {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	return &Reader{
		message: r,
		hash:    h,
	}
}

// Read reads from the underlying io.Reader as specified by the io.Reader
// interface.
func (r *Reader) Read(p []byte) (int, error) {
	n, err := r.message.Read(p)
	r.hash.Write(p[:n])
	return n, err
}

// Sign signs whatever has been read from the underlying io.Reader up to this
// point in time with the given wallet signing key.
//
// It behaves like SignWithComments but uses some generic comments.
func (r *Reader) Sign(privateKey *ed25519.PrivateKey) ([]byte, error) {
	var (
		trustedComment   = "timestamp:" + strconv.FormatInt(time.Now().Unix(), 10)
		untrustedComment = "signature from wallet signing key"
	)
	return r.SignWithComments(privateKey, trustedComment, untrustedComment)
}

// SignWithComments signs whatever has been read from the underlying
// io.Reader up to this point in time with the given wallet signing key.
//
// The trustedComment as well as the untrustedComment are embedded into the
// returned signature. The trustedComment is signed and will be checked when
// the signature is verified. The untrustedComment is not signed and must not
// be trusted.
//
// SignWithComments computes the digest as a snapshot. So, it is possible to
// create multiple signatures of different message prefixes by reading up to
// a certain byte, signing this message prefix, and then continue reading.
func (r *Reader) SignWithComments(privateKey *ed25519.PrivateKey, trustedComment, untrustedComment string) ([]byte, error) {
	const isHashed = true
	return sign(privateKey, r.hash.Sum(nil), trustedComment, untrustedComment, isHashed)
}

// Verify checks whether whatever has been read from the underlying
// io.Reader up to this point in time is authentic by verifying it with the
// given public key and signature.
//
// Verify computes the digest as a snapshot. Therefore, Verify can verify any
// signature produced by Sign or SignWithComments, including signatures of
// partial messages, given the correct public key and signature.
func (r *Reader) Verify(publicKey PublicKey, signature []byte) bool {
	const isHashed = true
	return verify(publicKey, r.hash.Sum(nil), signature, isHashed)
}

// Sign signs the given message with the wallet signing key.
//
// It behaves like SignWithComments with some generic comments.
func Sign(privateKey *ed25519.PrivateKey, message []byte) ([]byte, error) {
	var (
		trustedComment   = "timestamp:" + strconv.FormatInt(time.Now().Unix(), 10)
		untrustedComment = "signature from wallet signing key"
	)
	return SignWithComments(privateKey, message, trustedComment, untrustedComment)
}

// SignWithComments signs the given message with the wallet signing key.
//
// The trustedComment as well as the untrustedComment are embedded into the
// returned signature. The trustedComment is signed and will be checked when
// the signature is verified. The untrustedComment is not signed and must not
// be trusted.
func SignWithComments(privateKey *ed25519.PrivateKey, message []byte, trustedComment, untrustedComment string) ([]byte, error) {
	const isHashed = false
	return sign(privateKey, message, trustedComment, untrustedComment, isHashed)
}

// Verify checks whether message is authentic by verifying it with the given
// public key and signature. It returns true if and only if the signature
// verification is successful.
func Verify(publicKey PublicKey, message, signature []byte) bool {
	const isHashed = false
	return verify(publicKey, message, signature, isHashed)
}

// sign signs message with the wallet Ed25519 private key and returns the
// textual minisign signature encoding.
func sign(privateKey *ed25519.PrivateKey, message []byte, trustedComment, untrustedComment string, isHashed bool) ([]byte, error) {
	algorithm := EdDSA
	if isHashed {
		algorithm = HashEdDSA
	}

	msgSignature, err := ed25519.Sign(privateKey, message)
	if err != nil {
		return nil, err
	}
	commentSignature, err := ed25519.Sign(privateKey, append(msgSignature, []byte(trustedComment)...))
	if err != nil {
		return nil, err
	}

	signature := Signature{
		Algorithm: algorithm,
		KeyID:     keyIDFromPublicKey(privateKey.PublicKey.Point),

		TrustedComment:   trustedComment,
		UntrustedComment: untrustedComment,
	}
	copy(signature.Signature[:], msgSignature)
	copy(signature.CommentSignature[:], commentSignature)

	text, err := signature.MarshalText()
	if err != nil {
		return nil, err
	}
	return text, nil
}

func verify(publicKey PublicKey, message, signature []byte, isHashed bool) bool {
	var s Signature
	if err := s.UnmarshalText(signature); err != nil {
		return false
	}
	if s.KeyID != publicKey.ID() {
		return false
	}
	if s.Algorithm == HashEdDSA && !isHashed {
		h := blake2b.Sum512(message)
		message = h[:]
	}
	pub := &ed25519.PublicKey{Point: publicKey.bytes[:]}
	if !ed25519.Verify(pub, message, s.Signature[:]) {
		return false
	}
	globalMessage := append(s.Signature[:], []byte(s.TrustedComment)...)
	return ed25519.Verify(pub, globalMessage, s.CommentSignature[:])
}

// keyIDFromPublicKey returns the 64-bit minisign key ID of an Ed25519 public
// key point: the first eight bytes (little-endian) of its BLAKE2b-256 hash.
func keyIDFromPublicKey(point []byte) uint64 {
	sum := blake2b.Sum256(point)
	return binary.LittleEndian.Uint64(sum[:8])
}

// trimUntrustedComment returns text with a potential untrusted comment line.
func trimUntrustedComment(text []byte) []byte {
	s := bytes.SplitN(text, []byte{'\n'}, 2)
	if len(s) == 2 && strings.HasPrefix(string(s[0]), "untrusted comment: ") {
		return s[1]
	}
	return s[0]
}
