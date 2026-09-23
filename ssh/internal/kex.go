// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"crypto"
	"errors"
	"io"
	"math/big"

	"github.com/malivvan/crypto/x25519"
)

// kexResult captures the outcome of a key exchange.
type kexResult struct {
	// Session hash. See also RFC 4253, section 8.
	H []byte

	// Shared secret. See also RFC 4253, section 8.
	K []byte

	// Host key as hashed into H.
	HostKey []byte

	// Signature of H.
	Signature []byte

	// A cryptographic hash function that matches the security
	// level of the key exchange algorithm. It is used for
	// calculating H, and for deriving keys from H and K.
	Hash crypto.Hash

	// The session ID, which is the first H computed. This is used
	// to derive key material inside the transport.
	SessionID []byte
}

// handshakeMagics contains data that is always included in the
// session hash.
type handshakeMagics struct {
	clientVersion, serverVersion []byte
	clientKexInit, serverKexInit []byte
}

func (m *handshakeMagics) write(w io.Writer) {
	writeString(w, m.clientVersion)
	writeString(w, m.serverVersion)
	writeString(w, m.clientKexInit)
	writeString(w, m.serverKexInit)
}

// kexAlgorithm abstracts different key exchange algorithms.
type kexAlgorithm interface {
	// Server runs server-side key agreement, signing the result
	// with a hostkey. algo is the negotiated algorithm, and may
	// be a certificate type.
	Server(p packetConn, rand io.Reader, magics *handshakeMagics, s AlgorithmSigner, algo string) (*kexResult, error)

	// Client runs the client-side key agreement. Caller is
	// responsible for verifying the host key signature.
	Client(p packetConn, rand io.Reader, magics *handshakeMagics) (*kexResult, error)
}

// kexAlgoMap defines the supported KEXs. KEXs not included are not supported
// and will not be negotiated, even if explicitly configured.
var kexAlgoMap = map[string]kexAlgorithm{
	KeyExchangeMLKEM768X25519: &mlkem768WithCurve25519sha256{},
	KeyExchangeCurve25519:     &curve25519sha256{},
}

// curve25519sha256 implements the curve25519-sha256 (formerly known as
// curve25519-sha256@libssh.org) key exchange method, as described in RFC 8731.
type curve25519sha256 struct{}

type curve25519KeyPair struct {
	priv [32]byte
	pub  [32]byte
}

func (kp *curve25519KeyPair) generate(rand io.Reader) error {
	if _, err := io.ReadFull(rand, kp.priv[:]); err != nil {
		return err
	}
	x25519.KeyGen((*x25519.Key)(&kp.pub), (*x25519.Key)(&kp.priv))
	return nil
}

func (kex *curve25519sha256) Client(c packetConn, rand io.Reader, magics *handshakeMagics) (*kexResult, error) {
	var kp curve25519KeyPair
	if err := kp.generate(rand); err != nil {
		return nil, err
	}
	if err := c.writePacket(Marshal(&kexECDHInitMsg{kp.pub[:]})); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var reply kexECDHReplyMsg
	if err = Unmarshal(packet, &reply); err != nil {
		return nil, err
	}
	if len(reply.EphemeralPubKey) != 32 {
		return nil, errors.New("ssh: peer's curve25519 public value has wrong length")
	}

	var peerPub x25519.Key
	copy(peerPub[:], reply.EphemeralPubKey)
	var secret x25519.Key
	if !x25519.Shared(&secret, (*x25519.Key)(&kp.priv), &peerPub) {
		return nil, errors.New("ssh: peer's curve25519 public value is not valid")
	}

	h := crypto.SHA256.New()
	magics.write(h)
	writeString(h, reply.HostKey)
	writeString(h, kp.pub[:])
	writeString(h, reply.EphemeralPubKey)

	ki := new(big.Int).SetBytes(secret[:])
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)
	h.Write(K)

	return &kexResult{
		H:         h.Sum(nil),
		K:         K,
		HostKey:   reply.HostKey,
		Signature: reply.Signature,
		Hash:      crypto.SHA256,
	}, nil
}

func (kex *curve25519sha256) Server(c packetConn, rand io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string) (result *kexResult, err error) {
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexInit kexECDHInitMsg
	if err = Unmarshal(packet, &kexInit); err != nil {
		return
	}

	if len(kexInit.ClientPubKey) != 32 {
		return nil, errors.New("ssh: peer's curve25519 public value has wrong length")
	}

	var kp curve25519KeyPair
	if err := kp.generate(rand); err != nil {
		return nil, err
	}

	var peerPub x25519.Key
	copy(peerPub[:], kexInit.ClientPubKey)
	var secret x25519.Key
	if !x25519.Shared(&secret, (*x25519.Key)(&kp.priv), &peerPub) {
		return nil, errors.New("ssh: peer's curve25519 public value is not valid")
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	h := crypto.SHA256.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	writeString(h, kexInit.ClientPubKey)
	writeString(h, kp.pub[:])

	ki := new(big.Int).SetBytes(secret[:])
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)
	h.Write(K)

	H := h.Sum(nil)

	sig, err := signAndMarshal(priv, rand, H, algo)
	if err != nil {
		return nil, err
	}

	reply := kexECDHReplyMsg{
		EphemeralPubKey: kp.pub[:],
		HostKey:         hostKeyBytes,
		Signature:       sig,
	}
	if err := c.writePacket(Marshal(&reply)); err != nil {
		return nil, err
	}
	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      crypto.SHA256,
	}, nil
}
