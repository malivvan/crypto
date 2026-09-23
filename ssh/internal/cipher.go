// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/malivvan/crypto/chacha20"
	"github.com/malivvan/crypto/poly1305"
)

const (
	packetSizeMultiple = 16 // TODO(huin) this should be determined by the cipher.

	// RFC 4253 section 6.1 defines a minimum packet size of 32768 that implementations
	// MUST be able to process (plus a few more kilobytes for padding and mac). The RFC
	// indicates implementations SHOULD be able to handle larger packet sizes, but then
	// waffles on about reasonable limits.
	//
	// OpenSSH caps their maxPacket at 256kB so we choose to do
	// the same. maxPacket is also used to ensure that uint32
	// length fields do not overflow, so it should remain well
	// below 4G.
	maxPacket = 256 * 1024
)

// noneCipher implements cipher.Stream and provides no encryption. It is used
// by the transport before the first key-exchange.
type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

type cipherMode struct {
	keySize int
	ivSize  int
	create  func(key, iv []byte, macKey []byte, algs DirectionAlgorithms) (packetCipher, error)
}

// cipherModes documents properties of supported ciphers. Ciphers not included
// are not supported and will not be negotiated, even if explicitly configured.
var cipherModes = map[string]*cipherMode{
	CipherAES256GCM:        {32, 12, newGCMCipher},
	CipherChaCha20Poly1305: {64, 0, newChaCha20Cipher},
}

// prefixLen is the length of the packet prefix that contains the packet length
// and number of padding bytes.
const prefixLen = 5

// streamPacketCipher is a packetCipher using a stream cipher. It is also used
// before the first key exchange, when no cipher or MAC is in effect.
type streamPacketCipher struct {
	mac    hash.Hash
	cipher cipher.Stream
	etm    bool

	// The following members are to avoid per-packet allocations.
	prefix      [prefixLen]byte
	seqNumBytes [4]byte
	padding     [2 * packetSizeMultiple]byte
	packetData  []byte
	macResult   []byte
}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (s *streamPacketCipher) readCipherPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	if _, err := io.ReadFull(r, s.prefix[:]); err != nil {
		return nil, err
	}

	var encryptedPaddingLength [1]byte
	if s.mac != nil && s.etm {
		copy(encryptedPaddingLength[:], s.prefix[4:5])
		s.cipher.XORKeyStream(s.prefix[4:5], s.prefix[4:5])
	} else {
		s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	}

	length := binary.BigEndian.Uint32(s.prefix[0:4])
	paddingLength := uint32(s.prefix[4])

	var macSize uint32
	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		if s.etm {
			s.mac.Write(s.prefix[:4])
			s.mac.Write(encryptedPaddingLength[:])
		} else {
			s.mac.Write(s.prefix[:])
		}
		macSize = uint32(s.mac.Size())
	}

	if length <= paddingLength+1 {
		return nil, errors.New("ssh: invalid packet length, packet too small")
	}

	if length > maxPacket {
		return nil, errors.New("ssh: invalid packet length, packet too large")
	}

	// the maxPacket check above ensures that length-1+macSize
	// does not overflow.
	if uint32(cap(s.packetData)) < length-1+macSize {
		s.packetData = make([]byte, length-1+macSize)
	} else {
		s.packetData = s.packetData[:length-1+macSize]
	}

	if _, err := io.ReadFull(r, s.packetData); err != nil {
		return nil, err
	}
	mac := s.packetData[length-1:]
	data := s.packetData[:length-1]

	if s.mac != nil && s.etm {
		s.mac.Write(data)
	}

	s.cipher.XORKeyStream(data, data)

	if s.mac != nil {
		if !s.etm {
			s.mac.Write(data)
		}
		s.macResult = s.mac.Sum(s.macResult[:0])
		if subtle.ConstantTimeCompare(s.macResult, mac) != 1 {
			return nil, errors.New("ssh: MAC failure")
		}
	}

	return s.packetData[:length-paddingLength-1], nil
}

// writeCipherPacket encrypts and sends a packet of data to the writer argument
func (s *streamPacketCipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	if len(packet) > maxPacket {
		return errors.New("ssh: packet too large")
	}

	aadlen := 0
	if s.mac != nil && s.etm {
		// packet length is not encrypted for EtM modes
		aadlen = 4
	}

	paddingLength := packetSizeMultiple - (prefixLen+len(packet)-aadlen)%packetSizeMultiple
	if paddingLength < 4 {
		paddingLength += packetSizeMultiple
	}

	length := len(packet) + 1 + paddingLength
	binary.BigEndian.PutUint32(s.prefix[:], uint32(length))
	s.prefix[4] = byte(paddingLength)
	padding := s.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])

		if s.etm {
			// For EtM algorithms, the packet length must stay unencrypted,
			// but the following data (padding length) must be encrypted
			s.cipher.XORKeyStream(s.prefix[4:5], s.prefix[4:5])
		}

		s.mac.Write(s.prefix[:])

		if !s.etm {
			// For non-EtM algorithms, the algorithm is applied on unencrypted data
			s.mac.Write(packet)
			s.mac.Write(padding)
		}
	}

	if !(s.mac != nil && s.etm) {
		// For EtM algorithms, the padding length has already been encrypted
		// and the packet length must remain unencrypted
		s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	}

	s.cipher.XORKeyStream(packet, packet)
	s.cipher.XORKeyStream(padding, padding)

	if s.mac != nil && s.etm {
		// For EtM algorithms, packet and padding must be encrypted
		s.mac.Write(packet)
		s.mac.Write(padding)
	}

	if _, err := w.Write(s.prefix[:]); err != nil {
		return err
	}
	if _, err := w.Write(packet); err != nil {
		return err
	}
	if _, err := w.Write(padding); err != nil {
		return err
	}

	if s.mac != nil {
		s.macResult = s.mac.Sum(s.macResult[:0])
		if _, err := w.Write(s.macResult); err != nil {
			return err
		}
	}

	return nil
}

type gcmCipher struct {
	aead   cipher.AEAD
	prefix [4]byte
	iv     []byte
	buf    []byte
}

func newGCMCipher(key, iv, unusedMacKey []byte, unusedAlgs DirectionAlgorithms) (packetCipher, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return &gcmCipher{
		aead: aead,
		iv:   iv,
	}, nil
}

const gcmTagSize = 16

func (c *gcmCipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	// Pad out to multiple of 16 bytes. This is different from the
	// stream cipher because that encrypts the length too.
	padding := byte(packetSizeMultiple - (1+len(packet))%packetSizeMultiple)
	if padding < 4 {
		padding += packetSizeMultiple
	}

	length := uint32(len(packet) + int(padding) + 1)
	binary.BigEndian.PutUint32(c.prefix[:], length)
	if _, err := w.Write(c.prefix[:]); err != nil {
		return err
	}

	if cap(c.buf) < int(length) {
		c.buf = make([]byte, length)
	} else {
		c.buf = c.buf[:length]
	}

	c.buf[0] = padding
	copy(c.buf[1:], packet)
	if _, err := io.ReadFull(rand, c.buf[1+len(packet):]); err != nil {
		return err
	}
	c.buf = c.aead.Seal(c.buf[:0], c.iv, c.buf, c.prefix[:])
	if _, err := w.Write(c.buf); err != nil {
		return err
	}
	c.incIV()

	return nil
}

func (c *gcmCipher) incIV() {
	for i := 4 + 7; i >= 4; i-- {
		c.iv[i]++
		if c.iv[i] != 0 {
			break
		}
	}
}

func (c *gcmCipher) readCipherPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	if _, err := io.ReadFull(r, c.prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(c.prefix[:])
	if length > maxPacket {
		return nil, errors.New("ssh: max packet length exceeded")
	}

	if cap(c.buf) < int(length+gcmTagSize) {
		c.buf = make([]byte, length+gcmTagSize)
	} else {
		c.buf = c.buf[:length+gcmTagSize]
	}

	if _, err := io.ReadFull(r, c.buf); err != nil {
		return nil, err
	}

	plain, err := c.aead.Open(c.buf[:0], c.iv, c.buf, c.prefix[:])
	if err != nil {
		return nil, err
	}
	c.incIV()

	if len(plain) == 0 {
		return nil, errors.New("ssh: empty packet")
	}

	padding := plain[0]
	if padding < 4 {
		// padding is a byte, so it automatically satisfies
		// the maximum size, which is 255.
		return nil, fmt.Errorf("ssh: illegal padding %d", padding)
	}

	if int(padding)+1 >= len(plain) {
		return nil, fmt.Errorf("ssh: padding %d too large", padding)
	}
	plain = plain[1 : length-uint32(padding)]
	return plain, nil
}

// chacha20Poly1305Cipher implements the chacha20-poly1305@openssh.com
// AEAD, which is described here:
//
//	https://tools.ietf.org/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00
//
// the methods here also implement padding, which RFC 4253 Section 6
// also requires of stream ciphers.
type chacha20Poly1305Cipher struct {
	lengthKey  [32]byte
	contentKey [32]byte
	buf        []byte
}

func newChaCha20Cipher(key, unusedIV, unusedMACKey []byte, unusedAlgs DirectionAlgorithms) (packetCipher, error) {
	if len(key) != 64 {
		panic(len(key))
	}

	c := &chacha20Poly1305Cipher{
		buf: make([]byte, 256),
	}

	copy(c.contentKey[:], key[:32])
	copy(c.lengthKey[:], key[32:])
	return c, nil
}

func (c *chacha20Poly1305Cipher) readCipherPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[8:], seqNum)
	s, err := chacha20.NewUnauthenticatedCipher(c.contentKey[:], nonce)
	if err != nil {
		return nil, err
	}
	var polyKey, discardBuf [32]byte
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.XORKeyStream(discardBuf[:], discardBuf[:]) // skip the next 32 bytes

	encryptedLength := c.buf[:4]
	if _, err := io.ReadFull(r, encryptedLength); err != nil {
		return nil, err
	}

	var lenBytes [4]byte
	ls, err := chacha20.NewUnauthenticatedCipher(c.lengthKey[:], nonce)
	if err != nil {
		return nil, err
	}
	ls.XORKeyStream(lenBytes[:], encryptedLength)

	length := binary.BigEndian.Uint32(lenBytes[:])
	if length > maxPacket {
		return nil, errors.New("ssh: invalid packet length, packet too large")
	}

	contentEnd := 4 + length
	packetEnd := contentEnd + poly1305.TagSize
	if uint32(cap(c.buf)) < packetEnd {
		c.buf = make([]byte, packetEnd)
		copy(c.buf[:], encryptedLength)
	} else {
		c.buf = c.buf[:packetEnd]
	}

	if _, err := io.ReadFull(r, c.buf[4:packetEnd]); err != nil {
		return nil, err
	}

	var mac [poly1305.TagSize]byte
	copy(mac[:], c.buf[contentEnd:packetEnd])
	if !poly1305.Verify(&mac, c.buf[:contentEnd], &polyKey) {
		return nil, errors.New("ssh: MAC failure")
	}

	plain := c.buf[4:contentEnd]
	s.XORKeyStream(plain, plain)

	if len(plain) == 0 {
		return nil, errors.New("ssh: empty packet")
	}

	padding := plain[0]
	if padding < 4 {
		// padding is a byte, so it automatically satisfies
		// the maximum size, which is 255.
		return nil, fmt.Errorf("ssh: illegal padding %d", padding)
	}

	if int(padding)+1 >= len(plain) {
		return nil, fmt.Errorf("ssh: padding %d too large", padding)
	}

	plain = plain[1 : len(plain)-int(padding)]

	return plain, nil
}

func (c *chacha20Poly1305Cipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, payload []byte) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[8:], seqNum)
	s, err := chacha20.NewUnauthenticatedCipher(c.contentKey[:], nonce)
	if err != nil {
		return err
	}
	var polyKey, discardBuf [32]byte
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.XORKeyStream(discardBuf[:], discardBuf[:]) // skip the next 32 bytes

	// There is no blocksize, so fall back to multiple of 8 byte
	// padding, as described in RFC 4253, Sec 6.
	const packetSizeMultiple = 8

	padding := packetSizeMultiple - (1+len(payload))%packetSizeMultiple
	if padding < 4 {
		padding += packetSizeMultiple
	}

	// size (4 bytes), padding (1), payload, padding, tag.
	totalLength := 4 + 1 + len(payload) + padding + poly1305.TagSize
	if cap(c.buf) < totalLength {
		c.buf = make([]byte, totalLength)
	} else {
		c.buf = c.buf[:totalLength]
	}

	binary.BigEndian.PutUint32(c.buf, uint32(1+len(payload)+padding))
	ls, err := chacha20.NewUnauthenticatedCipher(c.lengthKey[:], nonce)
	if err != nil {
		return err
	}
	ls.XORKeyStream(c.buf, c.buf[:4])
	c.buf[4] = byte(padding)
	copy(c.buf[5:], payload)
	packetEnd := 5 + len(payload) + padding
	if _, err := io.ReadFull(rand, c.buf[5+len(payload):packetEnd]); err != nil {
		return err
	}

	s.XORKeyStream(c.buf[4:], c.buf[4:packetEnd])

	var mac [poly1305.TagSize]byte
	poly1305.Sum(&mac, c.buf[:packetEnd], &polyKey)

	copy(c.buf[packetEnd:], mac[:])

	if _, err := w.Write(c.buf); err != nil {
		return err
	}
	return nil
}
