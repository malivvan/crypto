// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pbkdf2

// This is the Blowfish block cipher, folded into this package because the only
// consumer in the module is bcrypt_pbkdf(3) (KeyBcrypt below). It is kept
// package-private and exposes only the operations KeyBcrypt needs:
//
//   - newSaltedBlowfish key the cipher with bcrypt's salted EKS scheme;
//   - (*blowfishCipher).expandKey re-expand the key schedule with a fresh key;
//   - (*blowfishCipher).encrypt encrypt a single 8-byte block.
//
// Blowfish is a legacy cipher (8-byte blocks, sweet32) and must never be used
// for general-purpose encryption; it is retained solely for OpenBSD's
// bcrypt_pbkdf compatibility.
type blowfishCipher struct {
	p              [18]uint32
	s0, s1, s2, s3 [256]uint32
}

// init copies the startup P-array and S-boxes into the cipher's schedule.
func (c *blowfishCipher) init() {
	copy(c.p[:], p[:])
	copy(c.s0[:], s0[:])
	copy(c.s1[:], s1[:])
	copy(c.s2[:], s2[:])
	copy(c.s3[:], s3[:])
}

// getNextWord returns the next big-endian uint32 from b at pos, wrapping.
func getNextWord(b []byte, pos *int) uint32 {
	var w uint32
	j := *pos
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	*pos = j
	return w
}

// expandKey runs the Blowfish key schedule with key, overwriting the schedule
// in place. It is the equivalent of the (upstream) exported ExpandKey that
// bcrypt uses to fold a fresh key into an already-initialised cipher.
func (c *blowfishCipher) expandKey(key []byte) {
	j := 0
	for i := 0; i < 18; i++ {
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

// expandSaltedKey builds the schedule by folding the salt into the key
// expansion (bcrypt's EKS scheme). Upstream names this expandKeyWithSalt.
func expandSaltedKey(c *blowfishCipher, key, salt []byte) {
	c.init()
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getNextWord(key, &j)
	}

	j = 0
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	expand := func(s *[256]uint32) {
		for i := 0; i < 256; i += 2 {
			l ^= getNextWord(salt, &j)
			r ^= getNextWord(salt, &j)
			l, r = encryptBlock(l, r, c)
			s[i], s[i+1] = l, r
		}
	}
	expand(&c.s0)
	expand(&c.s1)
	expand(&c.s2)
	expand(&c.s3)
}

// newSaltedBlowfish returns a Blowfish cipher keyed and salted with bcrypt's
// EKS scheme, used by bcryptHash.
func newSaltedBlowfish(key, salt []byte) *blowfishCipher {
	c := &blowfishCipher{}
	expandSaltedKey(c, key, salt)
	return c
}

// encrypt encrypts a single 8-byte block, src, writing 8 bytes to dst. bcrypt
// encrypts in-place (dst may equal src).
func (c *blowfishCipher) encrypt(dst, src []byte) {
	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = encryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
}

// encryptBlock runs one full Blowfish encryption round (16 Feistel rounds) on
// the 64-bit value l:r and returns the result.
func encryptBlock(l, r uint32, c *blowfishCipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[0]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[1]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[2]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[3]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[4]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[5]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[6]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[7]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[8]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[9]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[10]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[11]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[12]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[13]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[14]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[15]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[16]
	xr ^= c.p[17]
	return xr, xl
}
