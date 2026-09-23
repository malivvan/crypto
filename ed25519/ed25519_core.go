package ed25519

import (
	"bytes"
	"crypto/sha512"
	"io"
	"strconv"
)

// paramB is the size of keys in bytes.
const paramB = 256 / 8

// privateKeySize is the size of the RFC 8032 private key representation
// (seed || public key) used for signing.
const privateKeySize = SeedSize + PublicKeySize

func clamp(k []byte) {
	k[0] &= 248
	k[paramB-1] = (k[paramB-1] & 127) | 64
}

// privateKeyFromSeed derives the RFC 8032 private key (seed || public key)
// from the given 32-byte seed. It panics if len(seed) != SeedSize.
func privateKeyFromSeed(seed []byte) []byte {
	privateKey := make([]byte, privateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}
	var P pointR1
	k := sha512.Sum512(seed)
	clamp(k[:])
	reduceModOrder(k[:paramB], false)
	P.fixedMult(k[:paramB])
	copy(privateKey[:SeedSize], seed)
	_ = P.ToBytes(privateKey[SeedSize:])
}

func signAll(signature []byte, privateKey, message, ctx []byte, preHash bool) {
	if l := len(privateKey); l != privateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	H := sha512.New()
	var PHM []byte

	if preHash {
		_, _ = H.Write(message)
		PHM = H.Sum(nil)
		H.Reset()
	} else {
		PHM = message
	}

	// 1.  Hash the 32-byte private key using SHA-512.
	_, _ = H.Write(privateKey[:SeedSize])
	h := H.Sum(nil)
	clamp(h[:])
	prefix, s := h[paramB:], h[:paramB]

	// 2.  Compute SHA-512(dom2(F, C) || prefix || PH(M))
	H.Reset()

	writeDom(H, ctx, preHash)

	_, _ = H.Write(prefix)
	_, _ = H.Write(PHM)
	r := H.Sum(nil)
	reduceModOrder(r[:], true)

	// 3.  Compute the point [r]B.
	var P pointR1
	P.fixedMult(r[:paramB])
	R := (&[paramB]byte{})[:]
	if err := P.ToBytes(R); err != nil {
		panic(err)
	}

	// 4.  Compute SHA512(dom2(F, C) || R || A || PH(M)).
	H.Reset()

	writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(privateKey[SeedSize:])
	_, _ = H.Write(PHM)
	hRAM := H.Sum(nil)

	reduceModOrder(hRAM[:], true)

	// 5.  Compute S = (r + k * s) mod order.
	S := (&[paramB]byte{})[:]
	calculateS(S, r[:paramB], hRAM[:paramB], s)

	// 6.  The signature is the concatenation of R and S.
	copy(signature[:paramB], R[:])
	copy(signature[paramB:], S[:])
}

func verify(public, message, signature, ctx []byte, preHash bool) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}

	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}

	H := sha512.New()
	var PHM []byte

	if preHash {
		_, _ = H.Write(message)
		PHM = H.Sum(nil)
		H.Reset()
	} else {
		PHM = message
	}

	R := signature[:paramB]

	writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(public)
	_, _ = H.Write(PHM)
	hRAM := H.Sum(nil)
	reduceModOrder(hRAM[:], true)

	var Q pointR1
	encR := (&[paramB]byte{})[:]
	P.neg()
	Q.doubleMult(&P, signature[paramB:], hRAM[:paramB])
	_ = Q.ToBytes(encR)
	return bytes.Equal(R, encR)
}

// isLessThanOrder returns true if 0 <= x < order.
func isLessThanOrder(x []byte) bool {
	i := len(order) - 1
	for i > 0 && x[i] == order[i] {
		i--
	}
	return x[i] < order[i]
}

func writeDom(h io.Writer, ctx []byte, preHash bool) {
	dom2 := "SigEd25519 no Ed25519 collisions"

	if len(ctx) > 0 {
		_, _ = h.Write([]byte(dom2))
		if preHash {
			_, _ = h.Write([]byte{byte(0x01), byte(len(ctx))})
		} else {
			_, _ = h.Write([]byte{byte(0x00), byte(len(ctx))})
		}
		_, _ = h.Write(ctx)
	} else if preHash {
		_, _ = h.Write([]byte(dom2))
		_, _ = h.Write([]byte{0x01, 0x00})
	}
}
