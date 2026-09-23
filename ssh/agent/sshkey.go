package agent

import (
	"github.com/malivvan/crypto/ed25519"
)

// pubBlob marshals an ssh-ed25519 public key blob:
//
//	string "ssh-ed25519"
//	string <32-byte public point>
//
// which is the canonical RFC-style SSH wire representation returned to a peer
// in SSH2_AGENT_IDENTITIES_ANSWER.
func pubBlob(pub []byte) []byte {
	if len(pub) != ed25519.PublicKeySize {
		return nil
	}
	out := make([]byte, 0, 4+len(KeyAlgoED25519)+4+len(pub))
	out = writeString(out, []byte(KeyAlgoED25519))
	out = writeString(out, pub)
	return out
}

// parsePubBlob extracts the 32-byte Ed25519 public point from an ssh-ed25519
// public key blob, returning an error for any other shape.
func parsePubBlob(blob []byte) ([]byte, error) {
	rest := blob
	algo, rest, err := readString(rest)
	if err != nil {
		return nil, ErrMalformedRequest
	}
	if string(algo) != KeyAlgoED25519 {
		return nil, ErrMalformedRequest
	}
	pub, _, err := readString(rest)
	if err != nil {
		return nil, ErrMalformedRequest
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrMalformedRequest
	}
	return pub, nil
}

// Identity describes one ssh-ed25519 identity advertised by an agent: its wire
// public blob and a human comment.
type Identity struct {
	// Blob is the marshalled public key ("ssh-ed25519" + the 32-byte point).
	Blob []byte
	// Comment is the free-form comment on the key (e.g. its wallet key tag).
	Comment string
}

// ServerKey hods a wallet Ed25519 key plus its ssh comment and cached marshalled
// public blob; it is the unit served by the agent's identities message.
type ServerKey struct {
	// Priv is the wallet's Ed25519 private key. Kept non-exported pointer-free
	// copies are infeasible; callers hand us their wallet key directly.
	Priv *ed25519.PrivateKey
	// Comment labels the key; put a wallet tag or an address here.
	Comment string
}

// Identity returns the ssh Identity (public blob + comment) for k.
func (k *ServerKey) Identity() (Identity, error) {
	pub := pubBlob(k.Priv.PublicKey.Point)
	if pub == nil {
		return Identity{}, ErrMalformedRequest
	}
	return Identity{Blob: pub, Comment: k.Comment}, nil
}

// Public returns the 32-byte Ed25519 public point (a copy).
func (k *ServerKey) Public() []byte {
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, k.Priv.PublicKey.Point)
	return out
}
