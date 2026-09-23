package agent

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/malivvan/crypto/ed25519"
)

// ServerKeyring is an ordered set of ssh-ed25519 identities served by a Server or
// used by handleMessage. It is safe for concurrent use after population.
type ServerKeyring struct {
	mu    sync.RWMutex
	keys  []*ServerKey
	byPub map[string]*ServerKey
}

// NewServerKeyring returns an empty keyring.
func NewServerKeyring() *ServerKeyring {
	return &ServerKeyring{byPub: make(map[string]*ServerKey)}
}

// AddKey stores one key (replacing a previous key with the same public value).
func (kr *ServerKeyring) AddKey(priv *ed25519.PrivateKey, comment string) {
	if priv == nil {
		return
	}
	k := &ServerKey{Priv: priv, Comment: comment}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	pub := string(priv.PublicKey.Point)
	if _, ok := kr.byPub[pub]; !ok {
		kr.keys = append(kr.keys, k)
	}
	kr.byPub[pub] = k
}

// Len returns the number of keys in the keyring.
func (kr *ServerKeyring) Len() int {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return len(kr.keys)
}

// List returns copies of the current identities (public-blob + comment).
func (kr *ServerKeyring) List() []Identity {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := make([]Identity, 0, len(kr.keys))
	for _, k := range kr.keys {
		if id, err := k.Identity(); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// find returns the key whose 32-byte public point equals pub.
func (kr *ServerKeyring) find(pub []byte) *ServerKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.byPub[string(pub)]
}

// signRaw produces the raw 64-byte Ed25519 signature over data. ssh-ed25519
// signs the supplied data directly (no extra pre-hash), matching what the
// verifier (e.g. github.com/malivvan/crypto/ssh) recomputes.
func signRaw(k *ServerKey, data []byte) ([]byte, error) {
	if k == nil || k.Priv == nil {
		return nil, errors.New("sshagent: no key selected for signing")
	}
	return ed25519.Sign(k.Priv, data)
}

// serveConn services one logical agent connection until it closes, answering
// each length-prefixed request with a length-prefixed reply. Unsupported or
// unrecognised messages yield SSH_AGENT_FAILURE.
func serveConn(kr *ServerKeyring, conn net.Conn) error {
	defer conn.Close()
	for {
		msgType, payload, err := parseMessage(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		replyType, reply := replyTo(kr, msgType, payload)
		if _, err := conn.Write(encodeMessage(replyType, reply)); err != nil {
			return err
		}
	}
}

// failureBody returns the SSH_AGENT_FAILURE payload.
func failureBody() []byte { return []byte{} }

// replyTo computes the agent reply for one request. Unhandled or malformed
// request types map to SSH_AGENT_FAILURE.
func replyTo(kr *ServerKeyring, msgType byte, payload []byte) (replyType byte, reply []byte) {
	switch msgType {
	case agentRequestIdentities: // 11
		idents := kr.List()
		body := make([]byte, 4)
		binary.BigEndian.PutUint32(body, uint32(len(idents)))
		for _, id := range idents {
			body = writeString(body, id.Blob)
			body = writeString(body, []byte(id.Comment))
		}
		return agentIdentitiesAnswer, body

	case agentSignRequest: // 13
		keyBlob, rest, err := readString(payload)
		if err != nil {
			return agentFailure, failureBody()
		}
		pub, err := parsePubBlob(keyBlob)
		if err != nil {
			return agentFailure, failureBody()
		}
		data, rest2, err := readString(rest)
		if err != nil {
			return agentFailure, failureBody()
		}
		_ = rest2 // flags follow but are unused for ssh-ed25519
		k := kr.find(pub)
		if k == nil {
			return agentFailure, failureBody()
		}
		sig, err := signRaw(k, data)
		if err != nil {
			return agentFailure, failureBody()
		}
		// Signature blob: string "ssh-ed25519" , string <64-byte sig>.
		sigBlob := writeString(nil, []byte(KeyAlgoED25519))
		sigBlob = writeString(sigBlob, sig)
		return agentSignResponse, writeString(nil, sigBlob)

	default:
		return agentFailure, failureBody()
	}
}
