// Package agent lets the caller expose its Ed25519 keys over the
// OpenSSH agent protocol (RFC 4819 / PROTOCOL.agent): a pure-Go server that
// advertises and signs with the registered keys, and a client used to talk to
// an already-running ssh-agent (SSH_AUTH_SOCK) — the SSH counterpart of the
// module's gpg-agent in pgp/agent.
//
// The server implements the minimal, unambiguous subset of the protocol needed
// for modern ssh-ed25519 keys: SSH2_AGENTC_REQUEST_IDENTITIES /
// SSH2_AGENT_IDENTITIES_ANSWER and SSH2_AGENTC_SIGN_REQUEST /
// SSH2_AGENT_SIGN_RESPONSE (see README.md "Protocol" for the exact surface and
// why the remaining opcodes are rejected with SSH_AGENT_FAILURE).
package agent

import (
	"encoding/binary"
	"errors"
	"io"
)

// Agent message type bytes, taken verbatim from PROTOCOL.agent and the
// universally used OpenSSH / golang.org/x/crypto ssh/agent implementation.
const (
	agentFailure             = 5
	agentSuccess             = 6
	agentRequestIdentities   = 11
	agentIdentitiesAnswer    = 12
	agentSignRequest         = 13
	agentSignResponse        = 14
	agentAddIdentity         = 17
	agentRemoveIdentity      = 18
	agentRemoveAllIdentities = 19
	agentLock                = 22
	agentUnlock              = 23
	agentRequestV1Identities = 1
)

// KeyAlgoED25519 is the ssh algorithm name for Ed25519 keys.
const KeyAlgoED25519 = "ssh-ed25519"

// maxMessageLen guards against absurd allocation from a hostile length field.
// ssh-agent replies and requests never legitimately exceed 16 MiB.
const maxMessageLen = 16 << 20

// ErrMalformedRequest signals a wire-format error in a client message.
var ErrMalformedRequest = errors.New("sshagent: malformed agent request")

func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func putUint32(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

// readString reads one SSH string (uint32 length prefix followed by bytes).
func readString(b []byte) (val []byte, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n) > len(b)-4 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return b[4 : 4+int(n)], b[4+int(n):], nil
}

// writeString appends an SSH string encoding of val to dst.
func writeString(dst []byte, val []byte) []byte {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(val)))
	dst = append(dst, lb[:]...)
	return append(dst, val...)
}

// parseMessage splits a length-prefixed agent frame (the framing used on the
// unix socket) back into its type byte and the remaining payload.
func parseMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	n, err := readUint32(r)
	if err != nil {
		return 0, nil, err
	}
	if int(n) > maxMessageLen || n < 1 {
		return 0, nil, ErrMalformedRequest
	}
	payload = make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return payload[0], payload[1:], nil
}

// encodeMessage wraps a message (type byte + body) into a length-prefixed frame
// ready to write onto the agent socket.
func encodeMessage(msgType byte, body []byte) []byte {
	frame := make([]byte, 0, 4+1+len(body))
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(1+len(body)))
	frame = append(frame, lb[:]...)
	frame = append(frame, msgType)
	return append(frame, body...)
}
