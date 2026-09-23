package agent

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
)

// Client is a small, dependency-free ssh-ed25519 agent client. It talks to any
// running ssh-agent (for example the wallet's own Server, or an OpenSSH agent
// behind SSH_AUTH_SOCK) using only the minimal protocol subset the server
// exposes. For fuller protocol coverage integrators may instead use an ssh
// library client; Client is provided so the agent core has no dependency on
// golang.org/x/crypto.
type Client struct {
	conn net.Conn
}

// DialUnix connects the Client to an ssh-agent unix socket at path.
func DialUnix(path string) (*Client, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// DialEnv connects to the agent named by SSH_AUTH_SOCK, if set.
func DialEnv() (*Client, error) {
	path := os.Getenv("SSH_AUTH_SOCK")
	if path == "" {
		return nil, errors.New("sshagent: SSH_AUTH_SOCK is not set")
	}
	return DialUnix(path)
}

// Close closes the underlying socket.
func (c *Client) Close() error { return c.conn.Close() }

// List returns identities advertised by the agent.
func (c *Client) List() ([]Identity, error) {
	if err := writeFrame(c.conn, agentRequestIdentities, nil); err != nil {
		return nil, err
	}
	msgType, payload, err := readFrame(c.conn)
	if err != nil {
		return nil, err
	}
	if msgType == agentFailure {
		return nil, errors.New("sshagent: agent refused identities request")
	}
	if msgType != agentIdentitiesAnswer {
		return nil, errors.New("sshagent: unexpected reply to identities request")
	}
	rest := payload
	if len(rest) < 4 {
		return nil, ErrMalformedRequest
	}
	n := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	id := make([]Identity, 0, n)
	for i := uint32(0); i < n; i++ {
		blob, r, ok := takeString(rest)
		if !ok {
			return nil, ErrMalformedRequest
		}
		comment, r2, ok2 := takeString(r)
		if !ok2 {
			return nil, ErrMalformedRequest
		}
		rest = r2
		id = append(id, Identity{Blob: blob, Comment: string(comment)})
	}
	return id, nil
}

// Sign requests an agent signature over data matching the key whose public
// point is the ssh-ed25519 public blob pubBlob (as returned by List). It
// returns the raw 64-byte Ed25519 signature.
func (c *Client) Sign(pubBlob []byte, data []byte) ([]byte, error) {
	flags := make([]byte, 4)
	body := writeString(nil, pubBlob)
	body = writeString(body, data)
	body = append(body, flags...)
	if err := writeFrame(c.conn, agentSignRequest, body); err != nil {
		return nil, err
	}
	msgType, payload, err := readFrame(c.conn)
	if err != nil {
		return nil, err
	}
	if msgType == agentFailure {
		return nil, errors.New("sshagent: agent refused signature request")
	}
	if msgType != agentSignResponse {
		return nil, errors.New("sshagent: unexpected reply to sign request")
	}
	// Reply body is a string whose content is string(algo)||string(raw sig).
	blob, _, ok := takeString(payload)
	if !ok {
		return nil, ErrMalformedRequest
	}
	sigAlgo, inner, ok := takeString(blob)
	if !ok || string(sigAlgo) != KeyAlgoED25519 {
		return nil, ErrMalformedRequest
	}
	raw, _, ok := takeString(inner)
	if !ok {
		return nil, ErrMalformedRequest
	}
	return raw, nil
}

// Internal framed I/O for the client direction (length-prefixed request).
func writeFrame(w net.Conn, msgType byte, body []byte) error {
	_, err := w.Write(encodeMessage(msgType, body))
	return err
}

func readFrame(r net.Conn) (byte, []byte, error) {
	return parseMessage(r)
}

func takeString(b []byte) (v []byte, rest []byte, ok bool) {
	t, rest, err := readString(b)
	if err != nil {
		return nil, nil, false
	}
	return t, rest, true
}
