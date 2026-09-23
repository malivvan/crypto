// Package client exposes the SSH client-side implementation that lives in
// this module's ssh/internal as a stable, importable package.
//
// ssh is a server framework; its actual SSH protocol client (an adapted,
// hardened port restricted to the module's supported key-exchange / host-key
// set) is internal to ssh. Because Go's "internal" directory rule prevents
// code outside the ssh subtree from importing ssh/internal, this package
// re-exports the client API under github.com/malivvan/crypto/ssh/client.
//
// Only the surface required by external consumers is exported here. The
// exported identifiers are aliases of the ssh/internal ones, so parsed/signed
// values round-trip without conversion.
package client

import (
	"net"

	gossh "github.com/malivvan/crypto/ssh/internal"
)

// Client-API types, aliased back to the wallet's SSH implementation so values
// returned by this package match the types this package exposes.
type (
	// Client is a client connection to an SSH server.
	Client = gossh.Client
	// Session is a single session on an SSH client connection.
	Session = gossh.Session
	// ClientConfig holds client connection settings.
	ClientConfig = gossh.ClientConfig
	// NewChannel and Request describe an opened channel / global request.
	NewChannel = gossh.NewChannel
	// Conn is the muxed connection to the peer.
	Conn = gossh.Conn
	// Request is a global request received by a client.
	Request = gossh.Request
	// AuthMethod represents an authentication method for the client.
	AuthMethod = gossh.AuthMethod
	// HostKeyCallback verifies a peer host key during the handshake.
	HostKeyCallback = gossh.HostKeyCallback
	// Signer can sign over a known public key.
	Signer = gossh.Signer
	// PublicKey can be marshaled for the SSH wire protocol.
	PublicKey = gossh.PublicKey
	// Signature is the signature object returned by a Signer.
	Signature = gossh.Signature
	// KeyboardInteractiveChallenge is the challenge for keyboard-interactive.
	KeyboardInteractiveChallenge = gossh.KeyboardInteractiveChallenge
)

// NewClientConn establishes a new transport connection to c using the given
// client config, returning a Conn plus the open channel / global request
// streams for NewClient.
func NewClientConn(c net.Conn, addr string, config *ClientConfig) (Conn, <-chan NewChannel, <-chan *Request, error) {
	return gossh.NewClientConn(c, addr, config)
}

// NewClient returns a new Client from a Conn established with NewClientConn.
func NewClient(c Conn, chans <-chan NewChannel, reqs <-chan *Request) *Client {
	return gossh.NewClient(c, chans, reqs)
}

// Password returns an AuthMethod authenticating with the given password.
func Password(secret string) AuthMethod { return gossh.Password(secret) }

// KeyboardInteractive returns an AuthMethod that uses a challenge/response
// driven by the server.
func KeyboardInteractive(challenge KeyboardInteractiveChallenge) AuthMethod {
	return gossh.KeyboardInteractive(challenge)
}

// PasswordCallback returns an AuthMethod that asks for the password via the
// supplied callback.
func PasswordCallback(prompt func() (secret string, err error)) AuthMethod {
	return gossh.PasswordCallback(prompt)
}

// PublicKeys returns an AuthMethod authenticating with the given Signers.
func PublicKeys(signers ...Signer) AuthMethod { return gossh.PublicKeys(signers...) }

// PublicKeysCallback returns an AuthMethod that calls getSigners to obtain the
// available keys.
func PublicKeysCallback(getSigners func() (signers []Signer, err error)) AuthMethod {
	return gossh.PublicKeysCallback(getSigners)
}

// ParsePrivateKey parses an (unencrypted) PEM encoded private key.
func ParsePrivateKey(pemBytes []byte) (Signer, error) {
	return gossh.ParsePrivateKey(pemBytes)
}

// ParsePrivateKeyWithPassphrase parses an encrypted PEM encoded private key.
func ParsePrivateKeyWithPassphrase(pemBytes, passphrase []byte) (Signer, error) {
	return gossh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
}

// PassphraseMissingError is returned when a key parser is handed an encrypted
// key without the passphrase needed to unlock it.
type PassphraseMissingError = gossh.PassphraseMissingError

// Supported SSH public-key algorithms declared by the wallet's SSH
// implementation (Ed25519 family only; see AGENTS.md).
const (
	KeyAlgoED25519   = gossh.KeyAlgoED25519
	KeyAlgoSKED25519 = gossh.KeyAlgoSKED25519
)
