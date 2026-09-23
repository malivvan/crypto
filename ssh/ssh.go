// Package ssh is a minimal, hardened SSH server and client library.
//
// It provides an easy way to build SSH servers without having to deal with
// the SSH protocol details, and to dial those servers from Go: see [Dial],
// [DialContext] and [Client] for the client half, and [Server], [Serve] and
// [ListenAndServe] for the server half.
//
// The package only supports a deliberately small set of modern algorithms:
//
//   - Key exchange: curve25519-sha256, mlkem768x25519-sha256
//   - Host key certificates: ssh-ed25519-cert-v01@openssh.com,
//     sk-ssh-ed25519-cert-v01@openssh.com
//   - Ciphers: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com
//   - MACs: hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com
//
// Everything else (RSA, DSA, ECDSA, SHA-1, CBC, RC4, legacy Diffie-Hellman,
// ...) has been removed. [SupportedAlgorithms] reports the negotiated set.
//
// The exported key, channel and client types are aliases of the package's own
// protocol implementation, so values obtained from this package interoperate
// with each other without conversion.
package ssh

import (
	"crypto/subtle"
	"net"
)

// DefaultHandler is the default Handler used by Serve.
var DefaultHandler Handler

// Option is a functional option handler for Server.
type Option func(*Server) error

// Handler is a callback for handling established SSH sessions.
type Handler func(ServerSession)

// BannerHandler is a callback for displaying the server banner.
type BannerHandler func(ctx Context) string

// PublicKeyHandler is a callback for performing public key authentication.
type PublicKeyHandler func(ctx Context, key PublicKey) bool

// PasswordHandler is a callback for performing password authentication.
type PasswordHandler func(ctx Context, password string) bool

// KeyboardInteractiveHandler is a callback for performing keyboard-interactive authentication.
type KeyboardInteractiveHandler func(ctx Context, challenger KeyboardInteractiveChallenge) bool

// PtyHandler is a callback for handling PTY allocation requests.
type PtyHandler func(ctx Context, s ServerSession, pty Pty) (func() error, error)

// PtyCallback is a hook for handling PTY allocation requests.
type PtyCallback func(ctx Context, req Pty) bool

// SessionRequestCallback is a callback for allowing or denying SSH sessions.
type SessionRequestCallback func(sess ServerSession, requestType string) bool

// ConnCallback is a hook for new connections before handling.
// It allows wrapping for timeouts and limiting by returning
// the net.Conn that will be used as the underlying connection.
type ConnCallback func(ctx Context, conn net.Conn) net.Conn

// LocalPortForwardingCallback is a hook for allowing port forwarding.
type LocalPortForwardingCallback func(ctx Context, destinationHost string, destinationPort uint32) bool

// ReversePortForwardingCallback is a hook for allowing reverse port forwarding.
type ReversePortForwardingCallback func(ctx Context, bindHost string, bindPort uint32) bool

// ServerConfigCallback is a hook for creating custom default server configs.
type ServerConfigCallback func(ctx Context) *ServerConfig

// ConnectionFailedCallback is a hook for reporting failed connections
// Please note: the net.Conn is likely to be closed at this point.
type ConnectionFailedCallback func(conn net.Conn, err error)

// ConnectionCloseCallback is a hook for reporting closed connections.
type ConnectionCloseCallback func(conn net.Conn)

// Window represents the size of a PTY window.
//
// From https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
//
// Zero dimension parameters MUST be ignored. The character/row dimensions
// override the pixel dimensions (when nonzero).  Pixel dimensions refer
// to the drawable area of the window.
type Window struct {
	// Width is the number of columns.
	// It overrides WidthPixels.
	Width int
	// Height is the number of rows.
	// It overrides HeightPixels.
	Height int

	// WidthPixels is the drawable width of the window, in pixels.
	WidthPixels int
	// HeightPixels is the drawable height of the window, in pixels.
	HeightPixels int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	impl

	// Term is the TERM environment variable value.
	Term string

	// Window is the Window sent as part of the ptyallocate-req.
	Window Window

	// Modes represent a mapping of Terminal Mode opcode to value as it was
	// requested by the client as part of the ptyallocate-req. These are outlined as
	// part of https://datatracker.ietf.org/doc/html/rfc4254#section-8.
	//
	// The opcodes are the VINTR, VQUIT, ... constants declared in this package.
	// Boolean opcodes have values 0 or 1.
	Modes TerminalModes
}

// Serve accepts incoming SSH connections on the listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and
// then calls handler to handle sessions. Handler is typically nil, in which
// case the DefaultHandler is used.
func Serve(l net.Listener, handler Handler, options ...Option) error {
	srv := &Server{Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.Serve(l)
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle sessions on incoming connections. Handler is typically
// nil, in which case the DefaultHandler is used.
func ListenAndServe(addr string, handler Handler, options ...Option) error {
	srv := &Server{Addr: addr, Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.ListenAndServe()
}

// Handle registers the handler as the DefaultHandler.
func Handle(handler Handler) {
	DefaultHandler = handler
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk PublicKey) bool {
	// avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}
