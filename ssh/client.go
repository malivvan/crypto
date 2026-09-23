package ssh

import (
	"context"
	"errors"
	"net"

	gossh "github.com/malivvan/crypto/ssh/internal"
)

// errNilClientConfig is returned when a client function is called without a
// ClientConfig. Such a config can never authenticate or verify a host key.
var errNilClientConfig = errors.New("ssh: ClientConfig must not be nil")

// Client implements a traditional SSH client that supports shells,
// subprocesses, TCP port/streamlocal forwarding and tunneled dialing.
//
// Create one with [Dial], [DialContext] or [NewClient], then use
// [Client.NewSession] to run remote commands and [Client.Dial],
// [Client.DialContext] or [Client.Listen] to forward connections.
//
// The client half of this package only negotiates the algorithms listed in the
// package documentation, so it connects to servers that present an Ed25519
// host key certificate.
type Client = gossh.Client

// ClientSession is a session on a [Client]: a single remote command or shell,
// with piped standard input, output and error streams. Sessions are created
// with [Client.NewSession] and waited on with [ClientSession.Wait].
type ClientSession = gossh.Session

// ClientConfig holds the settings used to establish a client connection. It
// must not be modified after having been passed to an SSH function.
type ClientConfig = gossh.ClientConfig

// Config holds the configuration shared between client and server: the
// entropy source, rekeying threshold and the allowed key exchange, cipher and
// MAC algorithms.
type Config = gossh.Config

// ClientAuthCallback is a hook invoked before each authentication attempt. It
// allows the client to dynamically select an authentication method based on
// the current context, server capabilities, or previous failures.
//
// The callback is invoked after the initial "none" authentication method, once
// the server's supported authentication methods are known. Returning
// (nil, nil) falls back to the next untried method in ClientConfig.Auth.
type ClientAuthCallback = gossh.ClientAuthCallback

// ClientAuthContext contains information about the current state of the
// authentication process, passed to a [ClientAuthCallback].
type ClientAuthContext = gossh.ClientAuthContext

// Conn is an SSH connection for both server and client roles. It is the basis
// of [Client] and [ServerConn].
type Conn = gossh.Conn

// ConnMetadata holds the metadata of a connection.
type ConnMetadata = gossh.ConnMetadata

// AlgorithmsConnMetadata is a [ConnMetadata] that can return the algorithms
// negotiated between client and server.
type AlgorithmsConnMetadata = gossh.AlgorithmsConnMetadata

// NegotiatedAlgorithms defines the algorithms negotiated between client and
// server.
type NegotiatedAlgorithms = gossh.NegotiatedAlgorithms

// DirectionAlgorithms defines the algorithms negotiated in one direction
// (either read or write).
type DirectionAlgorithms = gossh.DirectionAlgorithms

// Algorithms defines the set of algorithms that can be configured in the
// client or server config for negotiation during a handshake.
type Algorithms = gossh.Algorithms

// Algorithm names supported by this package, for use in [Config] and
// [ClientConfig.HostKeyAlgorithms]. Call [SupportedAlgorithms] to list them
// all, including the key exchange, cipher and MAC sets.
const (
	CipherAES256GCM           = gossh.CipherAES256GCM
	CipherChaCha20Poly1305    = gossh.CipherChaCha20Poly1305
	KeyExchangeCurve25519     = gossh.KeyExchangeCurve25519
	KeyExchangeMLKEM768X25519 = gossh.KeyExchangeMLKEM768X25519
	HMACSHA256ETM             = gossh.HMACSHA256ETM
	HMACSHA512ETM             = gossh.HMACSHA512ETM
)

// SupportedAlgorithms returns the algorithms implemented by this package. The
// algorithms listed here are in preference order.
func SupportedAlgorithms() Algorithms {
	return gossh.SupportedAlgorithms()
}

// Dial starts a client connection to the given SSH server. It is a convenience
// function that connects to the given network address, initiates the SSH
// handshake, and then sets up a [Client].
//
// The config must be non-nil and must set HostKeyCallback, for example with
// [FixedHostKey], [InsecureIgnoreHostKey] or [CertChecker.CheckHostKey]. For
// access to incoming channels and requests, or to dial a connection that is
// already established, use [NewClientConn] instead.
func Dial(network, addr string, config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, errNilClientConfig
	}
	return gossh.Dial(network, addr, config)
}

// DialContext is like [Dial] but takes a context: if the context expires
// before the TCP connection is established or while the handshake runs, the
// connection is closed and the context's error is returned. Once the client is
// connected, the state of the context no longer affects it.
//
// The provided Context must be non-nil, and so must the config; see [Dial].
func DialContext(ctx context.Context, network, addr string, config *ClientConfig) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errNilClientConfig
	}
	conn, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// Abort a handshake that outlives the context. The connection is owned by
	// the client once NewClientConn returns, so the callback is disarmed then.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	c, chans, reqs, err := NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		// The handshake was aborted by the context: report why rather than the
		// network error the close caused.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return NewClient(c, chans, reqs), nil
}

// NewClientConn establishes an authenticated SSH connection using c as the
// underlying transport. The Request and NewChannel channels must be serviced
// (or passed to [NewClient]) or the connection will hang.
//
// The config must be non-nil and must set HostKeyCallback.
func NewClientConn(c net.Conn, addr string, config *ClientConfig) (Conn, <-chan NewChannel, <-chan *Request, error) {
	if config == nil {
		return nil, nil, nil, errNilClientConfig
	}
	return gossh.NewClientConn(c, addr, config)
}

// NewClient creates a [Client] on top of the connection established with
// [NewClientConn]. It takes over servicing of the channel and request streams
// returned by NewClientConn.
func NewClient(c Conn, chans <-chan NewChannel, reqs <-chan *Request) *Client {
	return gossh.NewClient(c, chans, reqs)
}

// NewControlClientConn establishes an SSH connection over an OpenSSH
// ControlMaster socket c in proxy mode.
//
// Note that this package only implements the client side of the multiplexing
// protocol. The provided net.Conn must be a local, secure connection (such as
// a Unix domain socket) connected to an already-running OpenSSH process acting
// as the ControlMaster.
//
// WARNING: Because proxy mode bypasses the standard cryptographic handshake,
// passing a standard network connection (e.g., TCP) will result in plaintext
// data leakage.
//
// The Request and NewChannel channels must be serviced or the connection will
// hang.
func NewControlClientConn(c net.Conn) (Conn, <-chan NewChannel, <-chan *Request, error) {
	return gossh.NewControlClientConn(c)
}

// HostKeyCallback is the function type used for verifying server keys. A
// HostKeyCallback must return nil if the host key is OK, or an error to reject
// it. It receives the hostname as passed to [Dial] or [NewClientConn]. The
// remote address is the RemoteAddr of the net.Conn underlying the SSH
// connection.
type HostKeyCallback = gossh.HostKeyCallback

// InsecureIgnoreHostKey returns a function that can be used for
// ClientConfig.HostKeyCallback to accept any host key. It should not be used
// for production code.
func InsecureIgnoreHostKey() HostKeyCallback {
	return gossh.InsecureIgnoreHostKey()
}

// FixedHostKey returns a function for use in ClientConfig.HostKeyCallback to
// accept only a specific host key.
func FixedHostKey(key PublicKey) HostKeyCallback {
	return gossh.FixedHostKey(key)
}

// BannerCallback is the function type used for handling the banner sent by the
// server. A BannerCallback receives the message sent by the remote server.
type BannerCallback = gossh.BannerCallback

// BannerDisplayStderr returns a function that can be used for
// ClientConfig.BannerCallback to display banners on os.Stderr.
func BannerDisplayStderr() BannerCallback {
	return gossh.BannerDisplayStderr()
}
