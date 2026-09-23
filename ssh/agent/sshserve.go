package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/malivvan/crypto/ed25519"
)

// Server runs an ssh-ed25519 agent endpoint on a unix socket. Create one with
// Listen, register wallet keys via AddKey, then Serve (or run Serve in its own
// goroutine). It is the SSH analogue of the standalone gpg agent server: only
// the Ed25519 signature backend is wired, consistent with the wallet's
// supported-set constraints.
type Server struct {
	ln     net.Listener
	kr     *ServerKeyring
	closed chan struct{}
	done   chan struct{}
}

// Listen binds a unix socket at path (0700) and returns a Server that will
// serve kr once Serve is called. If path already exists, it is replaced only
// when force is true.
func Listen(path string, kr *ServerKeyring, force bool) (*Server, error) {
	if kr == nil {
		kr = NewServerKeyring()
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("sshagent: socket dir: %w", err)
		}
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("sshagent: socket already exists: %s", path)
		}
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("sshagent: listen: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		ln.Close()
		return nil, fmt.Errorf("sshagent: chmod: %w", err)
	}
	return &Server{ln: ln, kr: kr, closed: make(chan struct{}), done: make(chan struct{})}, nil
}

// AddKey registers an Ed25519 wallet key with the given comment (for example a
// wallet key tag or identity). Subsequent calls take effect for new
// connections.
func (s *Server) AddKey(priv *ed25519.PrivateKey, comment string) {
	s.kr.AddKey(priv, comment)
}

// Path returns the unix socket path this server is bound to.
func (s *Server) Path() string {
	return s.ln.Addr().String()
}

// Serve accepts and handles client connections until Close. Run it in its own
// goroutine; it blocks.
func (s *Server) Serve() error {
	defer close(s.done)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
				return err
			}
		}
		go func(c net.Conn) { _ = serveConn(s.kr, c) }(conn)
	}
}

// Close stops the listener and waits for the serving goroutine to return.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		s.waitDone()
		return nil
	default:
	}
	close(s.closed)
	err := s.ln.Close()
	s.waitDone()
	return err
}

func (s *Server) waitDone() { <-s.done }
