package gpg

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/malivvan/crypto/pgp/agent/server"
)

// Server is a standalone gpg-agent-compatible Assuan service listening on a
// unix socket with owner-only (0700) permissions. Create one with Listen, then
// call Serve to accept connections in the current goroutine or Close to tear
// it down. Each accepted connection is handled concurrently in its own
// goroutine.
type Server struct {
	ln     net.Listener
	proto  server.ProtoInfo
	closed chan struct{}
	done   chan struct{}
}

// Listen binds a unix socket at path (with directories created up front) and
// returns a Server holding that listener. The socket file is chmod'ed 0700
// after bind. If path exists Listen fails unless force is true, in which case a
// stale existing name is removed first.
func Listen(path string, kr *Keyring, force bool) (*Server, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("gpg: create socket dir: %w", err)
		}
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("gpg: socket path already exists: %s", path)
		}
	}
	_ = os.Remove(path) // always try to clear for unix socket semantics
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("gpg: listen: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		ln.Close()
		return nil, fmt.Errorf("gpg: socket chmod: %w", err)
	}
	return &Server{
		ln:     ln,
		proto:  ProtoInfo(kr),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}, nil
}

// Addr returns the bound unix socket address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Path returns the filesystem path of the unix socket.
func (s *Server) Path() string {
	if ua, ok := s.ln.Addr().(*net.UnixAddr); ok {
		return ua.Name
	}
	return s.ln.Addr().String()
}

// Serve accepts and serves connections until the server is closed. It returns
// when Accept fails (for example after Close). Serve is intended to run in its
// own goroutine or to block the calling program.
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
		go func(c net.Conn) {
			defer c.Close()
			// One goroutine per client; ServeNet semantics preserved inside.
			_ = server.Serve(c, s.proto)
		}(conn)
	}
}

// Close closes the listener and waits for the Serve goroutine to exit.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		// already closed
		s.waitDone()
		return nil
	default:
	}
	close(s.closed)
	err := s.ln.Close()
	s.waitDone()
	return err
}

func (s *Server) waitDone() {
	<-s.done
}
