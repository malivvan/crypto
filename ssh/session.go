package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"unicode"
)

// ServerSession provides access to information about an SSH session and methods
// to read and write to the SSH channel with an embedded Channel interface from
// crypto/ssh.
//
// When Command() returns an empty slice, the user requested a shell. Otherwise
// the user is performing an exec with those command arguments.
//
// TODO: Signals.
type ServerSession interface {
	Channel

	// User returns the username used when establishing the SSH connection.
	User() string

	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr

	// Environ returns a copy of strings representing the environment set by the
	// user for this session, in the form "key=value".
	Environ() []string

	// Exit sends an exit status and then closes the session.
	Exit(code int) error

	// Command returns a shell parsed slice of arguments that were provided by the
	// user. Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	Command() []string

	// RawCommand returns the exact command that was provided by the user.
	RawCommand() string

	// Subsystem returns the subsystem requested by the user.
	Subsystem() string

	// PublicKey returns the PublicKey used to authenticate. If a public key was not
	// used it will return nil.
	PublicKey() PublicKey

	// Context returns the connection's context. The returned context is always
	// non-nil and holds the same data as the Context passed into auth
	// handlers and callbacks.
	//
	// The context is canceled when the client's connection closes or I/O
	// operation fails.
	Context() Context

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers via the Context.
	Permissions() Permissions

	// EmulatedPty returns true if the session is emulating a PTY using PtyWriter.
	EmulatedPty() bool

	// Pty returns PTY information, a channel of window size changes, and a boolean
	// of whether or not a PTY was accepted for this session.
	Pty() (Pty, <-chan Window, bool)

	// Signals registers a channel to receive signals sent from the client. The
	// channel must handle signal sends or it will block the SSH request loop.
	// Registering nil will unregister the channel from signal sends. During the
	// time no channel is registered signals are buffered up to a reasonable amount.
	// If there are buffered signals when a channel is registered, they will be
	// sent in order on the channel immediately after registering.
	Signals(c chan<- Signal)

	// Break regisers a channel to receive notifications of break requests sent
	// from the client. The channel must handle break requests, or it will block
	// the request handling loop. Registering nil will unregister the channel.
	// During the time that no channel is registered, breaks are ignored.
	Break(c chan<- bool)
}

// maxSigBufSize is how many signals will be buffered
// when there is no signal channel specified.
const maxSigBufSize = 128

// DefaultSessionHandler is the default handler for the "session" channel type.
func DefaultSessionHandler(srv *Server, conn *ServerConn, newChan NewChannel, ctx Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		slog.Warn("ssh: failed to accept session channel", "err", err)
		return
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           srv.Handler,
		ptyCb:             srv.PtyCallback,
		ptyHandler:        srv.PtyHandler,
		sessReqCb:         srv.SessionRequestCallback,
		subsystemHandlers: srv.SubsystemHandlers,
		ctx:               ctx,
	}
	ctx.SetValue(ContextKeySession, sess)
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	Channel
	conn              *ServerConn
	handler           Handler
	subsystemHandlers map[string]SubsystemHandler
	handled           bool
	exited            bool
	pty               *Pty
	winch             chan Window
	env               []string
	ptyCb             PtyCallback
	ptyHandler        PtyHandler
	sessReqCb         SessionRequestCallback
	rawCmd            string
	subsystem         string
	ctx               Context
	sigCh             chan<- Signal
	sigBuf            []Signal
	breakCh           chan<- bool
}

func (sess *session) Stderr() io.ReadWriter {
	if sess.pty != nil && sess.EmulatedPty() {
		return NewPtyReadWriter(sess.Channel.Stderr())
	}
	return sess.Channel.Stderr()
}

func (sess *session) Write(p []byte) (int, error) {
	if sess.pty != nil && sess.EmulatedPty() {
		return NewPtyWriter(sess.Channel).Write(p)
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() PublicKey {
	sessionkey := sess.ctx.Value(ContextKeyPublicKey)
	if sessionkey == nil {
		return nil
	}
	return sessionkey.(PublicKey)
}

func (sess *session) Permissions() Permissions {
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(ContextKeyPermissions).(*Permissions)
	return *perms
}

func (sess *session) Context() Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("ServerSession.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)} //nolint:gosec // SSH exit status is an unsigned 32-bit field
	_, err := sess.SendRequest("exit-status", false, Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shellSplit(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) EmulatedPty() bool {
	return sess.ctx.Value(contextKeyEmulatePty) == true
}

func (sess *session) Pty() (Pty, <-chan Window, bool) {
	if sess.pty != nil && (sess.EmulatedPty() || !sess.pty.IsZero()) {
		return *sess.pty, sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

func (sess *session) handleRequests(reqs <-chan *Request) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}

			payload := struct{ Value string }{}
			_ = Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			if sess.handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			sess.handled = true
			_ = req.Reply(true, nil)

			go func() {
				// Closed from a defer so the ptyallocate is still released when the
				// handler panics, rather than trading a crash for a leak.
				if sess.pty != nil && !sess.pty.IsZero() {
					defer func() { _ = sess.pty.Close() }()
				}
				defer recoverAndLog("panic in session handler", nil, func() {
					_ = sess.Exit(1)
				})
				if sess.pty != nil && !sess.pty.IsZero() {
					go func() {
						defer recoverAndLog("panic copying to ptyallocate", nil, nil)
						_, _ = io.Copy(sess.pty, sess)
					}()
					go func() {
						defer recoverAndLog("panic copying from ptyallocate", nil, nil)
						_, _ = io.Copy(sess, sess.pty)
					}()
				}
				sess.handler(sess)
				_ = sess.Exit(0)
			}()
		case "subsystem":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}

			payload := struct{ Value string }{}
			_ = Unmarshal(req.Payload, &payload)
			sess.subsystem = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[payload.Value]
			if handler == nil {
				handler = sess.subsystemHandlers["default"]
			}
			if handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			sess.handled = true
			_ = req.Reply(true, nil)

			go func() {
				defer recoverAndLog("panic in subsystem handler", nil, func() {
					_ = sess.Exit(1)
				})
				handler(sess)
				_ = sess.Exit(0)
			}()
		case "env":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			_ = Unmarshal(req.Payload, &kv)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			_ = req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			_ = Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "ptyallocate-req":
			if sess.handled || sess.pty != nil {
				_ = req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				_ = req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
					_ = req.Reply(false, nil)
					continue
				}
			}

			sess.pty = &ptyReq
			sess.winch = make(chan Window, 1)
			sess.winch <- ptyReq.Window

			if sess.ptyHandler != nil {
				closer, err := sess.ptyHandler(sess.ctx, sess, ptyReq)
				if err != nil {
					// TODO: handle error
					_ = req.Reply(false, nil)
					continue
				}

				defer func() { _ = closer() }() //nolint:staticcheck // intentional: runs when req channel closes

				if !sess.EmulatedPty() && !sess.pty.IsZero() {
					go func() {
						defer recoverAndLog("panic resizing ptyallocate", nil, nil)
						for win := range sess.winch {
							if err := resizePty(sess, win); err != nil {
								// TODO: handle error
								continue
							}
						}
					}()
				}
			}

			defer func() { //nolint:staticcheck // intentional: runs when req channel closes
				// when reqs is closed
				close(sess.winch)
			}()
			_ = req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				_ = req.Reply(false, nil)
				continue
			}
			win, _, ok := parseWindow(req.Payload)
			if ok {
				sess.pty.Window = win
				sess.winch <- win
			}
			_ = req.Reply(ok, nil)
		case agentRequestType:
			// TODO: option/callback to allow agent forwarding
			SetAgentRequested(sess.ctx)
			_ = req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			_ = req.Reply(ok, nil)
			sess.Unlock()
		default:
			slog.Debug("ssh: unknown session request", "type", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (sess *session) ptyAllocate(term string, win Window, modes TerminalModes) (func() error, error) {
	p, err := newPty(sess.ctx, term, win, modes)
	if err != nil {
		return nil, err
	}

	sess.pty = &Pty{
		Term:   term,
		Window: win,
		Modes:  modes,
		impl:   p,
	}

	return p.Close, nil
}

func resizePty(sess *session, win Window) error {
	if sess.pty == nil {
		return nil
	}

	return sess.pty.Resize(win.Width, win.Height)
}

var ErrNoClosing = errors.New("no closing quotation")
var ErrNoEscaped = errors.New("no escaped character")

func shellSplit(s string, whitespacesplit bool) ([]string, error) {
	isWord := func(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }
	isQuote := func(r rune) bool {
		switch r {
		case '\'', '"':
			return true
		default:
			return false
		}
	}
	isSpace := func(r rune) bool { return unicode.IsSpace(r) }
	isEscape := func(r rune) bool { return r == '\\' }
	isEscQuote := func(r rune) bool { return r == '"' }
	reader := bufio.NewReader(strings.NewReader(s))
	result := make([]string, 0)
	for {
		token, err := func(reader *bufio.Reader) (string, error) {
			token := ""
			quoted := false
			state := ' '
			escapedstate := ' '
		scanning:
			for {
				next, _, err := reader.ReadRune()
				if err != nil {
					if isQuote(state) {
						return token, ErrNoClosing
					} else if isEscape(state) {
						return token, ErrNoEscaped
					}
					return token, err
				}
				switch {
				case isSpace(state):
					switch {
					case isSpace(next):
						break scanning
					case isEscape(next):
						escapedstate = 'a'
						state = next
					case isWord(next):
						token += string(next)
						state = 'a'
					case isQuote(next):
						state = next
					default:
						token = string(next)
						if whitespacesplit {
							state = 'a'
						} else if token != "" || (quoted) {
							break scanning
						}
					}
				case isQuote(state):
					quoted = true
					switch {
					case next == state:
						state = 'a'
					case isEscape(next) && isEscQuote(state):
						escapedstate = state
						state = next
					default:
						token += string(next)
					}
				case isEscape(state):
					if isQuote(escapedstate) && next != state && next != escapedstate {
						token += string(state)
					}
					token += string(next)
					state = escapedstate
				case isWord(state):
					switch {
					case isSpace(next):
						if token != "" || (quoted) {
							break scanning
						}
					case isQuote(next):
						state = next
					case isEscape(next):
						escapedstate = 'a'
						state = next
					case isWord(next) || isQuote(next):
						token += string(next)
					default:
						if whitespacesplit {
							token += string(next)
						} else if token != "" {
							reader.UnreadRune()
							break scanning
						}
					}
				}
			}
			return token, nil
		}(reader)
		if token != "" {
			result = append(result, token)
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return result, err
		}
	}
	return result, nil
}
