package middleware

import (
	"fmt"

	"github.com/malivvan/crypto/ssh"
)

// ActiveTerm exits with status 1 any session that does not have an active
// PTY. This is useful for TUI applications that require a terminal to
// function correctly.
func ActiveTerm() ssh.Middleware {
	return func(next ssh.Handler) ssh.Handler {
		return func(sess ssh.ServerSession) {
			_, _, active := sess.Pty()
			if active {
				next(sess)
				return
			}
			_, _ = fmt.Fprintln(sess, "Requires an active PTY")
			_ = sess.Exit(1)
		}
	}
}
