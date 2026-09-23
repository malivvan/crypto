package middleware

import (
	"log"
	"runtime/debug"

	"github.com/malivvan/crypto/ssh"
)

// Recover returns a middleware that recovers from panics raised by the
// given middleware chain (or the next handler, if none is given) and logs
// them, with a stack trace, to the session's structured logger.
//
// Both the wrapped middleware chain and the next handler run on the
// connection's goroutine, and Go has no process-wide panic handler, so
// letting a panic escape would terminate the whole server process rather
// than just the offending session.
func Recover(mw ...ssh.Middleware) ssh.Middleware {
	h := func(ssh.ServerSession) {}
	for _, m := range mw {
		h = m(h)
	}
	return func(sh ssh.Handler) ssh.Handler {
		return func(s ssh.ServerSession) {
			guard(s, func() { h(s) })
			guard(s, func() { sh(s) })
		}
	}
}

func guard(s ssh.ServerSession, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered panic: %v\n%s", r, debug.Stack())
		}
	}()
	fn()
}
