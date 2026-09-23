// Package middleware provides commonly used middleware for ssh.Server
// handlers: rate limiting, access control, logging, panic recovery, scp
// servers, and more.
package middleware

import "github.com/malivvan/crypto/ssh"

// Chain composes a final ssh.Handler with the given middleware and returns
// the resulting ssh.Handler. Middleware are applied so that mw[0] is the
// outermost wrapper (runs first on the way in, last on the way out), and
// mw[len(mw)-1] is the innermost, wrapping final directly.
func Chain(final ssh.Handler, mw ...ssh.Middleware) ssh.Handler {
	h := final
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
