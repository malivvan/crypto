package middleware

import (
	"fmt"

	"github.com/malivvan/crypto/ssh"
)

// Comment returns a middleware that prints a comment at the end of a
// session, after the wrapped handler has returned.
func Comment(comment string) ssh.Middleware {
	return func(sh ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			sh(s)
			_, _ = fmt.Fprintln(s, comment)
		}
	}
}
