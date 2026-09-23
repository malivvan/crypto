package middleware

import (
	"log"
	"time"

	"github.com/malivvan/crypto/ssh"
)

// Elapsed returns a middleware that logs the elapsed time of the
// session.
//
// In order to provide an accurate elapsed time for the entire session,
// this must be called as the last middleware in the chain.
func Elapsed() ssh.Middleware {
	return func(sh ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			now := time.Now()
			sh(s)
			log.Printf("elapsed: user=%s remote-addr=%s duration=%s",
				s.User(),
				s.RemoteAddr().String(),
				time.Since(now),
			)
		}
	}
}
