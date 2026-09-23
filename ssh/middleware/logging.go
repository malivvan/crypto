package middleware

import (
	"log"
	"time"

	"github.com/malivvan/crypto/ssh"
)

// Logging returns a middleware that logs session connect and disconnect
// events using the session's structured logger. Connects are logged with the
// remote address, invoked command, TERM setting, window dimensions, client
// version, and whether public key auth was used. Disconnect logs the remote
// address and connection duration.
func Logging() ssh.Middleware {
	return func(next ssh.Handler) ssh.Handler {
		return func(sess ssh.ServerSession) {
			ct := time.Now()
			hpk := sess.PublicKey() != nil
			pty, _, _ := sess.Pty()
			log.Printf("connect: user=%s remote-addr=%s public-key=%t command=%v term=%s width=%d height=%d client-version=%s",
				sess.User(),
				sess.RemoteAddr().String(),
				hpk,
				sess.Command(),
				pty.Term,
				pty.Window.Width,
				pty.Window.Height,
				sess.Context().ClientVersion(),
			)
			next(sess)
			log.Printf("disconnect: user=%s remote-addr=%s duration=%s",
				sess.User(),
				sess.RemoteAddr().String(),
				time.Since(ct),
			)
		}
	}
}
