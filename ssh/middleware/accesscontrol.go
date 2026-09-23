package middleware

import (
	"fmt"

	"github.com/malivvan/crypto/ssh"
)

// AccessControl exits with status 1 any session trying to execute a command
// that is not in the allowed list. If no commands are provided, no commands
// will be allowed (only shells, if reached before this middleware rejects).
func AccessControl(cmds ...string) ssh.Middleware {
	return func(sh ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			if len(s.Command()) == 0 {
				sh(s)
				return
			}
			for _, cmd := range cmds {
				if s.Command()[0] == cmd {
					sh(s)
					return
				}
			}
			_, _ = fmt.Fprintln(s, "Command is not allowed: "+s.Command()[0])
			_ = s.Exit(1)
		}
	}
}
