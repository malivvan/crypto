package ssh

import gossh "github.com/malivvan/crypto/ssh/internal"

// ExitError is returned by [ClientSession.Wait] when the server reports a
// non-zero exit status for the remote command.
type ExitError = gossh.ExitError

// ExitMissingError is returned by [ClientSession.Wait] if a session is
// terminated without sending an exit-status message. It implements error.
type ExitMissingError = gossh.ExitMissingError

// Waitmsg stores the information about an exited remote command as reported by
// Wait.
type Waitmsg = gossh.Waitmsg

// OpenChannelError is returned if the other side rejects an [Conn.OpenChannel]
// request.
type OpenChannelError = gossh.OpenChannelError

// PassphraseMissingError is returned when a key parser is handed an encrypted
// key without the passphrase needed to unlock it.
type PassphraseMissingError = gossh.PassphraseMissingError

// AlgorithmNegotiationError is returned if the client and the server cannot
// agree on an algorithm for key exchange, host key, cipher or MAC.
type AlgorithmNegotiationError = gossh.AlgorithmNegotiationError
