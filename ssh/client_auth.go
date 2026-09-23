package ssh

import gossh "github.com/malivvan/crypto/ssh/internal"

// An AuthMethod represents an instance of an RFC 4252 authentication method.
// AuthMethods are passed to ClientConfig.Auth and are built with [Password],
// [PasswordCallback], [PublicKeys], [PublicKeysCallback],
// [KeyboardInteractive] or [RetryableAuthMethod].
type AuthMethod = gossh.AuthMethod

// KeyboardInteractiveChallenge is the callback used by the
// keyboard-interactive authentication method. It should print questions,
// optionally disabling echoing (e.g. for passwords), and return all the
// answers. The challenge may be called multiple times in a single session.
//
// RFC 4256 section 3.3 details how the UI should behave for both CLI and GUI
// environments.
type KeyboardInteractiveChallenge = gossh.KeyboardInteractiveChallenge

// Password returns an AuthMethod using the given password.
func Password(secret string) AuthMethod {
	return gossh.Password(secret)
}

// PasswordCallback returns an AuthMethod that uses a callback for fetching a
// password.
func PasswordCallback(prompt func() (secret string, err error)) AuthMethod {
	return gossh.PasswordCallback(prompt)
}

// PublicKeys returns an AuthMethod that uses the given key pairs.
func PublicKeys(signers ...Signer) AuthMethod {
	return gossh.PublicKeys(signers...)
}

// PublicKeysCallback returns an AuthMethod that runs the given function to
// obtain a list of key pairs.
func PublicKeysCallback(getSigners func() (signers []Signer, err error)) AuthMethod {
	return gossh.PublicKeysCallback(getSigners)
}

// KeyboardInteractive returns an AuthMethod using a prompt/response sequence
// controlled by the server.
func KeyboardInteractive(challenge KeyboardInteractiveChallenge) AuthMethod {
	return gossh.KeyboardInteractive(challenge)
}

// RetryableAuthMethod is a decorator for other auth methods enabling them to
// be retried up to maxTries before considering that AuthMethod itself failed.
// If maxTries is <= 0, it will retry indefinitely.
//
// This is useful for interactive clients using challenge/response type
// authentication (e.g. Keyboard-Interactive, Password, etc) where the user
// could mistype their response resulting in the server issuing a
// SSH_MSG_USERAUTH_FAILURE (RFC 4252 §8 [password] and RFC 4256 §3.4
// [keyboard-interactive]); without this decorator, the non-retryable
// AuthMethod would be removed from future consideration, and the user would
// never be able to retry their entry.
func RetryableAuthMethod(auth AuthMethod, maxTries int) AuthMethod {
	return gossh.RetryableAuthMethod(auth, maxTries)
}
