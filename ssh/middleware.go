package ssh

// Middleware is a function that takes an ssh.Handler and returns an
// ssh.Handler. Implementations should call the provided handler argument.
type Middleware func(next Handler) Handler
