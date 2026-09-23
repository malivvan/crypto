package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"

	gossh "github.com/malivvan/crypto/ssh/internal"
)

// generateSigner generates a default host signer: an ed25519 host certificate
// that is self-signed with the same ed25519 key. The certificate is only
// generated for the host key algorithms this package supports
// (ssh-ed25519-cert-v01@openssh.com and sk-ssh-ed25519-cert-v01@openssh.com).
func generateSigner() (gossh.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cert := &gossh.Certificate{
		Key:         signer.PublicKey(),
		Serial:      0,
		CertType:    gossh.HostCert,
		KeyId:       "generated",
		ValidAfter:  0,
		ValidBefore: gossh.CertTimeInfinity,
		// No ValidPrincipals means the certificate is valid for all hosts.
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return gossh.NewCertSigner(cert, signer)
}

func parsePtyRequest(payload []byte) (pty Pty, ok bool) {
	// From https://datatracker.ietf.org/doc/html/rfc4254
	// 6.2.  Requesting a Pseudo-Terminal
	// A pseudo-terminal can be allocated for the session by sending the
	// following message.
	//    byte      SSH_MSG_CHANNEL_REQUEST
	//    uint32    recipient channel
	//    string    "ptyallocate-req"
	//    boolean   want_reply
	//    string    TERM environment variable value (e.g., vt100)
	//    uint32    terminal width, characters (e.g., 80)
	//    uint32    terminal height, rows (e.g., 24)
	//    uint32    terminal width, pixels (e.g., 640)
	//    uint32    terminal height, pixels (e.g., 480)
	//    string    encoded terminal modes

	// The payload starts from the TERM variable.
	term, rem, ok := parseString(payload)
	if !ok {
		return pty, ok
	}
	win, rem, ok := parseWindow(rem)
	if !ok {
		return pty, ok
	}
	modes, ok := parseTerminalModes(rem)
	if !ok {
		return pty, ok
	}
	pty = Pty{
		Term:   term,
		Window: win,
		Modes:  modes,
	}
	return pty, ok
}

func parseTerminalModes(in []byte) (modes gossh.TerminalModes, ok bool) {
	// From https://datatracker.ietf.org/doc/html/rfc4254
	// 8.  Encoding of Terminal Modes
	//
	//  All 'encoded terminal modes' (as passed in a ptyallocate request) are encoded
	//  into a byte stream.  It is intended that the coding be portable
	//  across different environments.  The stream consists of opcode-
	//  argument pairs wherein the opcode is a byte value.  Opcodes 1 to 159
	//  have a single uint32 argument.  Opcodes 160 to 255 are not yet
	//  defined, and cause parsing to stop (they should only be used after
	//  any other data).  The stream is terminated by opcode TTY_OP_END
	//  (0x00).
	//
	//  The client SHOULD put any modes it knows about in the stream, and the
	//  server MAY ignore any modes it does not know about.  This allows some
	//  degree of machine-independence, at least between systems that use a
	//  POSIX-like tty interface.  The protocol can support other systems as
	//  well, but the client may need to fill reasonable values for a number
	//  of parameters so the server ptyallocate gets set to a reasonable mode (the
	//  server leaves all unspecified mode bits in their default values, and
	//  only some combinations make sense).
	_, rem, ok := parseUint32(in)
	if !ok {
		return modes, ok
	}
	const ttyOpEnd = 0
	for len(rem) > 0 {
		if modes == nil {
			modes = make(gossh.TerminalModes)
		}
		code := rem[0]
		rem = rem[1:]
		if code == ttyOpEnd || code > 160 {
			break
		}
		var val uint32
		val, rem, ok = parseUint32(rem)
		if !ok {
			return modes, ok
		}
		modes[code] = val
	}
	ok = true
	return modes, ok
}

func parseWindow(s []byte) (win Window, rem []byte, ok bool) {
	// 6.7.  Window Dimension Change Message
	// When the window (terminal) size changes on the client side, it MAY
	// send a message to the other side to inform it of the new dimensions.

	//   byte      SSH_MSG_CHANNEL_REQUEST
	//   uint32    recipient channel
	//   string    "window-change"
	//   boolean   FALSE
	//   uint32    terminal width, columns
	//   uint32    terminal height, rows
	//   uint32    terminal width, pixels
	//   uint32    terminal height, pixels
	wCols, rem, ok := parseUint32(s)
	if !ok {
		return win, rem, ok
	}
	hRows, rem, ok := parseUint32(rem)
	if !ok {
		return win, rem, ok
	}
	wPixels, rem, ok := parseUint32(rem)
	if !ok {
		return win, rem, ok
	}
	hPixels, rem, ok := parseUint32(rem)
	if !ok {
		return win, rem, ok
	}
	win = Window{
		Width:        int(wCols),
		Height:       int(hRows),
		WidthPixels:  int(wPixels),
		HeightPixels: int(hPixels),
	}
	return win, rem, ok
}

func parseString(in []byte) (out string, rem []byte, ok bool) {
	length, rem, ok := parseUint32(in)
	if uint32(len(rem)) < length || !ok { //nolint:gosec // length is bounded by the input size
		ok = false
		return
	}
	out, rem = string(rem[:length]), rem[length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}
