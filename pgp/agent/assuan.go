package gpg

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/malivvan/crypto/pgp/agent/common"
	"github.com/malivvan/crypto/pgp/agent/server"
	"github.com/malivvan/crypto/x25519"
)

// Version reported by GETINFO version.
const Version = "0.1.0"

// sessionState carries per-connection session data used by the Assuan command
// handlers.
type sessionState struct {
	kr         *Keyring
	activeGrip string // keygrip selected by the most recent SIGKEY / SETKEY.
}

// ProtoInfo builds the Assuan command table that serves kr. A fresh
// sessionState is allocated per connection (GetDefaultState), so concurrent
// clients never share a "currently selected" key.
func ProtoInfo(kr *Keyring) server.ProtoInfo {
	if kr == nil {
		kr = NewKeyring()
	}
	return server.ProtoInfo{
		Greeting: "OpenPGP wallet agent v" + Version,
		GetDefaultState: func() interface{} {
			return &sessionState{kr: kr}
		},
		SetOption: func(_ interface{}, key, _ string) error {
			return &common.Error{
				Src: common.ErrSrcAssuan, Code: common.ErrNotImplemented,
				SrcName: "assuan", Message: "option not supported: " + key,
			}
		},
		Help: map[string][]string{
			"GETINFO":   {"return agent information: GETINFO [version|pid|socket_name]"},
			"HAVEKEY":   {"check presence of keygrips: HAVEKEY <grip> [<grip> ...]"},
			"KEYINFO":   {"list/query keys: KEYINFO [--list] [<grip>]"},
			"SIGKEY":    {"select signing key: SIGKEY <grip-hex>"},
			"SETKEY":    {"select working key: SETKEY <grip-hex>"},
			"PKSIGN":    {"sign the hash supplied over INQUIRE HASHVAL"},
			"PKDECRYPT": {"decrypt session key supplied over INQUIRE DATA (see README)"},
		},
		Handlers: map[string]server.CommandHandler{
			"GETINFO":   cmdGetinfo,
			"HAVEKEY":   cmdHavekey,
			"KEYINFO":   cmdKeyinfo,
			"SIGKEY":    cmdSelectKey,
			"SETKEY":    cmdSelectKey,
			"PKSIGN":    cmdPksign,
			"PKDECRYPT": cmdPkdecrypt,
		},
	}
}

func astate(state interface{}) *sessionState {
	if s, ok := state.(*sessionState); ok {
		return s
	}
	// The vendored assuan server passes the session state wrapped one level:
	// handlers receive *interface{} whose pointee is *sessionState. Unwrap.
	if w, ok := state.(*interface{}); ok && w != nil {
		if s, ok := (*w).(*sessionState); ok {
			return s
		}
	}
	return nil
}

// asReply uses the canonical server framing text helper functions below.

func cmdGetinfo(pipe *common.Pipe, state interface{}, params string) error {
	if astate(state) == nil {
		return stateErr()
	}
	switch strings.TrimSpace(params) {
	case "", "version":
		if params == "" {
			return nil
		}
		return writeHexData(pipe, []byte(Version))
	case "pid":
		return writeHexData(pipe, nil) // no own pid concept needed
	case "socket_name":
		return nil
	default:
		return protoErr(common.ErrNotFound, "unknown GETINFO token")
	}
}

// HAVEKEY <grip> [<grip> ...] — OK only when the agent holds every listed key.
func cmdHavekey(pipe *common.Pipe, state interface{}, params string) error {
	s := astate(state)
	if s == nil || s.kr == nil {
		return stateErr()
	}
	grips := strings.Fields(params)
	if len(grips) == 0 {
		return protoErr(common.ErrAssParameter, "HAVEKEY requires at least one keygrip")
	}
	for _, g := range grips {
		if !s.kr.Has(g) {
			return protoErr(common.ErrNoSeckey, "no secret key")
		}
	}
	return nil // framework writes OK
}

// SIGKEY / SETKEY <grip> select the working key for the connection.
func cmdSelectKey(pipe *common.Pipe, state interface{}, params string) error {
	s := astate(state)
	if s == nil || s.kr == nil {
		return stateErr()
	}
	grip := strings.TrimSpace(params)
	if grip == "" {
		return protoErr(common.ErrAssParameter, "missing keygrip")
	}
	if !s.kr.Has(grip) {
		return protoErr(common.ErrNoSeckey, "no such key")
	}
	s.activeGrip = grip
	return nil
}

// cmdKeyinfo implements the subset of gpg-agent KEYINFO we can faithfully
// answer: it prints one row per requested/listed key in the gpg column format.
func cmdKeyinfo(pipe *common.Pipe, state interface{}, params string) error {
	s := astate(state)
	if s == nil || s.kr == nil {
		return stateErr()
	}
	fields := strings.Fields(params)
	listAll := false
	var target string
	for _, f := range fields {
		switch {
		case strings.HasPrefix(f, "--"):
			listAll = true
		default:
			target = f
		}
	}

	emit := func(k *Key) error {
		return writeHexData(pipe, []byte(keyinfoRow(k, s.activeGrip)))
	}

	switch {
	case listAll:
		for _, k := range s.kr.List() {
			if err := emit(k); err != nil {
				return err
			}
		}
		return nil
	case target != "":
		k := s.kr.Get(target)
		if k == nil {
			return protoErr(common.ErrNoSeckey, "no such key")
		}
		return emit(k)
	default:
		if s.activeGrip == "" {
			return protoErr(common.ErrAssParameter, "no key selected (use --list or pass a keygrip)")
		}
		k := s.kr.Get(s.activeGrip)
		if k == nil {
			return stateErr()
		}
		return emit(k)
	}
}

// keyinfoRow emits a gpg-agent KEYINFO style row:
//
//	<keygrip> <type> <serialno> <idstr> <cached> <protection> <fpr> <card> <flags>
//
// <type>: D = decryption-capable entry, E = signing/encryption-capable per our
// role mapping (see README table). Fields that require data we do not keep
// (serial, cached passphrase, protection description, fingerprint, card) are
// emitted as "-" per GnuPG's empty-field convention, which keeps the row
// parseable by gpg-connect-agent KEYINFO consumers.
func keyinfoRow(k *Key, activeGrip string) string {
	ktype := "-"
	switch k.Role {
	case RoleSigning:
		ktype = "S"
	case RoleDecryption:
		ktype = "E"
	}
	flags := "-"
	if k.GripHex == activeGrip {
		flags = ">" // "currently used for this connection"
	}
	idstr := "-"
	if k.Tag != "" {
		idstr = k.Tag
	}
	return strings.Join([]string{
		k.GripHex, ktype, "-", idstr, "-", "-", "-", "-", flags,
	}, " ")
}

// cmdPksign signs the digest the client supplies. The flow is:
//
//   - the client must first select a signing key with SIGKEY <grip>;
//   - PKSIGN makes the server issue "INQUIRE HASHVAL", over which the client
//     sends D <hexdigest> ... END;
//   - the server signs those exact bytes with Ed25519 and returns the 64-byte
//     signature, hex-encoded, via a single D line; the framework appends OK.
func cmdPksign(pipe *common.Pipe, state interface{}, _ string) error {
	s := astate(state)
	if s == nil || s.kr == nil {
		return stateErr()
	}
	k, err := s.selected(s.kr, true)
	if err != nil {
		return err
	}
	digest, err := inquireHexData(pipe, "HASHVAL")
	if err != nil {
		return protoErr(common.ErrAssReadError, "reading hash: "+err.Error())
	}
	sig, err := signEd25519(k, digest)
	if err != nil {
		return protoErr(common.ErrGeneral, err.Error())
	}
	return writeHexData(pipe, sig)
}

// cmdPkdecrypt decrypts a session key the client supplies over INQUIRE DATA.
//
// The client sends a single D line carrying the two X25519 session-key cipher
// fields produced by the module's x25519 encryption ("\t"-separated, both
// hex-encoded):
//
//	ephemeral-public-key(32 bytes, hex)  encrypted-session-key(hex)
//
// with an immediate END. The server unwraps the session key and returns it as
// hex on one D line. This is the deterministic framing defined in the package
// README ("Protocol"); see that section for the exact GnuPG parity boundary.
func cmdPkdecrypt(pipe *common.Pipe, state interface{}, _ string) error {
	s := astate(state)
	if s == nil || s.kr == nil {
		return stateErr()
	}
	k, err := s.selected(s.kr, false)
	if err != nil {
		return err
	}
	payload, err := inquireHexData(pipe, "DATA")
	if err != nil {
		return protoErr(common.ErrAssReadError, "reading data: "+err.Error())
	}
	// Hex-decoded payload is: ephemeral(32) || encryptedSessionKey.
	if len(payload) < x25519.KeySize {
		return protoErr(common.ErrAssParameter, "payload too short for x25519 ephemeral key")
	}
	ephemeral := payload[:x25519.KeySize]
	ct := payload[x25519.KeySize:]
	if len(ct) == 0 {
		return protoErr(common.ErrAssParameter, "empty encrypted session key")
	}
	sk, err := x25519.Decrypt(k.X25519, ephemeral, ct)
	if err != nil {
		return protoErr(common.ErrDecryptFailed, "decrypt: "+err.Error())
	}
	return writeHexData(pipe, sk)
}

// selected returns the key named by the session activeGrip and checks it is of
// the requested role without exposing whether the active grip is set.
func (s *sessionState) selected(kr *Keyring, needSigning bool) (*Key, error) {
	if s.activeGrip == "" {
		return nil, protoErr(common.ErrAssParameter, "no key selected (use SIGKEY/SETKEY)")
	}
	k := kr.Get(s.activeGrip)
	if k == nil {
		return nil, protoErr(common.ErrNoSeckey, "no such key")
	}
	if needSigning && !k.HasSigningKey() {
		return nil, protoErr(common.ErrWrongKeyUsage, "key is not usable for signing")
	}
	if !needSigning && !k.HasDecryptionKey() {
		return nil, protoErr(common.ErrWrongKeyUsage, "key is not usable for decryption")
	}
	return k, nil
}

func stateErr() error {
	return errors.New("gpg: internal server state error")
}

func protoErr(code common.ErrorCode, msg string) error {
	return &common.Error{
		Src: common.ErrSrcGPG, Code: code, SrcName: "gpg", Message: msg,
	}
}

// writeHexData sends data as a single, lowercase hex D line.
func writeHexData(pipe *common.Pipe, data []byte) error {
	if data == nil {
		data = []byte{}
	}
	return pipe.WriteData([]byte(hex.EncodeToString(data)))
}

// inquireHexData asks the attached client for data under the given keyword and
// returns the hex-decoded bytes of the (single) D line it sent back. It maps
// the CAN/END framing returned by the underlying transport to a single error.
func inquireHexData(pipe *common.Pipe, keyword string) ([]byte, error) {
	if err := pipe.WriteLine("INQUIRE", keyword); err != nil {
		return nil, err
	}
	raw, err := pipe.ReadData()
	if err != nil {
		return nil, err
	}
	// The client sends one hex-encoded value.
	dec := make([]byte, hex.DecodedLen(len(raw)))
	n, derr := hex.Decode(dec, raw)
	if derr != nil {
		return nil, derr
	}
	return dec[:n], nil
}
