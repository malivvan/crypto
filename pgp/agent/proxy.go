package gpg

import (
	"errors"
	"net"
	"os"
	"strings"

	"github.com/malivvan/crypto/pgp/agent/client"
	"github.com/malivvan/crypto/pgp/agent/common"
)

// Dial connects an Assuan client to an existing agent socket (for example a
// running gpg-agent). It performs the Assuan initial handshake read and returns
// a ready client.Session whose Pipe is bound to the socket.
func Dial(socketPath string) (*client.Session, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	ses, err := client.Init(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ses, nil
}

// AgentSocketPath selects the standard gpg-agent control socket from the
// environment (GNUPGHOME/S.gpg-agent) when no explicit path is supplied.
func AgentSocketPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	gnupgHome := os.Getenv("GNUPGHOME")
	if gnupgHome == "" {
		if h, err := os.UserHomeDir(); err == nil {
			gnupgHome = h + "/.gnupg"
		} else {
			return "", err
		}
	}
	sock := gnupgHome + "/S.gpg-agent"
	if _, err := os.Stat(sock); err != nil {
		return "", err
	}
	return sock, nil
}

// ErrWouldForward is returned by LocalKeyguard / relays when a key is not held
// locally and no upstream session is configured.
var ErrWouldForward = errors.New("gpg: keygrip not held locally and no upstream agent configured")

// LocalKeyguard decides, from a parsed Assuan command, whether the command can
// be served entirely from the local keyring (true) or would need to be relayed
// to a remote agent (false). It is a small, compositional building block used
// by the merge mode described in README "Extending an existing agent".
//
// The rule is conservative: any command line that references a keygrip (its
// argument list) which the local keyring does not hold is treated as requiring
// the remote agent. Commands without keygrips (OPTION, NOP, RESET, BYE, ...)
// are always served locally.
func LocalKeyguard(kr *Keyring) func(cmd, params string) (local bool, err error) {
	return func(cmd, params string) (bool, error) {
		if kr == nil {
			return false, ErrWouldForward
		}
		switch cmd {
		case "HAVEKEY", "KEYINFO", "SIGKEY", "SETKEY":
			grips := strings.Fields(params)
			for _, g := range grips {
				if g[0] == '-' { // option flag on the candidate token (e.g. --list)
					continue
				}
				if !kr.Has(g) {
					return false, nil
				}
			}
			return true, nil
		default:
			return true, nil
		}
	}
}

// ReadAndRelay relays a single already-initiated Assuan request/response round
// trip from down (the local wire pipe, where we got cmd/params) on to the
// upstream session `up`. It answers the local client by copying upstream's
// reply bytes verbatim until the request terminates (OK or ERR), transparently
// passing any INQUIRE/D/END exchanges in both directions.
//
// The upstream must not be used concurrently: callers should serialize relay
// requests on a single upstream Session (see Proxy).
//
// ReadAndRelay returns nil on a clean OK/ERR termination.
func ReadAndRelay(down *common.Pipe, up *client.Session, cmd, params string) error {
	if err := up.Pipe.WriteLine(cmd, params); err != nil {
		return err
	}
	for {
		scmd, sparams, err := up.Pipe.ReadLine()
		if err != nil {
			return err
		}
		switch scmd {
		case "INQUIRE":
			// Ask the same keyword of the local client, forward its raw
			// D../END answer upstream, then resume.
			if err := down.WriteLine(scmd, sparams); err != nil {
				return err
			}
			if err := forwardClientBlock(down, &up.Pipe); err != nil {
				return err
			}
		case "OK", "ERR":
			// Terminal line is relayed verbatim (including code/params).
			if err := down.WriteLine(scmd, sparams); err != nil {
				return err
			}
			return nil
		default:
			// Status (S ...) and data (D ...) intermediate lines are relayed.
			if err := down.WriteLine(scmd, sparams); err != nil {
				return err
			}
		}
	}
}

// forwardClientBlock consumes the local client's D../END (or CAN) block that an
// upstream INQUIRE triggered and replays it, unmodified, to the upstream pipe.
// It stops at the terminating END (or CAN) line.
func forwardClientBlock(down *common.Pipe, up *common.Pipe) error {
	for {
		scmd, sparams, err := down.ReadLine()
		if err != nil {
			return err
		}
		if err := up.WriteLine(scmd, sparams); err != nil {
			return err
		}
		if scmd == "END" || scmd == "CAN" {
			return nil
		}
	}
}

var _ = common.New // keep import referencing common package in docs
