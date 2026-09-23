package ssh

import gossh "github.com/malivvan/crypto/ssh/internal"

// Signal represents a POSIX signal as specified in RFC 4254 Section 6.10.
type Signal = gossh.Signal

// POSIX signals as listed in RFC 4254 Section 6.10.
const (
	SIGABRT = gossh.SIGABRT
	SIGALRM = gossh.SIGALRM
	SIGFPE  = gossh.SIGFPE
	SIGHUP  = gossh.SIGHUP
	SIGILL  = gossh.SIGILL
	SIGINT  = gossh.SIGINT
	SIGKILL = gossh.SIGKILL
	SIGPIPE = gossh.SIGPIPE
	SIGQUIT = gossh.SIGQUIT
	SIGSEGV = gossh.SIGSEGV
	SIGTERM = gossh.SIGTERM
	SIGUSR1 = gossh.SIGUSR1
	SIGUSR2 = gossh.SIGUSR2
)

// A Channel is an ordered, reliable, flow-controlled, duplex stream that is
// carried over an SSH connection.
type Channel = gossh.Channel

// NewChannel represents an incoming request to a channel. It must either be
// accepted for use by calling Accept, or rejected by calling Reject.
type NewChannel = gossh.NewChannel

// Request is a request sent to a channel or a connection. The channel or
// connection's request stream must be serviced, or the peer will block.
type Request = gossh.Request

// Signature represents a cryptographic signature.
type Signature = gossh.Signature

// RejectionReason is an enumeration used when rejecting channel creation
// requests. See RFC 4254, section 5.1.
type RejectionReason = gossh.RejectionReason

// Channel rejection reasons, as defined in RFC 4254 section 5.1.
const (
	Prohibited         = gossh.Prohibited
	ConnectionFailed   = gossh.ConnectionFailed
	UnknownChannelType = gossh.UnknownChannelType
	ResourceShortage   = gossh.ResourceShortage
)

// DiscardRequests consumes and rejects all requests from the passed-in channel.
func DiscardRequests(in <-chan *Request) {
	gossh.DiscardRequests(in)
}

// Marshal serializes the message in msg to SSH wire format. The msg argument
// should be a struct or pointer to struct. If the first member has the
// "sshtype" tag set to a number in decimal, that number is prepended to the
// result. If the last member has the "ssh" tag set to "rest", its contents are
// appended to the output.
func Marshal(msg interface{}) []byte {
	return gossh.Marshal(msg)
}

// Unmarshal parses data in SSH wire format into a structure. The out argument
// should be a pointer to struct. If the first member of the struct has the
// "sshtype" tag set to a '|'-separated set of numbers in decimal, the packet
// must start with one of those numbers. Unmarshal returns an error if the data
// cannot be parsed or has trailing bytes.
func Unmarshal(data []byte, out interface{}) error {
	return gossh.Unmarshal(data, out)
}

// TerminalModes is a mapping of terminal mode opcode to value as they are
// exchanged in the pty-req request. See RFC 4254 section 8.
//
// The opcodes are the VINTR, VQUIT, ... constants declared in this package.
// Boolean opcodes have values 0 or 1.
type TerminalModes = gossh.TerminalModes

// POSIX terminal mode flags as listed in RFC 4254 Section 8.
const (
	VINTR         = gossh.VINTR
	VQUIT         = gossh.VQUIT
	VERASE        = gossh.VERASE
	VKILL         = gossh.VKILL
	VEOF          = gossh.VEOF
	VEOL          = gossh.VEOL
	VEOL2         = gossh.VEOL2
	VSTART        = gossh.VSTART
	VSTOP         = gossh.VSTOP
	VSUSP         = gossh.VSUSP
	VDSUSP        = gossh.VDSUSP
	VREPRINT      = gossh.VREPRINT
	VWERASE       = gossh.VWERASE
	VLNEXT        = gossh.VLNEXT
	VFLUSH        = gossh.VFLUSH
	VSWTCH        = gossh.VSWTCH
	VSTATUS       = gossh.VSTATUS
	VDISCARD      = gossh.VDISCARD
	IGNPAR        = gossh.IGNPAR
	PARMRK        = gossh.PARMRK
	INPCK         = gossh.INPCK
	ISTRIP        = gossh.ISTRIP
	INLCR         = gossh.INLCR
	IGNCR         = gossh.IGNCR
	ICRNL         = gossh.ICRNL
	IUCLC         = gossh.IUCLC
	IXON          = gossh.IXON
	IXANY         = gossh.IXANY
	IXOFF         = gossh.IXOFF
	IMAXBEL       = gossh.IMAXBEL
	IUTF8         = gossh.IUTF8 // RFC 8160
	ISIG          = gossh.ISIG
	ICANON        = gossh.ICANON
	XCASE         = gossh.XCASE
	ECHO          = gossh.ECHO
	ECHOE         = gossh.ECHOE
	ECHOK         = gossh.ECHOK
	ECHONL        = gossh.ECHONL
	NOFLSH        = gossh.NOFLSH
	TOSTOP        = gossh.TOSTOP
	IEXTEN        = gossh.IEXTEN
	ECHOCTL       = gossh.ECHOCTL
	ECHOKE        = gossh.ECHOKE
	PENDIN        = gossh.PENDIN
	OPOST         = gossh.OPOST
	OLCUC         = gossh.OLCUC
	ONLCR         = gossh.ONLCR
	OCRNL         = gossh.OCRNL
	ONOCR         = gossh.ONOCR
	ONLRET        = gossh.ONLRET
	CS7           = gossh.CS7
	CS8           = gossh.CS8
	PARENB        = gossh.PARENB
	PARODD        = gossh.PARODD
	TTY_OP_ISPEED = gossh.TTY_OP_ISPEED
	TTY_OP_OSPEED = gossh.TTY_OP_OSPEED
)
