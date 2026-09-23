package ssh

import gossh "github.com/malivvan/crypto/ssh/internal"

// Certificate algorithm names. These values can appear in Certificate.Type,
// PublicKey.Type, ClientConfig.HostKeyAlgorithms and Signature.Format.
// Unlike key algorithm names, these are not passed to AlgorithmSigner nor
// returned by MultiAlgorithmSigner.
const (
	CertAlgoED25519v01   = gossh.CertAlgoED25519v01
	CertAlgoSKED25519v01 = gossh.CertAlgoSKED25519v01
)

// Certificate types distinguish between host and user certificates.
// The values can be set in the CertType field of Certificate.
const (
	UserCert = gossh.UserCert
	HostCert = gossh.HostCert
)

// CertTimeInfinity can be used for Certificate.ValidBefore to indicate that a
// certificate does not expire.
const CertTimeInfinity = gossh.CertTimeInfinity

// A Certificate represents an OpenSSH certificate as defined in
// [PROTOCOL.certkeys]. The Certificate type implements the PublicKey
// interface, so it can be unmarshaled using ParsePublicKey. It is an alias of
// the protocol implementation's type.
type Certificate = gossh.Certificate

// CertChecker does the work of verifying a certificate. Its methods can be
// plugged into ClientConfig.HostKeyCallback and ServerConfig.PublicKeyCallback.
// For the CertChecker to work, minimally, the IsAuthority callback should be
// set.
type CertChecker = gossh.CertChecker
