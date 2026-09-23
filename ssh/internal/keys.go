// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	walleted "github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/pbkdf2"
)

// Public key algorithms names. These values can appear in PublicKey.Type,
// ClientConfig.HostKeyAlgorithms, Signature.Format, or as AlgorithmSigner
// arguments.
const (
	KeyAlgoED25519   = "ssh-ed25519"
	KeyAlgoSKED25519 = "sk-ssh-ed25519@openssh.com"
)

// parsePubKey parses a public key of the given algorithm.
// Use ParsePublicKey for keys with prepended algorithm.
func parsePubKey(in []byte, algo string) (pubKey PublicKey, rest []byte, err error) {
	switch algo {
	case KeyAlgoED25519:
		return parseED25519(in)
	case KeyAlgoSKED25519:
		return parseSKEd25519(in)
	case CertAlgoED25519v01, CertAlgoSKED25519v01:
		cert, err := parseCert(in, certKeyAlgoNames[algo])
		if err != nil {
			return nil, nil, err
		}
		return cert, nil, nil
	}
	if keyFormat := keyFormatForAlgorithm(algo); keyFormat != "" {
		return nil, nil, fmt.Errorf("ssh: signature algorithm %q isn't a key format; key is malformed and should be re-encoded with type %q",
			algo, keyFormat)
	}

	return nil, nil, fmt.Errorf("ssh: unknown key algorithm: %v", algo)
}

// parseAuthorizedKey parses a public key in OpenSSH authorized_keys format
// (see sshd(8) manual page) once the options and key type fields have been
// removed.
func parseAuthorizedKey(in []byte) (out PublicKey, comment string, err error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, "", err
	}
	key = key[:n]
	out, err = ParsePublicKey(key)
	if err != nil {
		return nil, "", err
	}
	comment = string(bytes.TrimSpace(in[i:]))
	return out, comment, nil
}

// ParseKnownHosts parses an entry in the format of the known_hosts file.
//
// The known_hosts format is documented in the sshd(8) manual page. This
// function will parse a single entry from in. On successful return, marker
// will contain the optional marker value (i.e. "cert-authority" or "revoked")
// or else be empty, hosts will contain the hosts that this entry matches,
// pubKey will contain the public key and comment will contain any trailing
// comment at the end of the line. See the sshd(8) manual page for the various
// forms that a host string can take.
//
// The unparsed remainder of the input will be returned in rest. This function
// can be called repeatedly to parse multiple entries.
//
// If no entries were found in the input then err will be io.EOF. Otherwise a
// non-nil err value indicates a parse error.
func ParseKnownHosts(in []byte) (marker string, hosts []string, pubKey PublicKey, comment string, rest []byte, err error) {
	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		// Strip out the beginning of the known_host key.
		// This is either an optional marker or a (set of) hostname(s).
		keyFields := bytes.Fields(in)
		if len(keyFields) < 3 || len(keyFields) > 5 {
			return "", nil, nil, "", nil, errors.New("ssh: invalid entry in known_hosts data")
		}

		// keyFields[0] is either "@cert-authority", "@revoked" or a comma separated
		// list of hosts
		marker := ""
		if keyFields[0][0] == '@' {
			marker = string(keyFields[0][1:])
			keyFields = keyFields[1:]
		}

		hosts := string(keyFields[0])
		// keyFields[1] contains the key type (e.g. "ssh-ed25519"). This
		// information is duplicated within the base64-encoded key blob. As
		// OpenSSH's sshkey_read does, we verify that the declared key type
		// matches the type embedded in the key blob.
		wantType := string(keyFields[1])

		key := bytes.Join(keyFields[2:], []byte(" "))
		if pubKey, comment, err = parseAuthorizedKey(key); err != nil {
			return "", nil, nil, "", nil, err
		}
		if pubKey.Type() != wantType {
			return "", nil, nil, "", nil, fmt.Errorf("ssh: known hosts key type mismatch: human-readable type %q, encoded type %q", wantType, pubKey.Type())
		}

		return marker, strings.Split(hosts, ","), pubKey, comment, rest, nil
	}

	return "", nil, nil, "", nil, io.EOF
}

// ParseAuthorizedKey parses a public key from an authorized_keys file used in
// OpenSSH according to the sshd(8) manual page. Invalid lines are ignored.
func ParseAuthorizedKey(in []byte) (out PublicKey, comment string, options []string, rest []byte, err error) {
	var lastErr error
	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if out, comment, err = parseAuthorizedKey(in[i:]); err == nil {
			// The first field contains the declared key type. As OpenSSH's
			// sshkey_read does, we verify that it matches the type embedded in
			// the key blob. Without this check, a single-token option (e.g.
			// "restrict") appearing in the key type position could be silently
			// discarded along with its intended effect.
			if string(in[:i]) == out.Type() {
				return out, comment, options, rest, nil
			}
			err = fmt.Errorf("ssh: authorized keys key type mismatch: human-readable type %q, encoded type %q", in[:i], out.Type())
		}
		lastErr = err

		// No key type recognised. Maybe there's an options field at
		// the beginning.
		var b byte
		inQuote := false
		var candidateOptions []string
		optionStart := 0
		for i, b = range in {
			isEnd := !inQuote && (b == ' ' || b == '\t')
			if (b == ',' && !inQuote) || isEnd {
				if i-optionStart > 0 {
					candidateOptions = append(candidateOptions, string(in[optionStart:i]))
				}
				optionStart = i + 1
			}
			if isEnd {
				break
			}
			if b == '"' && (i == 0 || (i > 0 && in[i-1] != '\\')) {
				inQuote = !inQuote
			}
		}
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i == len(in) {
			// Invalid line: unmatched quote
			in = rest
			continue
		}

		in = in[i:]
		i = bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if out, comment, err = parseAuthorizedKey(in[i:]); err == nil {
			// As above, the declared key type (here following the options
			// field) must match the type embedded in the key blob.
			if string(in[:i]) == out.Type() {
				options = candidateOptions
				return out, comment, options, rest, nil
			}
			err = fmt.Errorf("ssh: authorized keys key type mismatch: human-readable type %q, encoded type %q", in[:i], out.Type())
		}
		lastErr = err

		in = rest
		continue
	}

	if lastErr != nil {
		return nil, "", nil, nil, fmt.Errorf("ssh: no key found; last parsing error for ignored line: %w", lastErr)
	}

	return nil, "", nil, nil, errors.New("ssh: no key found")
}

// ParsePublicKey parses an SSH public key or certificate formatted for use in
// the SSH wire protocol according to RFC 4253, section 6.6.
func ParsePublicKey(in []byte) (out PublicKey, err error) {
	algo, in, ok := parseString(in)
	if !ok {
		return nil, errShortRead
	}
	var rest []byte
	out, rest, err = parsePubKey(in, string(algo))
	if len(rest) > 0 {
		return nil, errors.New("ssh: trailing junk in public key")
	}

	return out, err
}

// MarshalAuthorizedKey serializes key for inclusion in an OpenSSH
// authorized_keys file. The return value ends with newline.
func MarshalAuthorizedKey(key PublicKey) []byte {
	b := &bytes.Buffer{}
	b.WriteString(key.Type())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(key.Marshal())
	e.Close()
	b.WriteByte('\n')
	return b.Bytes()
}

// MarshalPrivateKey returns a PEM block with the private key serialized in the
// OpenSSH format.
func MarshalPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, unencryptedOpenSSHMarshaler)
}

// MarshalPrivateKeyWithPassphrase returns a PEM block holding the encrypted
// private key serialized in the OpenSSH format.
func MarshalPrivateKeyWithPassphrase(key crypto.PrivateKey, comment string, passphrase []byte) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, passphraseProtectedOpenSSHMarshaler(passphrase))
}

// PublicKey represents a public key using an unspecified algorithm.
//
// Some PublicKeys provided by this package also implement CryptoPublicKey.
type PublicKey interface {
	// Type returns the key format name, e.g. "ssh-ed25519".
	Type() string

	// Marshal returns the serialized key data in SSH wire format, with the name
	// prefix. To unmarshal the returned data, use the ParsePublicKey function.
	Marshal() []byte

	// Verify that sig is a signature on the given data using this key. This
	// method will hash the data appropriately first. sig.Format is allowed to
	// be any signature algorithm compatible with the key type, the caller
	// should check if it has more stringent requirements.
	Verify(data []byte, sig *Signature) error
}

// CryptoPublicKey, if implemented by a PublicKey,
// returns the underlying crypto.PublicKey form of the key.
type CryptoPublicKey interface {
	CryptoPublicKey() crypto.PublicKey
}

// A Signer can create signatures that verify against a public key.
//
// Some Signers provided by this package also implement MultiAlgorithmSigner.
type Signer interface {
	// PublicKey returns the associated PublicKey.
	PublicKey() PublicKey

	// Sign returns a signature for the given data. This method will hash the
	// data appropriately first. The signature algorithm is expected to match
	// the key format returned by the PublicKey.Type method (and not to be any
	// alternative algorithm supported by the key format).
	Sign(rand io.Reader, data []byte) (*Signature, error)
}

// An AlgorithmSigner is a Signer that also supports specifying an algorithm to
// use for signing.
//
// An AlgorithmSigner can't advertise the algorithms it supports, unless it also
// implements MultiAlgorithmSigner, so it should be prepared to be invoked with
// every algorithm supported by the public key format.
type AlgorithmSigner interface {
	Signer

	// SignWithAlgorithm is like Signer.Sign, but allows specifying a desired
	// signing algorithm. Callers may pass an empty string for the algorithm in
	// which case the AlgorithmSigner will use a default algorithm. This default
	// doesn't currently control any behavior in this package.
	SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*Signature, error)
}

// MultiAlgorithmSigner is an AlgorithmSigner that also reports the algorithms
// supported by that signer.
type MultiAlgorithmSigner interface {
	AlgorithmSigner

	// Algorithms returns the available algorithms in preference order. The list
	// must not be empty, and it must not include certificate types.
	Algorithms() []string
}

// NewSignerWithAlgorithms returns a signer restricted to the specified
// algorithms. The algorithms must be set in preference order. The list must not
// be empty, and it must not include certificate types. An error is returned if
// the specified algorithms are incompatible with the public key type.
func NewSignerWithAlgorithms(signer AlgorithmSigner, algorithms []string) (MultiAlgorithmSigner, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("ssh: please specify at least one valid signing algorithm")
	}
	var signerAlgos []string
	supportedAlgos := algorithmsForKeyFormat(underlyingAlgo(signer.PublicKey().Type()))
	if s, ok := signer.(*multiAlgorithmSigner); ok {
		signerAlgos = s.Algorithms()
	} else {
		signerAlgos = supportedAlgos
	}

	for _, algo := range algorithms {
		if !slices.Contains(supportedAlgos, algo) {
			return nil, fmt.Errorf("ssh: algorithm %q is not supported for key type %q",
				algo, signer.PublicKey().Type())
		}
		if !slices.Contains(signerAlgos, algo) {
			return nil, fmt.Errorf("ssh: algorithm %q is restricted for the provided signer", algo)
		}
	}
	return &multiAlgorithmSigner{
		AlgorithmSigner:     signer,
		supportedAlgorithms: algorithms,
	}, nil
}

type multiAlgorithmSigner struct {
	AlgorithmSigner
	supportedAlgorithms []string
}

func (s *multiAlgorithmSigner) Algorithms() []string {
	return s.supportedAlgorithms
}

func (s *multiAlgorithmSigner) isAlgorithmSupported(algorithm string) bool {
	if algorithm == "" {
		algorithm = underlyingAlgo(s.PublicKey().Type())
	}
	for _, algo := range s.supportedAlgorithms {
		if algorithm == algo {
			return true
		}
	}
	return false
}

func (s *multiAlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*Signature, error) {
	if !s.isAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("ssh: algorithm %q is not supported: %v", algorithm, s.supportedAlgorithms)
	}
	return s.AlgorithmSigner.SignWithAlgorithm(rand, data, algorithm)
}

type ed25519PublicKey ed25519.PublicKey

func (k ed25519PublicKey) Type() string {
	return KeyAlgoED25519
}

// parseED25519 parses an Ed25519 key according to RFC 8709.
func parseED25519(in []byte) (out PublicKey, rest []byte, err error) {
	var w struct {
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if l := len(w.KeyBytes); l != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid size %d for Ed25519 public key", l)
	}

	return ed25519PublicKey(w.KeyBytes), w.Rest, nil
}

func (k ed25519PublicKey) Marshal() []byte {
	w := struct {
		Name     string
		KeyBytes []byte
	}{
		KeyAlgoED25519,
		[]byte(k),
	}
	return Marshal(&w)
}

func (k ed25519PublicKey) Verify(b []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	if l := len(k); l != ed25519.PublicKeySize {
		return fmt.Errorf("invalid size %d for Ed25519 public key", l)
	}

	if ok := ed25519.Verify(ed25519.PublicKey(k), b, sig.Blob); !ok {
		return errors.New("ssh: signature did not verify")
	}

	return nil
}

func (k ed25519PublicKey) CryptoPublicKey() crypto.PublicKey {
	return ed25519.PublicKey(k)
}

type skFields struct {
	// Flags contains U2F/FIDO2 flags such as 'user present'
	Flags byte
	// Counter is a monotonic signature counter which can be
	// used to detect concurrent use of a private key, should
	// it be extracted from hardware.
	Counter uint32
}

// flagUserPresence is the "user present" bit (UP) in the SK signature
// flags, matching the FIDO CTAP2 authenticatorData UP flag. See
// openssh/PROTOCOL.u2f.
const flagUserPresence = 0x01

// errSKMissingUserPresence is returned by SK key Verify methods when
// the signature does not assert user presence and the key was not
// marked as no-touch-required.
var errSKMissingUserPresence = errors.New("ssh: signature missing required user presence flag")

type skEd25519PublicKey struct {
	// application is a URL-like string, typically "ssh:" for SSH.
	// see openssh/PROTOCOL.u2f for details.
	application string
	ed25519.PublicKey
	// noTouchRequired, when true, disables the default user-presence
	// check in Verify. It is set by skKeyWithoutUP on a clone of the
	// key, never on an instance shared across authentication attempts.
	noTouchRequired bool
}

func (k *skEd25519PublicKey) Type() string {
	return KeyAlgoSKED25519
}

func parseSKEd25519(in []byte) (out PublicKey, rest []byte, err error) {
	var w struct {
		KeyBytes    []byte
		Application string
		Rest        []byte `ssh:"rest"`
	}

	if err := Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if l := len(w.KeyBytes); l != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid size %d for Ed25519 public key", l)
	}

	key := new(skEd25519PublicKey)
	key.application = w.Application
	key.PublicKey = ed25519.PublicKey(w.KeyBytes)

	return key, w.Rest, nil
}

func (k *skEd25519PublicKey) Marshal() []byte {
	w := struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{
		KeyAlgoSKED25519,
		[]byte(k.PublicKey),
		k.application,
	}
	return Marshal(&w)
}

func (k *skEd25519PublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	if l := len(k.PublicKey); l != ed25519.PublicKeySize {
		return fmt.Errorf("invalid size %d for Ed25519 public key", l)
	}

	hash, err := hashFunc(sig.Format)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write([]byte(k.application))
	appDigest := h.Sum(nil)

	h.Reset()
	h.Write(data)
	dataDigest := h.Sum(nil)

	var edSig struct {
		Signature []byte `ssh:"rest"`
	}

	if err := Unmarshal(sig.Blob, &edSig); err != nil {
		return err
	}

	var skf skFields
	if err := Unmarshal(sig.Rest, &skf); err != nil {
		return err
	}

	if skf.Flags&flagUserPresence == 0 && !k.noTouchRequired {
		return errSKMissingUserPresence
	}

	blob := struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{
		appDigest,
		skf.Flags,
		skf.Counter,
		dataDigest,
	}

	original := Marshal(blob)

	if ok := ed25519.Verify(k.PublicKey, original, edSig.Signature); !ok {
		return errors.New("ssh: signature did not verify")
	}

	return nil
}

func (k *skEd25519PublicKey) CryptoPublicKey() crypto.PublicKey {
	return k.PublicKey
}

// NewSignerFromKey takes any crypto.Signer and returns a corresponding Signer
// instance.
func NewSignerFromKey(key interface{}) (Signer, error) {
	switch key := key.(type) {
	case crypto.Signer:
		return NewSignerFromSigner(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}

type wrappedSigner struct {
	signer crypto.Signer
	pubKey PublicKey
}

// NewSignerFromSigner takes any crypto.Signer implementation and
// returns a corresponding Signer interface. This can be used, for
// example, with keys kept in hardware modules.
func NewSignerFromSigner(signer crypto.Signer) (Signer, error) {
	pubKey, err := NewPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return &wrappedSigner{signer, pubKey}, nil
}

func (s *wrappedSigner) PublicKey() PublicKey {
	return s.pubKey
}

func (s *wrappedSigner) Sign(rand io.Reader, data []byte) (*Signature, error) {
	return s.SignWithAlgorithm(rand, data, s.pubKey.Type())
}

func (s *wrappedSigner) Algorithms() []string {
	return algorithmsForKeyFormat(s.pubKey.Type())
}

func (s *wrappedSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*Signature, error) {
	if algorithm == "" {
		algorithm = s.pubKey.Type()
	}

	if !slices.Contains(s.Algorithms(), algorithm) {
		return nil, fmt.Errorf("ssh: unsupported signature algorithm %q for key format %q", algorithm, s.pubKey.Type())
	}

	hashFunc, err := hashFunc(algorithm)
	if err != nil {
		return nil, err
	}
	var digest []byte
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(data)
		digest = h.Sum(nil)
	} else {
		digest = data
	}

	signature, err := s.signer.Sign(rand, digest, hashFunc)
	if err != nil {
		return nil, err
	}

	return &Signature{
		Format: algorithm,
		Blob:   signature,
	}, nil
}

// NewPublicKey takes an ed25519.PublicKey and returns a corresponding
// PublicKey instance.
func NewPublicKey(key interface{}) (PublicKey, error) {
	switch key := key.(type) {
	case ed25519.PublicKey:
		if l := len(key); l != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ssh: invalid size %d for Ed25519 public key", l)
		}
		return ed25519PublicKey(key), nil
	case *walleted.PublicKey:
		if l := len(key.Point); l != walleted.PublicKeySize {
			return nil, fmt.Errorf("ssh: invalid size %d for Ed25519 public key", l)
		}
		return ed25519PublicKey(append([]byte(nil), key.Point...)), nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}

// ParsePrivateKey returns a Signer from a PEM encoded private key. It supports
// the same keys as ParseRawPrivateKey. If the private key is encrypted, it
// will return a PassphraseMissingError.
func ParsePrivateKey(pemBytes []byte) (Signer, error) {
	key, err := ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return NewSignerFromKey(key)
}

// ParsePrivateKeyWithPassphrase returns a Signer from a PEM encoded private
// key and passphrase. It supports the same keys as
// ParseRawPrivateKeyWithPassphrase.
func ParsePrivateKeyWithPassphrase(pemBytes, passphrase []byte) (Signer, error) {
	key, err := ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	if err != nil {
		return nil, err
	}

	return NewSignerFromKey(key)
}

// encryptedBlock tells whether a private key is
// encrypted by examining its Proc-Type header
// for a mention of ENCRYPTED
// according to RFC 1421 Section 4.6.1.1.
func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

// A PassphraseMissingError indicates that parsing this private key requires a
// passphrase. Use ParsePrivateKeyWithPassphrase.
type PassphraseMissingError struct {
	// PublicKey will be set if the private key format includes an unencrypted
	// public key along with the encrypted private key.
	PublicKey PublicKey
}

func (*PassphraseMissingError) Error() string {
	return "ssh: this private key is passphrase protected"
}

// ParseRawPrivateKey returns a private key from a PEM encoded private key. It
// supports Ed25519 private keys in PKCS#8 and OpenSSH formats. If the private
// key is encrypted, it will return a PassphraseMissingError.
func ParseRawPrivateKey(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	if encryptedBlock(block) {
		return nil, &PassphraseMissingError{}
	}

	switch block.Type {
	// RFC5208 - https://tools.ietf.org/html/rfc5208
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return parseOpenSSHPrivateKey(block.Bytes, unencryptedOpenSSHKey)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

// ParseRawPrivateKeyWithPassphrase returns a private key decrypted with
// passphrase from a PEM encoded private key. If the passphrase is wrong, it
// will return x509.IncorrectPasswordError.
func ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	if block.Type == "OPENSSH PRIVATE KEY" {
		return parseOpenSSHPrivateKey(block.Bytes, passphraseProtectedOpenSSHKey(passphrase))
	}

	if !encryptedBlock(block) || !x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("ssh: not an encrypted key")
	}

	buf, err := x509.DecryptPEMBlock(block, passphrase)
	if err != nil {
		if err == x509.IncorrectPasswordError {
			return nil, err
		}
		return nil, fmt.Errorf("ssh: cannot decode encrypted private keys: %v", err)
	}

	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(buf)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func unencryptedOpenSSHKey(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error) {
	if kdfName != "none" || cipherName != "none" {
		return nil, &PassphraseMissingError{}
	}
	if kdfOpts != "" {
		return nil, errors.New("ssh: invalid openssh private key")
	}
	return privKeyBlock, nil
}

func passphraseProtectedOpenSSHKey(passphrase []byte) openSSHDecryptFunc {
	return func(cipherName, kdfName, kdfOpts string, privKeyBlock []byte) ([]byte, error) {
		if kdfName == "none" || cipherName == "none" {
			return nil, errors.New("ssh: key is not password protected")
		}
		if kdfName != "bcrypt" {
			return nil, fmt.Errorf("ssh: unknown KDF %q, only supports %q", kdfName, "bcrypt")
		}

		var opts struct {
			Salt   string
			Rounds uint32
		}
		if err := Unmarshal([]byte(kdfOpts), &opts); err != nil {
			return nil, err
		}

		// OpenSSH does not impose an upper bound on the bcrypt round count
		// stored in the key file, but bcrypt_pbkdf cost is linear in rounds:
		// the default is 16, ssh-keygen lets users pick anything up to
		// INT_MAX. Cap at 2048 (128x the default, a few seconds of CPU) so
		// that an oversized value in the file cannot tie up the caller for
		// months.
		const maxRounds = 1 << 11
		if opts.Rounds > maxRounds {
			return nil, fmt.Errorf("ssh: bcrypt KDF rounds %d exceed maximum %d", opts.Rounds, maxRounds)
		}

		k, err := pbkdf2.KeyBcrypt(passphrase, []byte(opts.Salt), int(opts.Rounds), 32+16)
		if err != nil {
			return nil, err
		}
		key, iv := k[:32], k[32:]

		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch cipherName {
		case "aes256-ctr":
			ctr := cipher.NewCTR(c, iv)
			ctr.XORKeyStream(privKeyBlock, privKeyBlock)
		case "aes256-cbc":
			if len(privKeyBlock)%c.BlockSize() != 0 {
				return nil, fmt.Errorf("ssh: invalid encrypted private key length, not a multiple of the block size")
			}
			cbc := cipher.NewCBCDecrypter(c, iv)
			cbc.CryptBlocks(privKeyBlock, privKeyBlock)
		default:
			return nil, fmt.Errorf("ssh: unknown cipher %q, only supports %q or %q", cipherName, "aes256-ctr", "aes256-cbc")
		}

		return privKeyBlock, nil
	}
}

func unencryptedOpenSSHMarshaler(privKeyBlock []byte) ([]byte, string, string, string, error) {
	key := generateOpenSSHPadding(privKeyBlock, 8)
	return key, "none", "none", "", nil
}

func passphraseProtectedOpenSSHMarshaler(passphrase []byte) openSSHEncryptFunc {
	return func(privKeyBlock []byte) ([]byte, string, string, string, error) {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, "", "", "", err
		}

		opts := struct {
			Salt   []byte
			Rounds uint32
		}{salt, 16}

		// Derive key to encrypt the private key block.
		k, err := pbkdf2.KeyBcrypt(passphrase, salt, int(opts.Rounds), 32+aes.BlockSize)
		if err != nil {
			return nil, "", "", "", err
		}

		// Add padding matching the block size of AES.
		keyBlock := generateOpenSSHPadding(privKeyBlock, aes.BlockSize)

		// Encrypt the private key using the derived secret.

		dst := make([]byte, len(keyBlock))
		key, iv := k[:32], k[32:]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, "", "", "", err
		}

		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(dst, keyBlock)

		return dst, "aes256-ctr", "bcrypt", string(Marshal(opts)), nil
	}
}

const privateKeyAuthMagic = "openssh-key-v1\x00"

type openSSHDecryptFunc func(CipherName, KdfName, KdfOpts string, PrivKeyBlock []byte) ([]byte, error)
type openSSHEncryptFunc func(PrivKeyBlock []byte) (ProtectedKeyBlock []byte, cipherName, kdfName, kdfOptions string, err error)

type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	Rest         []byte `ssh:"rest"`
}

type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type openSSHEd25519PrivateKey struct {
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}

// parseOpenSSHPrivateKey parses an OpenSSH private key, using the decrypt
// function to unwrap the encrypted portion. unencryptedOpenSSHKey can be used
// as the decrypt function to parse an unencrypted private key. See
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key.
func parseOpenSSHPrivateKey(key []byte, decrypt openSSHDecryptFunc) (crypto.PrivateKey, error) {
	if len(key) < len(privateKeyAuthMagic) || string(key[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil, errors.New("ssh: invalid openssh private key format")
	}
	remaining := key[len(privateKeyAuthMagic):]

	var w openSSHEncryptedPrivateKey
	if err := Unmarshal(remaining, &w); err != nil {
		return nil, err
	}
	if w.NumKeys != 1 {
		// We only support single key files, and so does OpenSSH.
		// https://github.com/openssh/openssh-portable/blob/4103a3ec7/sshkey.c#L4171
		return nil, errors.New("ssh: multi-key files are not supported")
	}

	privKeyBlock, err := decrypt(w.CipherName, w.KdfName, w.KdfOpts, w.PrivKeyBlock)
	if err != nil {
		if err, ok := err.(*PassphraseMissingError); ok {
			pub, errPub := ParsePublicKey(w.PubKey)
			if errPub != nil {
				return nil, fmt.Errorf("ssh: failed to parse embedded public key: %v", errPub)
			}
			err.PublicKey = pub
		}
		return nil, err
	}

	var pk1 openSSHPrivateKey
	if err := Unmarshal(privKeyBlock, &pk1); err != nil || pk1.Check1 != pk1.Check2 {
		if w.CipherName != "none" {
			return nil, x509.IncorrectPasswordError
		}
		return nil, errors.New("ssh: malformed OpenSSH key")
	}

	switch pk1.Keytype {
	case KeyAlgoED25519:
		var key openSSHEd25519PrivateKey
		if err := Unmarshal(pk1.Rest, &key); err != nil {
			return nil, err
		}

		if len(key.Priv) != ed25519.PrivateKeySize {
			return nil, errors.New("ssh: private key unexpected length")
		}

		if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
			return nil, err
		}

		pk := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
		copy(pk, key.Priv)
		return &pk, nil
	default:
		return nil, errors.New("ssh: unhandled key type")
	}
}

func marshalOpenSSHPrivateKey(key crypto.PrivateKey, comment string, encrypt openSSHEncryptFunc) (*pem.Block, error) {
	var w openSSHEncryptedPrivateKey
	var pk1 openSSHPrivateKey

	// Random check bytes.
	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, err
	}

	pk1.Check1 = check
	pk1.Check2 = check
	w.NumKeys = 1

	// Use a []byte directly on ed25519 keys.
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		pub := make([]byte, ed25519.PublicKeySize)
		priv := make([]byte, ed25519.PrivateKeySize)
		copy(pub, k[32:])
		copy(priv, k)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Pub     []byte
		}{
			KeyAlgoED25519, pub,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHEd25519PrivateKey{
			Pub:     pub,
			Priv:    priv,
			Comment: comment,
		}
		pk1.Keytype = KeyAlgoED25519
		pk1.Rest = Marshal(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}

	var err error
	// Add padding and encrypt the key if necessary.
	w.PrivKeyBlock, w.CipherName, w.KdfName, w.KdfOpts, err = encrypt(Marshal(pk1))
	if err != nil {
		return nil, err
	}

	b := Marshal(w)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(privateKeyAuthMagic), b...),
	}
	return block, nil
}

func checkOpenSSHKeyPadding(pad []byte) error {
	for i, b := range pad {
		if int(b) != i+1 {
			return errors.New("ssh: padding not as expected")
		}
	}
	return nil
}

func generateOpenSSHPadding(block []byte, blockSize int) []byte {
	for i, l := 0, len(block); (l+i)%blockSize != 0; i++ {
		block = append(block, byte(i+1))
	}
	return block
}

// FingerprintLegacyMD5 returns the user presentation of the key's
// fingerprint as described by RFC 4716 section 4.
func FingerprintLegacyMD5(pubKey PublicKey) string {
	md5sum := md5.Sum(pubKey.Marshal())
	hexarray := make([]string, len(md5sum))
	for i, c := range md5sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(hexarray, ":")
}

// FingerprintSHA256 returns the user presentation of the key's
// fingerprint as unpadded base64 encoded sha256 hash.
// This format was introduced from OpenSSH 6.8.
// https://www.openssh.com/txt/release-6.8
// https://tools.ietf.org/html/rfc4648#section-3.2 (unpadded base64 encoding)
func FingerprintSHA256(pubKey PublicKey) string {
	sha256sum := sha256.Sum256(pubKey.Marshal())
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return "SHA256:" + hash
}
