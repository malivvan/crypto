// This file carries the selectable protocol surface of the ssh/agent
// sub-package into package agent: the protocol types and entry points Agent,
// ExtendedAgent, Key, AddedKey, SignatureFlags, ConstraintExtension,
// NewClient, NewKeyring and ServeAgent.
//
// The wallet's SSH stack is Ed25519-only, so this port serves only ssh-ed25519
// keys. The RSA/DSA/ECDSA/certificate pathways of the original ssh/agent and
// its dependency on the (now stripped) SSH *client* stack are dropped.
// Identities are addressed by their standard "ssh-ed25519"+point public blob,
// and Sign returns the raw 64-byte Ed25519 signature, so interoperability with
// OpenSSH agent peers on the wire is preserved.
package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/malivvan/crypto/ed25519"
)

// SignatureFlags hold additional flags passed to a signature request
// (PROTOCOL.agent section 4.5.1). ssh-ed25519 ignores the flag bits.
type SignatureFlags uint32

// Protocol signature-flag bit positions, kept so callers can round-trip the
// standard flag word; only SignatureFlagReserved (zero) applies to ed25519.
const (
	SignatureFlagReserved SignatureFlags = 1 << iota
	SignatureFlagRsaSha256
	SignatureFlagRsaSha512
)

// Key is one ssh-agent identity advertised by Agent.List.
type Key struct {
	// Format is the key algorithm name, here always "ssh-ed25519".
	Format string
	// Blob is the marshalled public key ("ssh-ed25519" then the 32-byte point).
	Blob []byte
	// Comment is the free-form comment attached to the identity.
	Comment string
}

func (k *Key) String() string {
	if k == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s %x %s", k.Format, k.Blob, k.Comment)
}

// AddedKey describes an ssh-ed25519 key to insert into an Agent keyring.
type AddedKey struct {
	// Seed is the 32-byte Ed25519 seed of the key to add.
	Seed []byte
	// Comment is an optional label for the identity.
	Comment string
	// LifetimeSecs, when non-zero, asks the agent to expire the key after this
	// many seconds.
	LifetimeSecs uint32
	// ConfirmBeforeUse requests interactive confirmation on each use; the
	// wallet agent refuses these keys.
	ConfirmBeforeUse bool
	// ConstraintExtensions are reserved protocol constraints; the wallet
	// agent refuses keys carrying them.
	ConstraintExtensions []ConstraintExtension
}

// ConstraintExtension describes an opaque ssh-agent key constraint extension
// (PROTOCOL.agent 4.7). Present for API compatibility; unsupported by the
// wallet for ssh-ed25519 keys.
type ConstraintExtension struct {
	ExtensionName    string
	ExtensionDetails []byte
}

// Agent is the interface implemented by ssh-agent endpoints that can list,
// sign and manage Ed25519 identities.
type Agent interface {
	// List returns the identities currently advertised by the agent.
	List() ([]*Key, error)
	// Sign has the agent sign data with the key whose public blob is pub,
	// returning the raw 64-byte Ed25519 signature.
	Sign(pub []byte, data []byte) ([]byte, error)
	// Add inserts an Ed25519 key into the agent keyring.
	Add(key AddedKey) error
	// Remove removes the identity whose public blob is pub.
	Remove(pub []byte) error
	// RemoveAll removes every identity.
	RemoveAll() error
}

// ExtendedAgent augments Agent with a flag-aware signer plus lock/unlock,
// mirroring the extended OpenSSH agent interface.
type ExtendedAgent interface {
	Agent
	// SignWithFlags behaves like Sign, forwarding the flag word; ssh-ed25519
	// ignores non-default flags.
	SignWithFlags(pub []byte, data []byte, flags SignatureFlags) ([]byte, error)
	// Lock disables signing and empties List until Unlock.
	Lock(passphrase []byte) error
	// Unlock re-enables a locked agent.
	Unlock(passphrase []byte) error
}

var _ ExtendedAgent = &keyringAgent{}
var _ Agent = &keyringAgent{}
var _ ExtendedAgent = &wireClient{}

func errUnsupported(what string) error {
	return fmt.Errorf("sshagent: %s unsupported for ssh-ed25519 keys", what)
}

// error helpers used by both the keyring and wire agent.
var (
	errKeyNotHeld = errors.New("sshagent: identity not held by agent")
)

// ---------------------------------------------------------------------------
// In-memory keyring agent (NewKeyring).
// ---------------------------------------------------------------------------

type keyringAgent struct {
	mu   sync.RWMutex
	keys []*ServerKey // wallets Ed25519 server-key container reused for signing
	lk   *lockingState
}

type lockingState struct {
	locked     bool
	passphrase []byte
}

var errLockedAgent = errors.New("sshagent: agent is locked")

// NewKeyring returns an in-memory Ed25519-only Agent, safe for concurrent use.
// It is the ported counterpart of the original ssh-agent in-memory keyring.
func NewKeyring() ExtendedAgent {
	return &keyringAgent{}
}

func (k *keyringAgent) List() ([]*Key, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.lk != nil && k.lk.locked {
		return nil, nil // empty list while locked (PROTOCOL.agent 2.7)
	}
	out := make([]*Key, 0, len(k.keys))
	for _, s := range k.keys {
		k := Key{Format: KeyAlgoED25519}
		id, err := s.Identity()
		if err != nil {
			return nil, err
		}
		k.Blob = id.Blob
		k.Comment = id.Comment
		out = append(out, &k)
	}
	return out, nil
}

func (k *keyringAgent) find(pub []byte) *ServerKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, s := range k.keys {
		if bytes.Equal(s.Public(), matchPoint(pub)) {
			return s
		}
	}
	return nil
}

// matchPoint normalises a key argument to its 32-byte point, accepting either a
// full "ssh-ed25519"+point blob or a bare point.
func matchPoint(pub []byte) []byte {
	if len(pub) == ed25519.PublicKeySize {
		return pub
	}
	if p, err := parsePubBlob(pub); err == nil {
		return p
	}
	return nil
}

func (k *keyringAgent) Sign(pub []byte, data []byte) ([]byte, error) {
	return k.SignWithFlags(pub, data, 0)
}

func (k *keyringAgent) SignWithFlags(pub []byte, data []byte, _ SignatureFlags) ([]byte, error) {
	if k.locked() {
		return nil, errLockedAgent
	}
	sk := k.find(pub)
	if sk == nil {
		return nil, errKeyNotHeld
	}
	return ed25519.Sign(sk.Priv, data)
}

func (k *keyringAgent) Add(key AddedKey) error {
	if k.locked() {
		return errLockedAgent
	}
	if key.ConfirmBeforeUse {
		return errUnsupported("ConfirmBeforeUse")
	}
	if len(key.ConstraintExtensions) > 0 {
		return errUnsupported("constraint extensions")
	}
	priv, err := ed25519.GenerateKeyFromSeed(key.Seed)
	if err != nil {
		return fmt.Errorf("sshagent: bad seed: %w", err)
	}
	sk := &ServerKey{Priv: priv, Comment: key.Comment}
	k.mu.Lock()
	for i, s := range k.keys {
		if string(s.Public()) == string(sk.Public()) {
			k.keys[i] = sk
			k.mu.Unlock()
			return nil
		}
	}
	k.keys = append(k.keys, sk)
	k.mu.Unlock()

	if key.LifetimeSecs > 0 {
		go k.expireAfter(sk.Public(), time.Duration(key.LifetimeSecs)*time.Second)
	}
	return nil
}

func (k *keyringAgent) expireAfter(pub []byte, d time.Duration) {
	time.Sleep(d)
	k.Remove(pub)
}

func (k *keyringAgent) Remove(pub []byte) error {
	if k.locked() {
		return errLockedAgent
	}
	want := matchPoint(pub)
	if want == nil {
		return errKeyNotHeld
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := 0; i < len(k.keys); {
		if bytes.Equal(k.keys[i].Public(), want) {
			k.keys[i] = k.keys[len(k.keys)-1]
			k.keys = k.keys[:len(k.keys)-1]
			return nil
		}
		i++
	}
	return errKeyNotHeld
}

func (k *keyringAgent) RemoveAll() error {
	if k.locked() {
		return errLockedAgent
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys = nil
	return nil
}

func (k *keyringAgent) locked() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.lk != nil && k.lk.locked
}

func (k *keyringAgent) Lock(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.lk != nil && k.lk.locked {
		return errLockedAgent
	}
	k.lk = &lockingState{locked: true, passphrase: passphrase}
	return nil
}

func (k *keyringAgent) Unlock(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.lk == nil || !k.lk.locked {
		return errors.New("sshagent: agent is not locked")
	}
	if string(passphrase) != string(k.lk.passphrase) {
		return errors.New("sshagent: incorrect passphrase")
	}
	k.lk.locked = false
	k.lk.passphrase = nil
	return nil
}

// ---------------------------------------------------------------------------
// Wire client (NewClient) and server loop (ServeAgent).
// ---------------------------------------------------------------------------

// wireClient implements ExtendedAgent over a framed io.ReadWriter carrying the
// OpenSSH agent protocol subset (identities + sign + remove/lock on the server
// side handled by ServeAgent).
type wireClient struct {
	rw io.ReadWriter
	mu sync.Mutex // serializes request/response frames
}

// NewClient returns an ExtendedAgent that talks to an ssh-agent over rw (for
// example *net.UnixConn, net.Pipe, or any io.ReadWriteCloser speaking the
// OpenSSH agent frame protocol).
func NewClient(rw io.ReadWriter) ExtendedAgent {
	return &wireClient{rw: rw}
}

func (c *wireClient) roundtrip(msgType byte, body []byte) (byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writePacket(c.rw, msgType, body); err != nil {
		return 0, nil, err
	}
	t, payload, err := parseMessage(c.rw)
	if err != nil {
		return 0, nil, err
	}
	return t, payload, nil
}

// writePacket writes one length-prefixed frame to w.
func writePacket(w io.Writer, msgType byte, body []byte) error {
	_, err := w.Write(encodeMessage(msgType, body))
	return err
}

func (c *wireClient) List() ([]*Key, error) {
	t, payload, err := c.roundtrip(agentRequestIdentities, nil)
	if err != nil {
		return nil, err
	}
	if t != agentIdentitiesAnswer {
		return nil, errors.New("sshagent: unexpected reply to identities request")
	}
	if len(payload) < 4 {
		return nil, ErrMalformedRequest
	}
	n := readBE32(payload)
	rest := payload[4:]
	out := make([]*Key, 0, n)
	for i := uint32(0); i < n; i++ {
		blob, r1, ok := takeString(rest)
		if !ok {
			return nil, ErrMalformedRequest
		}
		comment, r2, ok := takeString(r1)
		if !ok {
			return nil, ErrMalformedRequest
		}
		rest = r2
		kw := Key{}
		if !isEDKeyBlob(blob) {
			return nil, ErrMalformedRequest
		}
		kw.Format = KeyAlgoED25519
		kw.Blob = blob
		kw.Comment = string(comment)
		out = append(out, &kw)
	}
	return out, nil
}

func isEDKeyBlob(blob []byte) bool {
	algo, _, err := readString(blob)
	return err == nil && string(algo) == KeyAlgoED25519
}

func (c *wireClient) Sign(pub []byte, data []byte) ([]byte, error) {
	return c.SignWithFlags(pub, data, 0)
}

func (c *wireClient) SignWithFlags(pub []byte, data []byte, _ SignatureFlags) ([]byte, error) {
	body := writeString(nil, pub)
	body = writeString(body, data)
	body = append(body, 0, 0, 0, 0) // 4-byte flag word
	t, payload, err := c.roundtrip(agentSignRequest, body)
	if err != nil {
		return nil, err
	}
	if t != agentSignResponse {
		return nil, errors.New("sshagent: agent refused signature request")
	}
	outer, _, ok := takeString(payload)
	if !ok {
		return nil, ErrMalformedRequest
	}
	sigAlgo, inner, _ := takeString(outer)
	if string(sigAlgo) != KeyAlgoED25519 {
		return nil, ErrMalformedRequest
	}
	raw, _, ok := takeString(inner)
	if !ok {
		return nil, ErrMalformedRequest
	}
	return raw, nil
}

func (c *wireClient) Remove(pub []byte) error {
	body := writeString(nil, pub)
	return c.expectSuccess(agentRemoveIdentity, body)
}

func (c *wireClient) RemoveAll() error {
	return c.expectSuccess(agentRemoveAllIdentities, nil)
}

func (c *wireClient) Add(AddedKey) error {
	// Keys must be added in the process that owns their material; the wallet
	// does not push private seeds over the wire.
	return errUnsupported("Add over the wire")
}

func (c *wireClient) expectSuccess(msgType byte, body []byte) error {
	t, _, err := c.roundtrip(msgType, body)
	if err != nil {
		return err
	}
	if t != agentSuccess {
		return errors.New("sshagent: agent refused request")
	}
	return nil
}

func (c *wireClient) Lock(passphrase []byte) error {
	return c.expectSuccess(agentLock, writeString(nil, passphrase))
}

func (c *wireClient) Unlock(passphrase []byte) error {
	return c.expectSuccess(agentUnlock, writeString(nil, passphrase))
}

// ServeAgent serves the Ed25519 subset of the OpenSSH agent protocol on rw
// until the peer closes it, dispatching to the given Agent. Requests outside
// the supported subset (add/lock/remove of non-held keys) yield SSH_AGENT_FAILURE.
func ServeAgent(a Agent, rw io.ReadWriter) error {
	for {
		msgType, payload, err := parseMessage(rw)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		replyType, body := serve(a, msgType, payload)
		if err := writePacket(rw, replyType, body); err != nil {
			return err
		}
	}
}

func serve(a Agent, msgType byte, payload []byte) (byte, []byte) {
	switch msgType {
	case agentRequestIdentities: // SSH2_AGENTC_REQUEST_IDENTITIES
		keys, err := a.List()
		if err != nil {
			return agentFailure, nil
		}
		return agentIdentitiesAnswer, identitiesBody(keys)

	case agentSignRequest: // SSH2_AGENTC_SIGN_REQUEST
		keyInfo, rest, err := readString(payload)
		if err != nil {
			return agentFailure, nil
		}
		data, _, err := readString(rest)
		if err != nil {
			return agentFailure, nil
		}
		pub, err := parsePubBlob(keyInfo)
		if err != nil {
			return agentFailure, nil
		}
		sig, err := a.Sign(pub, data)
		if err != nil {
			return agentFailure, nil
		}
		inner := writeString(nil, []byte(KeyAlgoED25519))
		inner = writeString(inner, sig)
		return agentSignResponse, writeString(nil, inner)

	case agentRemoveIdentity: // 18
		keyInfo, _, err := readString(payload)
		if err != nil {
			return agentFailure, nil
		}
		pub, err := parsePubBlob(keyInfo)
		if err != nil {
			return agentFailure, nil
		}
		if err := a.Remove(pub); err != nil {
			return agentFailure, nil
		}
		return agentSuccess, nil

	case agentRemoveAllIdentities: // 19
		if err := a.RemoveAll(); err != nil {
			return agentFailure, nil
		}
		return agentSuccess, nil

	case agentLock, agentUnlock:
		var pass []byte
		if rest := payload; len(rest) > 0 {
			p, _, err0 := readString(rest)
			if err0 != nil {
				return agentFailure, nil
			}
			pass = p
		}
		ae, ok := a.(ExtendedAgent)
		if !ok {
			return agentFailure, nil
		}
		var err error
		if msgType == agentLock {
			err = ae.Lock(pass)
		} else {
			err = ae.Unlock(pass)
		}
		if err != nil {
			return agentFailure, nil
		}
		return agentSuccess, nil
	}
	return agentFailure, nil
}

func identitiesBody(keys []*Key) []byte {
	body := make([]byte, 4)
	putUint32(body, uint32(len(keys)))
	for _, k := range keys {
		body = writeString(body, k.Blob)
		body = writeString(body, []byte(k.Comment))
	}
	return body
}

func readBE32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
