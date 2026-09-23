// Package gpg provides a gpg-agent-compatible Assuan service that fronts an
// open wallet's Ed25519 (signing) and X25519 (encryption) keys.
//
// The wallet derives its keys with the high-level API in the module root
// (wallet.DeriveEd25519 / wallet.DeriveX25519). This package is the bridge that
// turns a set of those keys into a keyring addressed by OpenPGP keygrip and
// serves it over the Assuan ("gpg-agent") IPC protocol.
//
// Two integration styles are supported:
//
//   - Standalone server: serve the wallet keyring on a unix socket of your own
//     (CreateServer / Listen).
//
//   - Extension ("wrap an existing agent"): connect to an already-running
//     gpg-agent socket and answer locally for the keygrips the wallet owns
//     while transparently forwarding every command that targets an unknown
//     keygrip to the upstream agent. See Proxy / Extension.
//
// Only Ed25519 (EdDSA) signing and X25519 (ECDH) decryption are performed and
// advertised here; every other algorithm family is rejected in line with the
// module's supported-set constraints (see AGENTS.md).
package gpg

import (
	"encoding/hex"

	"github.com/malivvan/crypto/ed25519"
	"github.com/malivvan/crypto/pgp/grip"
	"github.com/malivvan/crypto/x25519"
)

// Role reports what an agent-carried key may be used for.
type Role int

const (
	// RoleSigning marks an Ed25519 signing key. Roles distinguish keys so a
	// decryption key can never be (mis)used to sign and vice versa.
	RoleSigning Role = iota
	// RoleDecryption marks an X25519 encryption/decryption key.
	RoleDecryption
)

func (r Role) String() string {
	switch r {
	case RoleSigning:
		return "signing"
	case RoleDecryption:
		return "decryption"
	}
	return "unknown"
}

// Key is the agent-visible view of a single wallet key. Exactly one operation
// backend is populated depending on Role.
type Key struct {
	// Grip is the 20-byte OpenPGP keygrip identifying this key over Assuan,
	// and GripHex its upper-case hexadecimal rendering.
	Grip    [20]byte
	GripHex string

	// Tag is an optional human/machine label such as "primary-signing".
	Tag string

	Role Role

	// Ed25519 is set when Role == RoleSigning.
	Ed25519 *ed25519.PrivateKey
	// X25519 is set when Role == RoleDecryption.
	X25519 *x25519.PrivateKey
}

// SignKey wraps an Ed25519 private key produced by wallet.DeriveEd25519 (or
// ed25519.GenerateKeyFromSeed) as a signing key, computing its OpenPGP keygrip
// from the public half.
func SignKey(priv *ed25519.PrivateKey, tag string) *Key {
	g := grip.ED25519(priv.PublicKey)
	h := hex.EncodeToString(g[:])
	return &Key{Grip: *g, GripHex: h, Tag: tag, Role: RoleSigning, Ed25519: priv}
}

// DecryptKey wraps an X25519 private key produced by wallet.DeriveX25519 (or
// x25519.GenerateKeyFromSeed) as a decryption key, computing its keygrip from
// the public half.
func DecryptKey(priv *x25519.PrivateKey, tag string) *Key {
	var pub x25519.Key
	copy(pub[:], priv.PublicKey.Point)
	g := grip.X25519(pub)
	h := hex.EncodeToString(g[:])
	return &Key{Grip: *g, GripHex: h, Tag: tag, Role: RoleDecryption, X25519: priv}
}

// Keyring addresses a set of keys by keygrip hex string, matching how GnuPG
// names keys in Assuan (HAVEKEY/KEYINFO/SIGKEY all take the keygrip).
type Keyring struct {
	byHex map[string]*Key
	order []*Key
}

// NewKeyring builds a keyring from the supplied wallet keys.
func NewKeyring(keys ...*Key) *Keyring {
	kr := &Keyring{}
	for _, k := range keys {
		if k != nil {
			kr.Add(k)
		}
	}
	return kr
}

// Add merges one key into the keyring. Keys are compared by keygrip; adding a
// key whose grip is already present replaces the earlier entry (and keeps its
// original List position). Keygrip hex is normalised to upper-case for lookup.
func (kr *Keyring) Add(k *Key) {
	if kr.byHex == nil {
		kr.byHex = make(map[string]*Key)
	}
	grip := normGrip(k.GripHex)
	if _, ok := kr.byHex[grip]; !ok {
		kr.order = append(kr.order, k)
	}
	kr.byHex[grip] = k
}

func normGrip(gripHex string) string {
	buf := make([]byte, 0, len(gripHex))
	for _, c := range gripHex {
		switch {
		case c >= 'a' && c <= 'f':
			buf = append(buf, byte(c-'a'+'A'))
		case (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'):
			buf = append(buf, byte(c))
		}
	}
	return string(buf)
}

// Has reports whether gripHex (either casing, optional '0x'-style dross) names
// a key held by this keyring.
func (kr *Keyring) Has(gripHex string) bool { return kr.get(gripHex) != nil }

// Get returns the key for gripHex or nil.
func (kr *Keyring) Get(gripHex string) *Key { return kr.get(gripHex) }

func (kr *Keyring) get(gripHex string) *Key {
	if kr == nil || kr.byHex == nil {
		return nil
	}
	if len(gripHex) >= 2 && gripHex[0] == '0' && (gripHex[1] == 'x' || gripHex[1] == 'X') {
		gripHex = gripHex[2:]
	}
	// Normalise any lower-case / whitespace form to upper-case hex.
	buf := make([]byte, 0, len(gripHex))
	for _, c := range gripHex {
		switch {
		case c >= 'a' && c <= 'f':
			buf = append(buf, byte(c-'a'+'A'))
		case (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'):
			buf = append(buf, byte(c))
		}
	}
	return kr.byHex[string(buf)]
}

// List returns the keys held by the keyring in insertion order.
func (kr *Keyring) List() []*Key {
	if kr == nil {
		return nil
	}
	out := make([]*Key, len(kr.order))
	copy(out, kr.order)
	return out
}
