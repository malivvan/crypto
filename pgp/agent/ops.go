package gpg

import (
	"errors"
	"fmt"

	"github.com/malivvan/crypto/ed25519"
)

// ErrWrongKey is returned when a key is used for the wrong operation (e.g.
// requesting an Ed25519 signature from the X25519 decryption key).
var ErrWrongKey = errors.New("gpg: key type mismatch for requested operation")

// This file implements the private-key operations the agent can perform for a
// held key. Every operation asks that the client first deselect any previous
// key via RESET and then selects an explicit keygrip with SIGKEY/SETKEY, so the
// agent never relies on an implicit default key (matching gpg-agent's rule that
// the default key is only used when no key was set, which a wallet with many
// keys should avoid).

// signEd25519 signs digestBytes (already the exact bytes the caller wants
// authenticated, typically a hash over the message, or a raw message). The
// signature returned is the standard 64-byte Ed25519 signature.
//
// NOTE on scope: GnuPG's PKSIGN wire encoding (libgcrypt S-expression,
// pre-hash flags, kdf) is intentionally NOT reimplemented here; this method and
// the calling handler use a documented, self-contained framing that is exact
// and testable against the module's ed25519 implementation. Interoperation with
// a byte-exact stock gpg-agent signature S-expression is out of scope (see
// README "Compatibility").
func signEd25519(k *Key, digestBytes []byte) ([]byte, error) {
	if k == nil || k.Role != RoleSigning || k.Ed25519 == nil {
		return nil, ErrWrongKey
	}
	sig, err := ed25519.Sign(k.Ed25519, digestBytes)
	if err != nil {
		return nil, fmt.Errorf("gpg: ed25519 sign: %w", err)
	}
	return sig, nil
}

// HasSigningKey is a cheap predicate used by HAVEKEY for signing-capable keys.
func (k *Key) HasSigningKey() bool { return k != nil && k.Role == RoleSigning }

// HasDecryptionKey reports whether the key can decrypt.
func (k *Key) HasDecryptionKey() bool { return k != nil && k.Role == RoleDecryption }
