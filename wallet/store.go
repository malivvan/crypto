package wallet

import (
	"bytes"
	"fmt"
	"io"

	"github.com/malivvan/crypto/pgp"
	"github.com/malivvan/crypto/pgp/armor"
)

// This file implements the gpg-like layer of a wallet: the wallet acts as an
// OpenPGP keyring (KeyRing interface), supports locking/unlocking its private
// keys with a passphrase and can persist and restore the whole wallet (own
// key plus every trusted keyring entity) in ASCII armor.
//
// Security model: secrets are never written to disk unencrypted (Save
// requires the wallet to be locked), and passphrase material passed to
// Lock/Unlock is zeroed after use.

// allEntities returns the wallet's own entity followed by every keyring
// entity imported via AddEntity.
func (wl *wallet) allEntities() []*pgp.Entity {
	entities := make([]*pgp.Entity, 0, 1+len(wl.entities))
	if wl.entity != nil {
		entities = append(entities, wl.entity)
	}
	entities = append(entities, wl.entities...)
	return entities
}

// KeysById returns the keys that match the given key id, following the
// KeyRing contract. The wallet's own entity (with its private keys) is
// searched first, then every keyring entity.
func (wl *wallet) KeysById(id uint64) []pgp.Key {
	return pgp.EntityList(wl.allEntities()).KeysById(id)
}

// EntitiesById returns the entities whose primary key matches the given key
// id, following the KeyRing contract.
func (wl *wallet) EntitiesById(id uint64) []*pgp.Entity {
	return pgp.EntityList(wl.allEntities()).EntitiesById(id)
}

// compile-time check that *wallet implements pgp.KeyRing.
var _ pgp.KeyRing = (*wallet)(nil)

// AddEntity adds a trusted entity (typically the public key of a
// correspondent) to the wallet's keyring. Duplicate entities (same primary
// fingerprint) are ignored.
func (wl *wallet) AddEntity(e *pgp.Entity) error {
	if e == nil || e.PrimaryKey == nil {
		return fmt.Errorf("wallet: cannot add a nil entity")
	}
	for _, existing := range wl.allEntities() {
		if bytes.Equal(existing.PrimaryKey.Fingerprint, e.PrimaryKey.Fingerprint) {
			return nil
		}
	}
	wl.entities = append(wl.entities, e)
	return nil
}

// Entities returns the wallet's own entity followed by every keyring entity.
func (wl *wallet) Entities() []*pgp.Entity {
	return wl.allEntities()
}

// IsLocked reports whether the wallet's private keys are currently encrypted
// with a passphrase.
func (wl *wallet) IsLocked() bool {
	return wl.entity != nil && wl.entity.PrivateKey != nil && wl.entity.PrivateKey.Encrypted
}

// Lock encrypts every private key of the wallet (primary key and subkeys)
// with the given passphrase, mirroring pgp.Entity.EncryptPrivateKeys.
// Locked wallets cannot sign or decrypt until Unlock is called. The
// passphrase is zeroed after use.
func (wl *wallet) Lock(password string) error {
	if wl.entity == nil || wl.entity.PrivateKey == nil {
		return fmt.Errorf("wallet: wallet has no private key to lock")
	}
	pw := []byte(password)
	defer clear(pw)
	if err := wl.entity.EncryptPrivateKeys(pw, wl.config); err != nil {
		return fmt.Errorf("wallet: error locking wallet: %w", err)
	}
	return nil
}

// Unlock decrypts every private key of the wallet with the given passphrase,
// mirroring pgp.Entity.DecryptPrivateKeys. The passphrase is zeroed
// after use.
func (wl *wallet) Unlock(password string) error {
	if wl.entity == nil || wl.entity.PrivateKey == nil {
		return fmt.Errorf("wallet: wallet has no private key to unlock")
	}
	pw := []byte(password)
	defer clear(pw)
	if err := wl.entity.DecryptPrivateKeys(pw); err != nil {
		return fmt.Errorf("wallet: error unlocking wallet: %w", err)
	}
	return nil
}

// Save persists the whole wallet in ASCII armor: first the wallet's own
// private key block, then one public key block per keyring entity.
//
// To avoid writing unencrypted key material to disk, Save refuses to run
// while the wallet is unlocked; call Lock first.
func (wl *wallet) Save(w io.Writer) error {
	if wl.entity == nil {
		return fmt.Errorf("wallet: nothing to save")
	}
	if !wl.IsLocked() {
		return fmt.Errorf("wallet: refusing to save an unlocked wallet; call Lock(password) first")
	}

	// Own private key block. SerializePrivateWithoutSigning preserves the
	// stored packets verbatim, so locked and unlocked forms roundtrip.
	priv, err := armor.Encode(w, pgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("wallet: error armoring private key: %w", err)
	}
	if err := wl.entity.SerializePrivateWithoutSigning(priv, wl.config); err != nil {
		_ = priv.Close()
		return fmt.Errorf("wallet: error serializing private key: %w", err)
	}
	if err := priv.Close(); err != nil {
		return fmt.Errorf("wallet: error finalizing private key block: %w", err)
	}
	// armor.Encode does not terminate the block with a newline; separate
	// blocks so that Load can frame them.
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("wallet: error writing block separator: %w", err)
	}

	// Trusted keyring entities (public material only).
	for _, e := range wl.entities {
		if e == nil {
			continue
		}
		pub, err := armor.Encode(w, pgp.PublicKeyType, nil)
		if err != nil {
			return fmt.Errorf("wallet: error armoring public key: %w", err)
		}
		if err := e.Serialize(pub); err != nil {
			_ = pub.Close()
			return fmt.Errorf("wallet: error serializing public key: %w", err)
		}
		if err := pub.Close(); err != nil {
			return fmt.Errorf("wallet: error finalizing public key block: %w", err)
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return fmt.Errorf("wallet: error writing block separator: %w", err)
		}
	}
	return nil
}

// splitArmorBlocks splits a stream of concatenated ASCII-armor blocks into
// individual BEGIN/END chunks. armor.Decode cannot read multiple blocks from
// a single reader (its internal buffer over-reads), so Load frames the file
// itself.
func splitArmorBlocks(data []byte) [][]byte {
	var blocks [][]byte
	rest := data
	for {
		start := bytes.Index(rest, []byte("-----BEGIN PGP "))
		if start < 0 {
			break
		}
		// Find the END marker that closes this block.
		end := bytes.Index(rest[start:], []byte("-----END PGP "))
		if end < 0 {
			break
		}
		end += start
		// Include the rest of the END line (and its trailing newline).
		lineEnd := bytes.IndexByte(rest[end:], '\n')
		switch {
		case lineEnd < 0:
			lineEnd = len(rest) - end
		default:
			lineEnd++
		}
		blocks = append(blocks, rest[start:end+lineEnd])
		rest = rest[end+lineEnd:]
	}
	return blocks
}

// Load restores a wallet previously written by Wallet.Save. The loaded
// wallet starts in the locked state it was saved in; use Unlock(password)
// before signing or decrypting. Because the SLIP-10/SLIP-21 master nodes
// cannot be re-derived from a saved keyring, the DeriveEd25519, DeriveX25519
// and DeriveSecret functions return an error on loaded wallets.
func Load(r io.Reader) (Wallet, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("wallet: error reading wallet file: %w", err)
	}
	blocks := splitArmorBlocks(data)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("wallet: no armored blocks found in wallet file")
	}

	var private *pgp.Entity
	var ring []*pgp.Entity
	for _, block := range blocks {
		decoded, err := armor.Decode(bytes.NewReader(block))
		if err != nil {
			return nil, fmt.Errorf("wallet: error decoding armor: %w", err)
		}
		switch decoded.Type {
		case pgp.PrivateKeyType:
			if private != nil {
				return nil, fmt.Errorf("wallet: multiple private key blocks in wallet file")
			}
			entities, err := pgp.ReadKeyRing(decoded.Body)
			if err != nil {
				return nil, fmt.Errorf("wallet: error reading private key block: %w", err)
			}
			if len(entities) != 1 {
				return nil, fmt.Errorf("wallet: expected one entity in private key block, got %d", len(entities))
			}
			private = entities[0]
		case pgp.PublicKeyType:
			entities, err := pgp.ReadKeyRing(decoded.Body)
			if err != nil {
				return nil, fmt.Errorf("wallet: error reading public key block: %w", err)
			}
			ring = append(ring, entities...)
		default:
			return nil, fmt.Errorf("wallet: unexpected armor block %q in wallet file", decoded.Type)
		}
	}

	if private == nil {
		return nil, fmt.Errorf("wallet: no private key block found in wallet file")
	}
	return &wallet{
		config:   Defaults(),
		entity:   private,
		entities: ring,
	}, nil
}
