package wallet

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/malivvan/crypto/pgp"
	"github.com/malivvan/crypto/pgp/armor"
	"github.com/malivvan/crypto/pgp/clearsign"
	walleterrors "github.com/malivvan/crypto/pgp/errors"
	"github.com/malivvan/crypto/pgp/packet"
)

// ---------------------------------------------------------------------------
// Detached signatures
// ---------------------------------------------------------------------------

// DetachSigner produces a detached OpenPGP signature over the message given
// to Wallet.Sign. By default, the message is signed by the wallet's own
// entity; additional signers can be attached with DetachSigner.Sign.
type DetachSigner struct {
	wallet  *wallet
	reader  io.Reader
	err     error
	signers []*pgp.Entity
	hints   *pgp.FileHints
	textSig bool
	armored bool
	cfg     *packet.Config
}

// Sign appends an additional signing entity to the detached signature.
func (ds *DetachSigner) Sign(e *pgp.Entity) *DetachSigner {
	if e != nil {
		ds.signers = append(ds.signers, e)
	}
	return ds
}

// Text produces a text signature (SigTypeText) instead of a binary one.
func (ds *DetachSigner) Text() *DetachSigner {
	ds.textSig = true
	return ds
}

// Armor wraps the output in ASCII armor ("PGP SIGNATURE").
func (ds *DetachSigner) Armor() *DetachSigner {
	ds.armored = true
	return ds
}

// File attaches literal-data metadata (file name, modification time, ...).
func (ds *DetachSigner) File(hints *pgp.FileHints) *DetachSigner {
	ds.hints = hints
	return ds
}

// Config overrides the packet config used for this signature. Passing nil
// restores the wallet's default config.
func (ds *DetachSigner) Config(c *packet.Config) *DetachSigner {
	ds.cfg = c
	return ds
}

func (ds *DetachSigner) params() *pgp.SignParams {
	return &pgp.SignParams{
		Config:  ds.wallet.resolveConfig(ds.cfg),
		TextSig: ds.textSig,
		Hints:   ds.hints,
	}
}

// writeTo signs the message and writes the detached signature to w.
func (ds *DetachSigner) writeTo(w io.Writer) (err error) {
	if ds.err != nil {
		return ds.err
	}
	var enc io.WriteCloser
	if ds.armored {
		enc, err = armor.Encode(w, pgp.SignatureType, nil)
		if err != nil {
			return err
		}
		w = enc
	}
	err = pgp.DetachSignWithParams(w, ds.signers, ds.reader, ds.params())
	if err != nil {
		if enc != nil {
			_ = enc.Close()
		}
		return err
	}
	if enc != nil {
		err = enc.Close()
	}
	return err
}

// Output writes the detached signature to w.
func (ds *DetachSigner) Output(w io.Writer) error {
	return ds.writeTo(w)
}

// String returns the detached signature as a string.
func (ds *DetachSigner) String() (string, error) {
	buf := new(bytes.Buffer)
	if err := ds.writeTo(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Bytes returns the detached signature as a byte slice.
func (ds *DetachSigner) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := ds.writeTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DetachVerifier verifies a detached signature over data. The signed data is
// given to Wallet.Verify, the signature is attached with
// DetachVerifier.Signature and the verification is performed by Verify.
type DetachVerifier struct {
	wallet    *wallet
	data      io.Reader // the signed message content
	signature io.Reader // the detached signature
	err       error
	armored   bool // the signature is ASCII-armored
	verifiers []*pgp.Entity
	cfg       *packet.Config
}

// Signature provides the detached signature to verify. It may be a string,
// []byte or io.Reader. Use Armor when the signature is ASCII-armored.
func (dv *DetachVerifier) Signature(v any) *DetachVerifier {
	reader, err := readerFrom(v)
	dv.signature = reader
	dv.err = err
	return dv
}

// Armor marks the signature as ASCII-armored ("PGP SIGNATURE").
func (dv *DetachVerifier) Armor() *DetachVerifier {
	dv.armored = true
	return dv
}

// Verifier appends an entity whose keys may have produced the signature.
func (dv *DetachVerifier) Verifier(e *pgp.Entity) *DetachVerifier {
	if e != nil {
		dv.verifiers = append(dv.verifiers, e)
	}
	return dv
}

// Config overrides the packet config used for the verification. Passing nil
// restores the wallet's default config.
func (dv *DetachVerifier) Config(c *packet.Config) *DetachVerifier {
	dv.cfg = c
	return dv
}

// Verify checks the detached signature against the signed data, using the
// wallet's whole keyring (plus any Verifier entities) to look up the
// signing key. It returns an error if the signature is missing, unknown,
// expired or invalid.
func (dv *DetachVerifier) Verify() error {
	if dv.err != nil {
		return dv.err
	}
	if dv.signature == nil {
		return fmt.Errorf("wallet: no signature to verify; provide it with Signature(...)")
	}
	cfg := dv.wallet.resolveConfig(dv.cfg)
	entities := append(dv.wallet.allEntities(), dv.verifiers...)
	keyring := pgp.EntityList(entities)
	var err error
	if dv.armored {
		_, _, err = pgp.VerifyArmoredDetachedSignature(keyring, dv.data, dv.signature, cfg)
	} else {
		_, _, err = pgp.VerifyDetachedSignature(keyring, dv.data, dv.signature, cfg)
	}
	if err != nil {
		return fmt.Errorf("wallet: error verifying detached signature: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Clearsigned messages
// ---------------------------------------------------------------------------

// Clearsigner produces a clearsigned (ASCII-armored, dash-escaped) message.
// The message is signed by the wallet's own entity unless overridden.
type Clearsigner struct {
	wallet  *wallet
	reader  io.Reader
	err     error
	signers []*pgp.Entity
	headers map[string]string
	cfg     *packet.Config
}

// Sign appends an additional signing entity to the clearsigned message.
func (cs *Clearsigner) Sign(e *pgp.Entity) *Clearsigner {
	if e != nil {
		cs.signers = append(cs.signers, e)
	}
	return cs
}

// Headers adds custom headers to the clearsign armor block.
func (cs *Clearsigner) Headers(h map[string]string) *Clearsigner {
	cs.headers = h
	return cs
}

// Config overrides the packet config used for the signature. Passing nil
// restores the wallet's default config.
func (cs *Clearsigner) Config(c *packet.Config) *Clearsigner {
	cs.cfg = c
	return cs
}

// privateKeys resolves the signing entities to their private keys, using the
// same key-selection rules as the underlying pgp sign operations.
func (cs *Clearsigner) privateKeys() ([]*packet.PrivateKey, error) {
	cfg := cs.wallet.resolveConfig(cs.cfg)
	var keys []*packet.PrivateKey
	for _, signer := range cs.signers {
		if signer == nil {
			continue
		}
		key, ok := signer.SigningKeyById(cfg.Now(), cfg.SigningKey(), cfg)
		if !ok || key.PrivateKey == nil {
			return nil, fmt.Errorf("wallet: signer %x has no usable private signing key", signer.PrimaryKey.KeyId)
		}
		if key.PrivateKey.Encrypted {
			return nil, fmt.Errorf("wallet: signing key %x is encrypted", key.PublicKey.KeyId)
		}
		keys = append(keys, key.PrivateKey)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("wallet: no signer provided")
	}
	return keys, nil
}

// writeTo clearsigns the message and writes it to w.
func (cs *Clearsigner) writeTo(w io.Writer) (err error) {
	if cs.err != nil {
		return cs.err
	}
	keys, err := cs.privateKeys()
	if err != nil {
		return err
	}
	cfg := cs.wallet.resolveConfig(cs.cfg)
	plain, err := clearsign.EncodeMultiWithHeader(w, keys, cfg, cs.headers)
	if err != nil {
		return err
	}
	if _, err = io.Copy(plain, cs.reader); err != nil {
		_ = plain.Close()
		return err
	}
	return plain.Close()
}

// Output writes the clearsigned message to w.
func (cs *Clearsigner) Output(w io.Writer) error {
	return cs.writeTo(w)
}

// String returns the clearsigned message as a string.
func (cs *Clearsigner) String() (string, error) {
	buf := new(bytes.Buffer)
	if err := cs.writeTo(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Bytes returns the clearsigned message as a byte slice.
func (cs *Clearsigner) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := cs.writeTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Encryption (with optional signing)
// ---------------------------------------------------------------------------

// Encryptor encrypts a message. It is created by Wallet.Encrypt (no
// signature) or Wallet.EncryptSign (signed by the wallet). Recipients are
// attached with To/ToHidden; when none are configured and no password is
// given the message is encrypted to the wallet's own key. Additional
// passphrases can be attached with Password.
type Encryptor struct {
	wallet     *wallet
	reader     io.Reader
	err        error
	to         []*pgp.Entity
	toHidden   []*pgp.Entity
	signers    []*pgp.Entity
	passwords  [][]byte
	hints      *pgp.FileHints
	textSig    bool
	armored    bool
	sessionKey []byte
	outsideSig []byte
	encTime    *time.Time
	cfg        *packet.Config
}

// To adds an explicitly mentioned recipient entity.
func (en *Encryptor) To(e ...*pgp.Entity) *Encryptor {
	for _, recipient := range e {
		if recipient != nil {
			en.to = append(en.to, recipient)
		}
	}
	return en
}

// ToHidden adds a hidden recipient entity (not mentioned in the message).
func (en *Encryptor) ToHidden(e ...*pgp.Entity) *Encryptor {
	for _, recipient := range e {
		if recipient != nil {
			en.toHidden = append(en.toHidden, recipient)
		}
	}
	return en
}

// Sign adds an entity that signs the message before it is encrypted. When
// EncryptSign was used the wallet's own entity is already a signer.
func (en *Encryptor) Sign(e ...*pgp.Entity) *Encryptor {
	for _, signer := range e {
		if signer != nil {
			en.signers = append(en.signers, signer)
		}
	}
	return en
}

// Password adds an additional passphrase the message is encrypted to.
func (en *Encryptor) Password(p ...[]byte) *Encryptor {
	for _, pw := range p {
		if pw != nil {
			en.passwords = append(en.passwords, pw)
		}
	}
	return en
}

// Text produces text signatures (SigTypeText) for the signing entities.
func (en *Encryptor) Text() *Encryptor {
	en.textSig = true
	return en
}

// Armor wraps the output in ASCII armor ("PGP MESSAGE").
func (en *Encryptor) Armor() *Encryptor {
	en.armored = true
	return en
}

// File attaches literal-data metadata (file name, modification time, ...).
func (en *Encryptor) File(hints *pgp.FileHints) *Encryptor {
	en.hints = hints
	return en
}

// SessionKey forces the given session key instead of a random one.
func (en *Encryptor) SessionKey(key []byte) *Encryptor {
	en.sessionKey = key
	return en
}

// OutsideSig embeds an externally produced signature in the encrypted
// message. This is only meant for exceptional cases.
func (en *Encryptor) OutsideSig(sig []byte) *Encryptor {
	en.outsideSig = sig
	return en
}

// EncryptionTime overrides the time used to select the encryption key.
func (en *Encryptor) EncryptionTime(t time.Time) *Encryptor {
	en.encTime = &t
	return en
}

// Config overrides the packet config used for encryption. Passing nil
// restores the wallet's default config.
func (en *Encryptor) Config(c *packet.Config) *Encryptor {
	en.cfg = c
	return en
}

func (en *Encryptor) params() *pgp.EncryptParams {
	return &pgp.EncryptParams{
		Hints:          en.hints,
		Signers:        en.signers,
		TextSig:        en.textSig,
		Passwords:      en.passwords,
		SessionKey:     en.sessionKey,
		OutsideSig:     en.outsideSig,
		EncryptionTime: en.encTime,
		Config:         en.wallet.resolveConfig(en.cfg),
	}
}

// writeTo encrypts the message and writes the ciphertext to w.
func (en *Encryptor) writeTo(w io.Writer) (err error) {
	if en.err != nil {
		return en.err
	}
	var enc io.WriteCloser
	if en.armored {
		enc, err = armor.Encode(w, pgp.MessageType, nil)
		if err != nil {
			return err
		}
		w = enc
	}
	err = en.encryptTo(w)
	if err != nil {
		if enc != nil {
			_ = enc.Close()
		}
		return err
	}
	if enc != nil {
		err = enc.Close()
	}
	return err
}

func (en *Encryptor) encryptTo(w io.Writer) (err error) {
	var plain io.WriteCloser
	params := en.params()
	switch {
	case len(en.to)+len(en.toHidden) > 0:
		plain, err = pgp.EncryptWithParams(w, en.to, en.toHidden, params)
	case len(en.passwords) > 0:
		// Password-only encryption: the first password is the primary one,
		// any remaining passwords are attached as additional SKESK packets.
		additional := &pgp.EncryptParams{}
		*additional = *params
		additional.Passwords = en.passwords[1:]
		plain, err = pgp.SymmetricallyEncryptWithParams(en.passwords[0], w, additional)
	default:
		// No explicit recipient: encrypt to the wallet's own key.
		plain, err = pgp.EncryptWithParams(w, []*pgp.Entity{en.wallet.entity}, nil, params)
	}
	if err != nil {
		return err
	}
	if _, err = io.Copy(plain, en.reader); err != nil {
		_ = plain.Close()
		return err
	}
	return plain.Close()
}

// Output encrypts the message and writes the ciphertext to w.
func (en *Encryptor) Output(w io.Writer) error {
	return en.writeTo(w)
}

// String returns the ciphertext as a string.
func (en *Encryptor) String() (string, error) {
	buf := new(bytes.Buffer)
	if err := en.writeTo(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Bytes returns the ciphertext as a byte slice.
func (en *Encryptor) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := en.writeTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Decryption (with optional verification)
// ---------------------------------------------------------------------------

// Decryptor decrypts a message. It is created by Wallet.Decrypt or
// Wallet.DecryptVerify. The wallet's own key is always used for decryption
// and (when verifying) signature lookup; additional public entities can be
// attached with Verifier. Passphrase-based messages are handled with
// Password or a custom Prompt.
type Decryptor struct {
	wallet    *wallet
	reader    io.Reader
	err       error
	armored   bool
	verify    bool
	verifiers []*pgp.Entity
	password  []byte
	pwTried   bool
	prompt    pgp.PromptFunction
	cfg       *packet.Config
}

// Armor marks the input as an ASCII-armored message.
func (dc *Decryptor) Armor() *Decryptor {
	dc.armored = true
	return dc
}

// Verifier appends an entity whose keys may have produced the embedded
// signature.
func (dc *Decryptor) Verifier(e *pgp.Entity) *Decryptor {
	if e != nil {
		dc.verifiers = append(dc.verifiers, e)
	}
	return dc
}

// Password provides a passphrase used to decrypt passphrase-protected
// (SKESK) messages. A wrong passphrase results in an error.
func (dc *Decryptor) Password(p []byte) *Decryptor {
	dc.password = p
	dc.prompt = nil
	return dc
}

// Prompt installs a custom passphrase/key prompt, mirroring pgp.ReadMessage.
func (dc *Decryptor) Prompt(f pgp.PromptFunction) *Decryptor {
	dc.prompt = f
	dc.password = nil
	return dc
}

// Config overrides the packet config used for decryption. Passing nil
// restores the wallet's default config.
func (dc *Decryptor) Config(c *packet.Config) *Decryptor {
	dc.cfg = c
	return dc
}

// resolvePrompt returns the prompt function to pass to pgp.ReadMessage.
func (dc *Decryptor) resolvePrompt() pgp.PromptFunction {
	if dc.prompt != nil {
		return dc.prompt
	}
	if dc.password == nil {
		return nil
	}
	return func(keys []pgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			return nil, walleterrors.ErrKeyIncorrect
		}
		if dc.pwTried {
			// ReadMessage would otherwise retry the prompt forever.
			return nil, walleterrors.ErrKeyIncorrect
		}
		dc.pwTried = true
		return dc.password, nil
	}
}

// keyring returns the entities used for decryption and signature lookup:
// the wallet's whole keyring plus any attached verifier entities.
func (dc *Decryptor) keyring() pgp.EntityList {
	entities := append(dc.wallet.allEntities(), dc.verifiers...)
	return pgp.EntityList(entities)
}

// read parses the (optionally armored) message into MessageDetails without
// consuming the plaintext body.
func (dc *Decryptor) read() (*pgp.MessageDetails, error) {
	if dc.err != nil {
		return nil, dc.err
	}
	r := dc.reader
	if dc.armored {
		block, err := armor.Decode(r)
		if err != nil {
			return nil, fmt.Errorf("wallet: error decoding armored message: %w", err)
		}
		if block.Type != pgp.MessageType {
			return nil, fmt.Errorf("wallet: expected armored %q, got: %q", pgp.MessageType, block.Type)
		}
		r = block.Body
	}
	cfg := dc.wallet.resolveConfig(dc.cfg)
	md, err := pgp.ReadMessage(r, dc.keyring(), dc.resolvePrompt(), cfg)
	if err != nil {
		return nil, fmt.Errorf("wallet: error reading message: %w", err)
	}
	return md, nil
}

// Message parses the message and returns its MessageDetails without reading
// the plaintext. The caller must drain md.UnverifiedBody to trigger the
// integrity and signature checks.
func (dc *Decryptor) Message() (*pgp.MessageDetails, error) {
	return dc.read()
}

// writePlain runs the full read pipeline: parse the message, stream the
// plaintext body to w (consuming it fully so integrity checks complete) and
// enforce the verify-mode contract.
func (dc *Decryptor) writePlain(w io.Writer) (*pgp.MessageDetails, error) {
	md, err := dc.read()
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, md.UnverifiedBody); err != nil {
		return md, fmt.Errorf("wallet: error reading plaintext: %w", err)
	}
	if err := dc.checkVerified(md); err != nil {
		return md, err
	}
	return md, nil
}

// Output decrypts the message and streams the plaintext to w. The message
// body is fully consumed so that integrity checks (and, in verify mode, the
// signature verification) complete before Output returns. It returns the
// same errors as Plaintext.
func (dc *Decryptor) Output(w io.Writer) error {
	_, err := dc.writePlain(w)
	return err
}

// Plaintext decrypts the message, reads the whole plaintext and returns it
// together with the message details. In verify mode (DecryptVerify) an error
// is returned unless an embedded signature was verified successfully.
func (dc *Decryptor) Plaintext() ([]byte, *pgp.MessageDetails, error) {
	var buf bytes.Buffer
	md, err := dc.writePlain(&buf)
	if err != nil {
		return nil, md, err
	}
	return buf.Bytes(), md, nil
}

// checkVerified enforces the verify-mode contract after the plaintext body
// has been fully consumed: the message must carry a signature that verified
// against the wallet keyring.
func (dc *Decryptor) checkVerified(md *pgp.MessageDetails) error {
	if !dc.verify {
		return nil
	}
	if !md.IsSigned {
		return fmt.Errorf("wallet: message is not signed")
	}
	if md.SignatureError != nil {
		return fmt.Errorf("wallet: message signature verification failed: %w", md.SignatureError)
	}
	if !md.IsVerified || md.Signature == nil || md.SignedBy == nil {
		return fmt.Errorf("wallet: no verified signature found")
	}
	return nil
}
