// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errors contains common error types for the OpenPGP packages.
package errors // import "github.com/malivvan/crypto/pgp/errors"

import (
	"fmt"
	"strconv"
)

var (
	// ErrDecryptSessionKeyParsing is a generic error message for parsing errors in decrypted data
	// to reduce the risk of oracle attacks.
	ErrDecryptSessionKeyParsing = DecryptWithSessionKeyError("parsing error")
	// ErrAEADTagVerification is returned if one of the tag verifications in SEIPDv2 fails
	ErrAEADTagVerification error = DecryptWithSessionKeyError("AEAD tag verification failed")
	// ErrMDCHashMismatch
	ErrMDCHashMismatch error = SignatureError("MDC hash mismatch")
	// ErrMDCMissing
	ErrMDCMissing error = SignatureError("MDC packet not found")
)

// A StructuralError is returned when OpenPGP data is found to be syntactically
// invalid.
type StructuralError string

func (s StructuralError) Error() string {
	return "wallet: invalid data: " + string(s)
}

// A DecryptWithSessionKeyError is returned when a failure occurs when reading from symmetrically decrypted data or
// an authentication tag verification fails.
// Such an error indicates that the supplied session key is likely wrong or the data got corrupted.
type DecryptWithSessionKeyError string

func (s DecryptWithSessionKeyError) Error() string {
	return "wallet: decryption with session key failed: " + string(s)
}

// HandleSensitiveParsingError handles parsing errors when reading data from potentially decrypted data.
// The function makes parsing errors generic to reduce the risk of oracle attacks in SEIPDv1.
func HandleSensitiveParsingError(err error, decrypted bool) error {
	if !decrypted {
		// Data was not encrypted so we return the inner error.
		return err
	}
	// The data is read from a stream that decrypts using a session key;
	// therefore, we need to handle parsing errors appropriately.
	// This is essential to mitigate the risk of oracle attacks.
	if decError, ok := err.(*DecryptWithSessionKeyError); ok {
		return decError
	}
	if decError, ok := err.(DecryptWithSessionKeyError); ok {
		return decError
	}
	return ErrDecryptSessionKeyParsing
}

// UnsupportedError indicates that, although the OpenPGP data is valid, it
// makes use of currently unimplemented features.
type UnsupportedError string

func (s UnsupportedError) Error() string {
	return "wallet: unsupported feature: " + string(s)
}

// InvalidArgumentError indicates that the caller is in error and passed an
// incorrect value.
type InvalidArgumentError string

func (i InvalidArgumentError) Error() string {
	return "wallet: invalid argument: " + string(i)
}

// SignatureError indicates that a syntactically valid signature failed to
// validate.
type SignatureError string

func (b SignatureError) Error() string {
	return "wallet: invalid signature: " + string(b)
}

type signatureExpiredError int

func (se signatureExpiredError) Error() string {
	return "wallet: signature expired"
}

var ErrSignatureExpired error = signatureExpiredError(0)

type keyExpiredError int

func (ke keyExpiredError) Error() string {
	return "wallet: key expired"
}

var ErrSignatureOlderThanKey error = signatureOlderThanKeyError(0)

type signatureOlderThanKeyError int

func (ske signatureOlderThanKeyError) Error() string {
	return "wallet: signature is older than the key"
}

var ErrKeyExpired error = keyExpiredError(0)

type keyIncorrectError int

func (ki keyIncorrectError) Error() string {
	return "wallet: incorrect key"
}

var ErrKeyIncorrect error = keyIncorrectError(0)

// KeyInvalidError indicates that the public key parameters are invalid
// as they do not match the private ones
type KeyInvalidError string

func (e KeyInvalidError) Error() string {
	return "wallet: invalid key: " + string(e)
}

type unknownIssuerError int

func (unknownIssuerError) Error() string {
	return "wallet: signature made by unknown entity"
}

var ErrUnknownIssuer error = unknownIssuerError(0)

type keyRevokedError int

func (keyRevokedError) Error() string {
	return "wallet: signature made by revoked key"
}

var ErrKeyRevoked error = keyRevokedError(0)

type WeakAlgorithmError string

func (e WeakAlgorithmError) Error() string {
	return "wallet: weak algorithms are rejected: " + string(e)
}

type UnknownPacketTypeError uint8

func (upte UnknownPacketTypeError) Error() string {
	return "wallet: unknown packet type: " + strconv.Itoa(int(upte))
}

type CriticalUnknownPacketTypeError uint8

func (upte CriticalUnknownPacketTypeError) Error() string {
	return "wallet: unknown critical packet type: " + strconv.Itoa(int(upte))
}

// AEADError indicates that there is a problem when initializing or using a
// AEAD instance, configuration struct, nonces or index values.
type AEADError string

func (ae AEADError) Error() string {
	return "wallet: aead error: " + string(ae)
}

// ErrDummyPrivateKey results when operations are attempted on a private key
// that is just a dummy key. See
// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;h=fe55ae16ab4e26d8356dc574c9e8bc935e71aef1;hb=23191d7851eae2217ecdac6484349849a24fd94a#l1109
type ErrDummyPrivateKey string

func (dke ErrDummyPrivateKey) Error() string {
	return "wallet: s2k GNU dummy key: " + string(dke)
}

// ErrMalformedMessage results when the packet sequence is incorrect
type ErrMalformedMessage string

func (dke ErrMalformedMessage) Error() string {
	return "wallet: malformed message " + string(dke)
}

type messageTooLargeError int

func (e messageTooLargeError) Error() string {
	return "wallet: decompressed message size exceeds provided limit"
}

// ErrMessageTooLarge is returned if the read data from
// a compressed packet exceeds the provided limit.
var ErrMessageTooLarge error = messageTooLargeError(0)

// ErrEncryptionKeySelection is returned if encryption key selection fails (v2 API).
type ErrEncryptionKeySelection struct {
	PrimaryKeyId      string
	PrimaryKeyErr     error
	EncSelectionKeyId *string
	EncSelectionErr   error
}

func (eks ErrEncryptionKeySelection) Error() string {
	prefix := fmt.Sprintf("wallet: key selection for primary key %s:", eks.PrimaryKeyId)
	if eks.PrimaryKeyErr != nil {
		return fmt.Sprintf("%s invalid primary key: %s", prefix, eks.PrimaryKeyErr)
	}
	if eks.EncSelectionKeyId != nil {
		return fmt.Sprintf("%s invalid encryption key %s: %s", prefix, *eks.EncSelectionKeyId, eks.EncSelectionErr)
	}
	return fmt.Sprintf("%s no encryption key: %s", prefix, eks.EncSelectionErr)
}
