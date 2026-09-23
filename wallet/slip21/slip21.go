// Package slip21 implements the SLIP-0021 key derivation scheme for symmetric keys.
// SLIP-0021 implementation according to the https://github.com/satoshilabs/slips/blob/master/slip-0021.md
package slip21

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"regexp"
	"strings"
)

const (
	// you should use this Prefix for your path
	Prefix = "m/SLIP-0021"

	// As in https://github.com/satoshilabs/slips/blob/master/slip-0021.md
	seedModifier = "Symmetric key seed"
)

var (
	ErrInvalidPath = fmt.Errorf("invalid derivation path")
	pathRegex      = regexp.MustCompile("^m(/.+)*$")
)

type Node interface {
	Derive(label []byte) (Node, error)
	Key() []byte
}

type node struct {
	key  []byte
	code []byte
}

// DeriveForPath derives key for a path in slip-0021 format and a seed
func DeriveForPath(path string, seed []byte) (Node, error) {
	if !IsValidPath(path) {
		return nil, ErrInvalidPath
	}

	key, err := NewMasterNode(seed)
	if err != nil {
		return nil, err
	}

	labels := strings.Split(path, "/")
	for _, label := range labels[1:] {
		key, err = key.Derive([]byte(label))
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

// NewMasterNode generates a new master key from seed
func NewMasterNode(seed []byte) (Node, error) {
	hash := hmac.New(sha512.New, []byte(seedModifier))
	_, err := hash.Write(seed)
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	key := &node{
		key:  sum[32:],
		code: sum[0:32],
	}

	return key, nil
}

// Derive derives a child node with a label
func (k *node) Derive(label []byte) (Node, error) {
	hash := hmac.New(sha512.New, k.code)
	_, err := hash.Write(append([]byte{0x0}, label...))
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	newKey := &node{
		key:  sum[32:],
		code: sum[:32],
	}
	return newKey, nil
}

// SymmetricKey returns 256 bit symmetric key for the current node
func (k *node) Key() []byte {
	if k == nil {
		return nil
	}
	return k.key
}

// IsValidPath check whether or not the path has valid segments
func IsValidPath(path string) bool {
	return pathRegex.MatchString(path)
}
