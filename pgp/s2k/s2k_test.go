// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"testing"
)

var saltedTests = []struct {
	in, out string
}{
	{"hello", "468f2de3e72a9d2b99db4e31da1ec9267033beb8"},
	{"world", "bc36c1145f885a404eff122e94f658bf0c76baaf"},
	{"foo", "9fe0b8f36d05cae1d1c1cd699380bb23ecc5455d"},
	{"bar", "ff2ea61e5b49c18e4666e22180a356581c9686c8"},
	{"x", "536b357e1ebd2e4209a08b2226acb7ba20fd3277"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "dbb0424c49227836fc55ad3fe8df6f95d3ea77e2"},
}

func TestSalted(t *testing.T) {
	h := sha256.New()
	salt := [4]byte{1, 2, 3, 4}

	for i, test := range saltedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Salted(out, h, []byte(test.in), salt[:])
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var iteratedTests = []struct {
	in, out string
}{
	{"hello", "b6daedf34ac3ce31b3bacf275e8db101e4068330"},
	{"world", "232560bc14f79dbdf44a5ea13d4edf44ae7ced11"},
	{"foo", "f04d10a4e89a4b8db33fc3d7465af3393d7dc195"},
	{"bar", "65f59d72c45170b6ae3225c4e130d539979e36ef"},
	{"x", "11c5bec591a91d5431f5d585309dabb00bf245eb"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "eff8d826b7e5226671c489087e1b9f7a48a07e3a"},
}

func TestIterated(t *testing.T) {
	h := sha256.New()
	salt := [4]byte{4, 3, 2, 1}

	for i, test := range iteratedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Iterated(out, h, []byte(test.in), salt[:], 31)
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var parseTests = []struct {
	spec, in, out string
	dummyKey      bool
	params        Params
}{
	/* Simple with SHA256 */
	{"0008", "hello", "2cf24dba", false,
		Params{SimpleS2K, 0x08, [16]byte{}, 0, 0, 0, 0}},
	/* Salted with SHA256 */
	{"01080102030405060708", "hello", "ef1da44b", false,
		Params{SaltedS2K, 0x08, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0, 0, 0, 0}},
	/* Iterated with SHA256 */
	{"03080102030405060708f1", "hello", "b28da2aa", false,
		Params{IteratedSaltedS2K, 0x08, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0xf1, 0, 0, 0}},
	/* Argon2 (salt, then passes=3, parallelism=4, memoryExp=16) */
	{"0401020304050607080102030405060708030410", "hello", "dabc018a", false,
		Params{Argon2S2K, 0x00, [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0, 0x03, 0x04, 0x10}},
	/* GNU dummy S2K */
	{"6502474e5501", "", "", true,
		Params{GnuS2K, 0x02, [16]byte{}, 0, 0, 0, 0}},
}

func TestParseIntoParams(t *testing.T) {
	for i, test := range parseTests {
		spec, _ := hex.DecodeString(test.spec)
		buf := bytes.NewBuffer(spec)
		params, err := ParseIntoParams(buf)
		if err != nil {
			t.Errorf("%d: ParseIntoParams returned error: %s", i, err)
			continue
		}

		if test.params.mode != params.mode || test.params.hashId != params.hashId || test.params.countByte != params.countByte ||
			!bytes.Equal(test.params.salt(), params.salt()) {
			t.Errorf("%d: Wrong config, got: %+v want: %+v", i, params, test.params)
		}

		if params.Dummy() != test.dummyKey {
			t.Errorf("%d: Got GNU dummy %v, expected %v", i, params.Dummy(), test.dummyKey)
		}

		if !test.dummyKey {
			expectedHash, _ := hex.DecodeString(test.out)
			out := make([]byte, len(expectedHash))

			f, err := params.Function()
			if err != nil {
				t.Errorf("%d: params.Function() returned error: %s", i, err)
				continue
			}
			f(out, []byte(test.in))
			if !bytes.Equal(out, expectedHash) {
				t.Errorf("%d: Wrong output got: %x want: %x", i, out, expectedHash)
			}
		}

		var reserialized bytes.Buffer
		err = params.Serialize(&reserialized)
		if err != nil {
			t.Errorf("%d: params.Serialize() returned error: %s", i, err)
			continue
		}
		if !bytes.Equal(reserialized.Bytes(), spec) {
			t.Errorf("%d: Wrong reserialized got: %x want: %x", i, reserialized.Bytes(), spec)
		}
		if testing.Short() {
			break
		}
	}
}

func TestSerializeSaltedOK(t *testing.T) {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA512}
	for _, h := range hashes {
		params := testSerializeConfigOK(t, &Config{S2KMode: SaltedS2K, Hash: h, PassphraseIsHighEntropy: true})

		if params.mode != SaltedS2K {
			t.Fatalf("Wrong mode, expected %d got %d", SaltedS2K, params.mode)
		}
	}
}

func TestSerializeSaltedLowEntropy(t *testing.T) {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA512}
	for _, h := range hashes {
		params := testSerializeConfigOK(t, &Config{S2KMode: SaltedS2K, Hash: h})

		if params.mode != IteratedSaltedS2K {
			t.Fatalf("Wrong mode, expected %d got %d", IteratedSaltedS2K, params.mode)
		}

		if params.countByte != 224 { // The default case. Corresponding to 16777216
			t.Fatalf("Wrong count byte, expected %d got %d", 224, params.countByte)
		}
	}
}

func TestSerializeSaltedIteratedOK(t *testing.T) {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA512}
	// {input, expected}
	testCounts := [][]int{{-1, 96}, {0, 224}, {1024, 96}, {65536, 96}, {4063232, 191}, {65011712, 255}}
	for _, h := range hashes {
		for _, c := range testCounts {
			params := testSerializeConfigOK(t, &Config{Hash: h, S2KCount: c[0]})

			if params.mode != IteratedSaltedS2K {
				t.Fatalf("Wrong mode, expected %d got %d", IteratedSaltedS2K, params.mode)
			}

			if int(params.countByte) != c[1] {
				t.Fatalf("Wrong count byte, expected %d got %d", c[1], params.countByte)
			}
		}
	}
}

func testSerializeConfigOK(t *testing.T, c *Config) *Params {
	buf := bytes.NewBuffer(nil)
	key := make([]byte, 16)
	passphrase := []byte("testing")
	err := Serialize(buf, key, rand.Reader, passphrase, c)
	if err != nil {
		t.Fatalf("failed to serialize with config %+v: %s", c, err)
	}

	f, err := Parse(bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to reparse: %s", err)
	}
	key2 := make([]byte, len(key))
	f(key2, passphrase)
	if !bytes.Equal(key2, key) {
		t.Errorf("keys don't match: %x (serialied) vs %x (parsed)", key, key2)
	}

	params, err := ParseIntoParams(bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse params: %s", err)
	}

	return params
}

var argon2DeriveTest = []struct {
	in, out string
}{
	{"hello", "bf69293d2961bbbebe4c64c745cf44d4"},
}

func TestArgon2Derive(t *testing.T) {
	salt := []byte("12345678")

	for i, test := range argon2DeriveTest {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Argon2(out, []byte(test.in), salt, 3, 4, 16)
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

func TestArgon2EncodeMemory(t *testing.T) {
	tests := []struct {
		in  uint32
		out uint8
	}{
		{64 * 1024, 16},
		{64*1024 + 1, 17},
		{2147483648, 31},
		{1, 3}, // clamped to lower bound 8*1
	}
	for i, test := range tests {
		conf := &Argon2Config{
			Memory:              test.in,
			DegreeOfParallelism: 1,
		}
		if out := conf.EncodedMemory(); out != test.out {
			t.Errorf("#%d, got: %d want: %d", i, out, test.out)
		}
	}
}

func TestSerializeArgon2(t *testing.T) {
	config := &Config{
		S2KMode:      Argon2S2K,
		Argon2Config: &Argon2Config{NumberOfPasses: 3, DegreeOfParallelism: 4, Memory: 64 * 1024},
	}

	params := testSerializeConfigOK(t, config)

	if params.mode != Argon2S2K {
		t.Fatalf("Wrong mode, expected %d got %d", Argon2S2K, params.mode)
	}
}

func TestValidateArgon2Params(t *testing.T) {
	tests := []struct {
		params  Params
		wantErr bool
	}{
		{Params{parallelism: 4, passes: 3, memoryExp: 6}, false},
		{Params{parallelism: 0, passes: 3, memoryExp: 6}, true},
		{Params{parallelism: 4, passes: 0, memoryExp: 6}, true},
		{Params{parallelism: 4, passes: 3, memoryExp: 4}, true},
		{Params{parallelism: 4, passes: 3, memoryExp: 32}, true},
		{Params{parallelism: 4, passes: 3, memoryExp: 5}, false},
		{Params{parallelism: 4, passes: 3, memoryExp: 31}, false},
	}

	for _, tt := range tests {
		err := validateArgon2Params(&tt.params)
		if tt.wantErr && err == nil {
			t.Errorf("validateArgon2Params: expected an error for %+v", tt.params)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("validateArgon2Params: expected no error for %+v, got: %s", tt.params, err)
		}
	}
}
