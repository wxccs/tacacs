// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

package crypto

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tacerrs "github.com/wxccs/tacacs/errors"
)

// referencePad is an independent re-implementation of the RFC 8907 §4.5
// pseudo-pad, used only to cross-check the production implementation.
func referencePad(n int, key []byte, sessionID uint32, version, seqNo byte) []byte {
	if n == 0 {
		return nil
	}
	base := make([]byte, 0, 4+len(key)+2+md5DigestSize)
	bb := make([]byte, 4)
	binary.BigEndian.PutUint32(bb, sessionID)
	base = append(base, bb...)
	base = append(base, key...)
	base = append(base, version, seqNo)

	pad := make([]byte, 0, n)
	var prev []byte
	for len(pad) < n {
		h := md5.New()
		h.Write(base)
		if prev != nil {
			h.Write(prev)
		}
		d := h.Sum(nil)
		rem := n - len(pad)
		if rem > md5DigestSize {
			rem = md5DigestSize
		}
		pad = append(pad, d[:rem]...)
		prev = d
	}
	return pad
}

func TestObfuscateRoundtrip(t *testing.T) {
	cases := []struct {
		name      string
		body      []byte
		key       []byte
		sessionID uint32
		version   byte
		seqNo     byte
	}{
		{"empty", nil, []byte("key"), 0x12345678, 0xc0, 1},
		{"single block", []byte("hello, tacacs+ world!"), []byte("sharedsecret"), 0xdeadbeef, 0xc0, 1},
		{"multi block", bytes.Repeat([]byte{0xab}, 40), []byte("k"), 1, 0xc1, 3},
		{"exactly 16", make([]byte, 16), []byte("sixteenbytekey!"), 0x11223344, 0xc0, 5},
		{"17 bytes", make([]byte, 17), []byte("k2"), 0x55aa55aa, 0xc1, 7},
		{"empty key", []byte("data"), nil, 0x99999999, 0xc0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obf := Obfuscate(c.body, c.key, c.sessionID, c.version, c.seqNo)
			assert.Equal(t, len(c.body), len(obf))
			deobf := Deobfuscate(obf, c.key, c.sessionID, c.version, c.seqNo)
			assert.Equal(t, c.body, deobf)
		})
	}
}

func TestObfuscateMatchesReferencePad(t *testing.T) {
	// The first 16 obfuscated bytes equal plaintext XOR MD5(session_id||key||version||seq_no).
	body := []byte("The quick brown fox jumps over the lazy dog 1234567890")
	key := []byte("supersecretkey")
	sessionID := uint32(0x0a1b2c3d)
	version := byte(0xc0)
	seqNo := byte(1)

	obf := Obfuscate(body, key, sessionID, version, seqNo)

	// Reference first block: MD5(session_id[BE] || key || version || seq_no).
	h := md5.New()
	bb := make([]byte, 4)
	binary.BigEndian.PutUint32(bb, sessionID)
	h.Write(bb)
	h.Write(key)
	h.Write([]byte{version, seqNo})
	firstBlock := h.Sum(nil)

	for i := 0; i < 16; i++ {
		assert.Equal(t, body[i]^firstBlock[i], obf[i], "byte %d", i)
	}

	// Full pad cross-check via independent reimplementation.
	pad := referencePad(len(body), key, sessionID, version, seqNo)
	for i := range body {
		assert.Equal(t, body[i]^pad[i], obf[i], "byte %d", i)
	}
}

func TestObfuscateMultiBlockChaining(t *testing.T) {
	// Second MD5 block appends the first digest; verify byte 16..31 chain.
	body := bytes.Repeat([]byte{0x00}, 32) // all-zero so obf == pad
	key := []byte("k")
	sessionID := uint32(0x0badf00d)
	version := byte(0xc1)
	seqNo := byte(3)

	obf := Obfuscate(body, key, sessionID, version, seqNo)

	h1 := md5.New()
	bb := make([]byte, 4)
	binary.BigEndian.PutUint32(bb, sessionID)
	h1.Write(bb)
	h1.Write(key)
	h1.Write([]byte{version, seqNo})
	d1 := h1.Sum(nil)

	h2 := md5.New()
	h2.Write(bb)
	h2.Write(key)
	h2.Write([]byte{version, seqNo})
	h2.Write(d1)
	d2 := h2.Sum(nil)

	assert.Equal(t, d1, obf[:16], "first block")
	assert.Equal(t, d2, obf[16:32], "second block")
}

func TestObfuscateInPlace(t *testing.T) {
	body := []byte("in place obfuscation test value here")
	orig := append([]byte(nil), body...)
	ObfuscateInPlace(body, []byte("key"), 0x11223344, 0xc0, 1)
	assert.False(t, bytes.Equal(orig, body))
	DeobfuscateInPlace(body, []byte("key"), 0x11223344, 0xc0, 1)
	assert.Equal(t, orig, body)
}

func TestObfuscateDifferentKeysDiffer(t *testing.T) {
	body := []byte("same body different keys")
	a := Obfuscate(body, []byte("keyA"), 1, 0xc0, 1)
	b := Obfuscate(body, []byte("keyB"), 1, 0xc0, 1)
	assert.False(t, bytes.Equal(a, b))
	// Wrong key must fail to deobfuscate (returns garbage, not original).
	assert.NotEqual(t, body, Deobfuscate(a, []byte("keyB"), 1, 0xc0, 1))
	assert.Equal(t, body, Deobfuscate(a, []byte("keyA"), 1, 0xc0, 1))
}

func TestObfuscateDifferentSeqNoDiffer(t *testing.T) {
	body := []byte("sequence matters")
	a := Obfuscate(body, []byte("k"), 1, 0xc0, 1)
	b := Obfuscate(body, []byte("k"), 1, 0xc0, 2)
	assert.False(t, bytes.Equal(a, b))
}

func TestObfuscateEmptyBody(t *testing.T) {
	out := Obfuscate(nil, []byte("k"), 1, 0xc0, 1)
	assert.Empty(t, out)
}

func TestPolicyCheckUnencryptedFlag(t *testing.T) {
	p := Policy{}
	err := p.CheckUnencryptedFlag(true)
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrUnencryptedDisabled))

	assert.NoError(t, p.CheckUnencryptedFlag(false))

	p.AllowUnencrypted = true
	assert.NoError(t, p.CheckUnencryptedFlag(true))
}

func TestObfuscateKnownHex(t *testing.T) {
	// All-zero body of 16 bytes yields the raw first MD5 digest as the pad.
	body := make([]byte, 16)
	key := []byte("test")
	obf := Obfuscate(body, key, 0x01020304, 0xc0, 1)
	pad := referencePad(16, key, 0x01020304, 0xc0, 1)
	assert.Equal(t, hex.EncodeToString(pad), hex.EncodeToString(obf))
}
