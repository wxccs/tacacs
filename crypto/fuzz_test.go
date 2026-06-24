// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package crypto

import (
	"bytes"
	"testing"
)

// FuzzObfuscateRoundtrip asserts that de-obfuscation inverts obfuscation for
// any body, key, and session parameters, and that neither direction panics.
// The MD5 pseudo-pad XOR is its own inverse, so Deobfuscate(Obfuscate(b)) must
// recover b exactly.
func FuzzObfuscateRoundtrip(f *testing.F) {
	f.Add([]byte("password"), []byte("secret"), uint32(0x12345678), uint8(0xc1), uint8(1))
	f.Add([]byte{}, []byte("k"), uint32(0), uint8(0), uint8(0))
	f.Add([]byte("a"), []byte{}, uint32(1), uint8(0xc0), uint8(3))
	f.Fuzz(func(t *testing.T, body, key []byte, sessionID uint32, version, seqNo uint8) {
		orig := bytes.Clone(body)
		obf := Obfuscate(body, key, sessionID, version, seqNo)
		got := Deobfuscate(obf, key, sessionID, version, seqNo)
		if !bytes.Equal(got, orig) {
			t.Fatalf("roundtrip mismatch: got %x want %x", got, orig)
		}
	})
}
