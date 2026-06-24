// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package packet

import (
	"encoding/hex"
	"testing"
)

// seedHex decodes a hex string into a byte slice for use as a fuzz seed,
// failing the test on malformed input.
func seedHex(f *testing.F, s string) []byte {
	f.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatalf("bad seed hex %q: %v", s, err)
	}
	return b
}

// The fuzz targets below assert the single security-critical property of every
// decoder that parses untrusted network input: it MUST NOT panic, read out of
// bounds, or loop unboundedly on any byte sequence. When a decode succeeds, we
// additionally re-marshal to confirm the round trip does not panic.

func FuzzHeaderUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "c10203041234567800000100"))
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var h Header
		if err := h.UnmarshalBinary(data); err == nil {
			_, _ = h.MarshalBinary()
		}
	})
}

func FuzzAuthenStartUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "0100010100000000"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AuthenStart
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}

func FuzzAuthenContinueUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "000000000000"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AuthenContinue
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}

func FuzzAuthenReplyUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "0100000000000000"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AuthenReply
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}

func FuzzAuthorRequestUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "0001010100000000000000"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AuthorRequest
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}

func FuzzAuthorReplyUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "010000000000"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AuthorReply
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}

func FuzzAcctRequestUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "02000101010000000000000000"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AcctRequest
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}

func FuzzAcctReplyUnmarshal(f *testing.F) {
	f.Add(seedHex(f, "000000000100"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		var a AcctReply
		if err := a.UnmarshalBinary(data); err == nil {
			_, _ = a.MarshalBinary()
		}
	})
}
