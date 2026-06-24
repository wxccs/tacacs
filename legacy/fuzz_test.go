// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package legacy

import "testing"

// These targets assert that the RFC 1492 decoders never panic on arbitrary
// input. UDP packets are binary; the TCP request/reply are line-oriented ASCII.

func FuzzUDPSimpleUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var p UDPSimple
		_ = p.UnmarshalBinary(data)
	})
}

func FuzzUDPExtendedUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 24))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var p UDPExtended
		_ = p.UnmarshalBinary(data)
	})
}

func FuzzTCPRequestUnmarshal(f *testing.F) {
	f.Add([]byte("LOGIN\nalice\nsecret\ntty0\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var r TCPRequest
		_ = r.UnmarshalText(data)
	})
}

func FuzzTCPReplyUnmarshal(f *testing.F) {
	f.Add([]byte("ACCEPTED\n"))
	f.Add([]byte(""))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var r TCPReply
		_ = r.UnmarshalText(data)
	})
}
