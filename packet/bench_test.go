// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package packet

import "testing"

func BenchmarkHeaderMarshal(b *testing.B) {
	h := Header{Version: 0xc0, Type: 1, SeqNo: 1, SessionID: 1, Length: 16}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = h.MarshalBinary()
	}
}

func BenchmarkHeaderUnmarshal(b *testing.B) {
	h := Header{Version: 0xc0, Type: 1, SeqNo: 1, SessionID: 1, Length: 16}
	data, _ := h.MarshalBinary()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var got Header
		_ = got.UnmarshalBinary(data)
	}
}

func BenchmarkAuthenStartMarshal(b *testing.B) {
	s := AuthenStart{
		Action: 1, PrivLvl: 1, Type: 1, Service: 1,
		User: "alice", Port: "tty0", RemAddr: "10.0.0.1",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = s.MarshalBinary()
	}
}
