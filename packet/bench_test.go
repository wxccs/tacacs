// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
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
