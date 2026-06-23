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

package crypto

import "testing"

func BenchmarkObfuscate(b *testing.B) {
	body := make([]byte, 256)
	key := []byte("sharedsecretkey")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Obfuscate(body, key, 0x12345678, 0xc0, 1)
	}
}

func BenchmarkObfuscateLarge(b *testing.B) {
	body := make([]byte, 4096)
	key := []byte("sharedsecretkey")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Obfuscate(body, key, 0x12345678, 0xc0, 1)
	}
}
