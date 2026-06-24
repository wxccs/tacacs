// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

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
