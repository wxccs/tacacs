// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package transport

import (
	"bytes"
	"testing"
)

// FuzzReadPacket asserts the framing layer never panics on arbitrary wire
// bytes. A bounded length field must be honored so a malicious header cannot
// drive an unbounded allocation; the body read simply ends in a short-read
// error rather than over-allocating.
func FuzzReadPacket(f *testing.F) {
	f.Add(append([]byte{0xc1, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x02}, 0xaa, 0xbb))
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = ReadPacket(bytes.NewReader(data))
	})
}
