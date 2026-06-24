// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package proxy

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

// FuzzReadHeader exercises the PROXY header parser (v1 text and v2 binary) on
// arbitrary input. The property under test: ReadHeader must never panic and,
// on success, must return a non-nil *net.TCPAddr.
func FuzzReadHeader(f *testing.F) {
	f.Add([]byte("PROXY TCP4 10.0.0.1 192.168.1.1 12345 49\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(append(v2Sig[:], 0x21, 0x11, 0x00, 0x0c))
	f.Add([]byte{0xc0, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		addr, err := ReadHeader(r)
		if err == nil {
			if _, ok := addr.(*net.TCPAddr); !ok {
				t.Fatalf("ReadHeader returned %T, want *net.TCPAddr", addr)
			}
		}
	})
}
