// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package proxy

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestReadHeaderTCP4(t *testing.T) {
	raw := "PROXY TCP4 10.0.0.1 192.168.1.1 12345 49\r\n"
	r := bufio.NewReader(bytes.NewReader([]byte(raw)))
	addr, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type = %T, want *net.TCPAddr", addr)
	}
	if ta.IP.String() != "10.0.0.1" {
		t.Errorf("ip = %s, want 10.0.0.1", ta.IP)
	}
	if ta.Port != 12345 {
		t.Errorf("port = %d, want 12345", ta.Port)
	}
}

func TestReadHeaderTCP6(t *testing.T) {
	raw := "PROXY TCP6 2001:db8::1 2001:db8::2 12345 49\r\n"
	r := bufio.NewReader(bytes.NewReader([]byte(raw)))
	addr, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ta := addr.(*net.TCPAddr)
	if ta.IP.String() != "2001:db8::1" {
		t.Errorf("ip = %s, want 2001:db8::1", ta.IP)
	}
}

func TestReadHeaderUnknown(t *testing.T) {
	raw := "PROXY UNKNOWN\r\n"
	r := bufio.NewReader(bytes.NewReader([]byte(raw)))
	_, err := ReadHeader(r)
	if err != ErrNoProxyHeader {
		t.Errorf("err = %v, want ErrNoProxyHeader", err)
	}
}

func TestReadHeaderNoProxyHeader(t *testing.T) {
	// First byte is not 'P' — a TACACS+ packet header.
	raw := []byte{0xc0, 0x01, 0x00}
	r := bufio.NewReader(bytes.NewReader(raw))
	_, err := ReadHeader(r)
	if err != ErrNoProxyHeader {
		t.Errorf("err = %v, want ErrNoProxyHeader", err)
	}
	// Verify that the full original bytes are still readable (none consumed).
	out := make([]byte, len(raw))
	n, _ := r.Read(out)
	if n != len(raw) || !bytes.Equal(out[:n], raw) {
		t.Errorf("after no-proxy: read %d bytes %v, want %d bytes %v", n, out[:n], len(raw), raw)
	}
}

func TestReadHeaderMalformed(t *testing.T) {
	cases := []string{
		"PROXY TCP4 not-an-ip 192.168.1.1 12345 49\r\n",
		"PROXY TCP4 10.0.0.1 192.168.1.1\r\n",
		"PROXY TCP4 10.0.0.1 192.168.1.1 99999 49\r\n",
		"PROXY TCP4 10.0.0.1 192.168.1.1 12345 49 99\r\n",
		"PROXY WEIRD\r\n",
	}
	for _, c := range cases {
		r := bufio.NewReader(bytes.NewReader([]byte(c)))
		_, err := ReadHeader(r)
		if err != ErrMalformedProxy {
			t.Errorf("for %q: err = %v, want ErrMalformedProxy", c, err)
		}
	}
}

func TestReadHeaderFamilyMismatch(t *testing.T) {
	// TCP4 with v6 address.
	raw := "PROXY TCP4 2001:db8::1 10.0.0.1 12345 49\r\n"
	r := bufio.NewReader(bytes.NewReader([]byte(raw)))
	_, err := ReadHeader(r)
	if err != ErrMalformedProxy {
		t.Errorf("err = %v, want ErrMalformedProxy", err)
	}
}

func TestWriteHeaderRoundTrip(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	proxyAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 49}
	var buf bytes.Buffer
	if err := WriteHeader(&buf, client, proxyAddr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	addr, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	ta := addr.(*net.TCPAddr)
	if ta.IP.String() != "10.0.0.1" || ta.Port != 12345 {
		t.Errorf("round-trip = %s:%d, want 10.0.0.1:12345", ta.IP, ta.Port)
	}
}
