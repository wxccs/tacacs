// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// buildV2 constructs a PROXY v2 header with the given command, family and
// address block, followed by the supplied payload bytes.
func buildV2(verCmd, famProto byte, addr, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write(v2Sig[:])
	buf.WriteByte(verCmd)
	buf.WriteByte(famProto)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(addr)))
	buf.Write(l[:])
	buf.Write(addr)
	buf.Write(payload)
	return buf.Bytes()
}

func v2Inet(src, dst net.IP, sport, dport uint16) []byte {
	b := make([]byte, 0, v2AddrLenInet)
	b = append(b, src.To4()...)
	b = append(b, dst.To4()...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], sport)
	b = append(b, p[:]...)
	binary.BigEndian.PutUint16(p[:], dport)
	b = append(b, p[:]...)
	return b
}

func v2Inet6(src, dst net.IP, sport, dport uint16) []byte {
	b := make([]byte, 0, v2AddrLenInet6)
	b = append(b, src.To16()...)
	b = append(b, dst.To16()...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], sport)
	b = append(b, p[:]...)
	binary.BigEndian.PutUint16(p[:], dport)
	b = append(b, p[:]...)
	return b
}

func TestReadHeaderV2Inet(t *testing.T) {
	addr := v2Inet(net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"), 12345, 49)
	payload := []byte{0xc0, 0x01, 0x02}
	raw := buildV2(v2Version<<4|v2CmdProxy, v2FamInet<<4|0x1, addr, payload)

	r := bufio.NewReader(bytes.NewReader(raw))
	got, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ta, ok := got.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type = %T, want *net.TCPAddr", got)
	}
	if ta.IP.String() != "10.0.0.1" || ta.Port != 12345 {
		t.Errorf("addr = %s:%d, want 10.0.0.1:12345", ta.IP, ta.Port)
	}
	// The payload following the header must remain readable.
	out := make([]byte, len(payload))
	if _, err := r.Read(out); err != nil || !bytes.Equal(out, payload) {
		t.Errorf("payload = %v (err %v), want %v", out, err, payload)
	}
}

func TestReadHeaderV2Inet6(t *testing.T) {
	addr := v2Inet6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 33333, 49)
	raw := buildV2(v2Version<<4|v2CmdProxy, v2FamInet6<<4|0x1, addr, nil)

	r := bufio.NewReader(bytes.NewReader(raw))
	got, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ta := got.(*net.TCPAddr)
	if ta.IP.String() != "2001:db8::1" || ta.Port != 33333 {
		t.Errorf("addr = %s:%d, want 2001:db8::1:33333", ta.IP, ta.Port)
	}
}

// TestReadHeaderV2WithTLV verifies trailing TLV bytes (advertised in the
// length but beyond the address block) are consumed and the address still
// parses.
func TestReadHeaderV2WithTLV(t *testing.T) {
	addr := v2Inet(net.ParseIP("10.0.0.7"), net.ParseIP("10.0.0.8"), 5000, 49)
	tlv := []byte{0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef} // PP2_TYPE_CRC32C-ish
	block := append(addr, tlv...)
	payload := []byte{0xc1}
	raw := buildV2(v2Version<<4|v2CmdProxy, v2FamInet<<4|0x1, block, payload)

	r := bufio.NewReader(bytes.NewReader(raw))
	got, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.(*net.TCPAddr).IP.String() != "10.0.0.7" {
		t.Errorf("ip = %s, want 10.0.0.7", got.(*net.TCPAddr).IP)
	}
	out := make([]byte, len(payload))
	if _, err := r.Read(out); err != nil || !bytes.Equal(out, payload) {
		t.Errorf("payload = %v (err %v), want %v", out, err, payload)
	}
}

// TestReadHeaderV2Local verifies a LOCAL command falls back to RemoteAddr
// (ErrNoProxyHeader) after consuming the header.
func TestReadHeaderV2Local(t *testing.T) {
	raw := buildV2(v2Version<<4|v2CmdLocal, 0x00, nil, []byte{0xc0})
	r := bufio.NewReader(bytes.NewReader(raw))
	_, err := ReadHeader(r)
	if err != ErrNoProxyHeader {
		t.Errorf("err = %v, want ErrNoProxyHeader", err)
	}
	// Payload after the (empty) header still readable.
	b, _ := r.ReadByte()
	if b != 0xc0 {
		t.Errorf("payload byte = %#x, want 0xc0", b)
	}
}

// TestReadHeaderV2UnspecFamily verifies an unsupported family falls back.
func TestReadHeaderV2UnspecFamily(t *testing.T) {
	raw := buildV2(v2Version<<4|v2CmdProxy, 0x00, []byte{0x01, 0x02}, nil)
	r := bufio.NewReader(bytes.NewReader(raw))
	_, err := ReadHeader(r)
	if err != ErrNoProxyHeader {
		t.Errorf("err = %v, want ErrNoProxyHeader", err)
	}
}

func TestReadHeaderV2Malformed(t *testing.T) {
	// Bad signature (right first byte, wrong rest).
	badSig := buildV2(v2Version<<4|v2CmdProxy, v2FamInet<<4|0x1, v2Inet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2), nil)
	badSig[5] = 0xFF // corrupt signature
	// Wrong version.
	badVer := buildV2(0x10|v2CmdProxy, v2FamInet<<4|0x1, v2Inet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2), nil)
	// Bad command.
	badCmd := buildV2(v2Version<<4|0x7, v2FamInet<<4|0x1, v2Inet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2), nil)
	// INET family but truncated address block.
	shortAddr := buildV2(v2Version<<4|v2CmdProxy, v2FamInet<<4|0x1, []byte{0x0a, 0x00}, nil)

	for name, raw := range map[string][]byte{
		"badSig": badSig, "badVer": badVer, "badCmd": badCmd, "shortAddr": shortAddr,
	} {
		r := bufio.NewReader(bytes.NewReader(raw))
		if _, err := ReadHeader(r); err != ErrMalformedProxy {
			t.Errorf("%s: err = %v, want ErrMalformedProxy", name, err)
		}
	}
}
