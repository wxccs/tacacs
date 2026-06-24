// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// MaxHeaderLen is the maximum length of a PROXY v1 header (per spec).
const MaxHeaderLen = 108

// ProtocolV1Prefix is the ASCII signature that starts every PROXY v1 header.
const ProtocolV1Prefix = "PROXY "

var (
	// ErrNoProxyHeader is returned by ReadHeader when the first bytes do not
	// begin the PROXY v1 signature. Callers may treat this as "no PROXY
	// header present" and fall back to the connection's RemoteAddr.
	ErrNoProxyHeader = errors.New("proxy: no PROXY v1 header")
	// ErrMalformedProxy is returned when a PROXY v1 header is present but
	// malformed (wrong field count, bad IP, bad port, etc.).
	ErrMalformedProxy = errors.New("proxy: malformed PROXY v1 header")
)

// ReadHeader reads a PROXY protocol header (v1 text or v2 binary) from r and
// returns the real client address. It dispatches on the first byte: 'P' begins
// the v1 signature, 0x0D begins the v2 signature. Any other first byte means
// no PROXY header is present and ErrNoProxyHeader is returned without consuming
// any bytes, so the caller can fall back to normal TACACS+ framing.
//
// On success the entire header (line+CRLF for v1, fixed block+address+TLVs for
// v2) has been consumed and r is positioned at the first payload byte.
func ReadHeader(r *bufio.Reader) (net.Addr, error) {
	peek, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	switch peek[0] {
	case 'P':
		return readHeaderV1(r)
	case v2Sig[0]:
		return readHeaderV2(r)
	default:
		return nil, ErrNoProxyHeader
	}
}

// readHeaderV1 parses a PROXY v1 text header. The first byte ('P') has already
// been confirmed by ReadHeader but not consumed.
func readHeaderV1(r *bufio.Reader) (net.Addr, error) {
	// Read the full line (up to MaxHeaderLen).
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) > MaxHeaderLen {
		return nil, ErrMalformedProxy
	}
	// Strip trailing \r\n.
	line = strings.TrimRight(line, "\r\n")
	return parseLine(line)
}

func parseLine(line string) (net.Addr, error) {
	// Expected: "PROXY TCP4 <src> <dst> <sport> <dport>" or the TCP6 variant,
	// or "PROXY UNKNOWN".
	parts := strings.Split(line, " ")
	if len(parts) < 2 || parts[0] != "PROXY" {
		return nil, ErrMalformedProxy
	}
	proto := parts[1]
	if proto == "UNKNOWN" {
		return nil, ErrNoProxyHeader
	}
	if proto != "TCP4" && proto != "TCP6" {
		return nil, ErrMalformedProxy
	}
	if len(parts) != 6 {
		return nil, ErrMalformedProxy
	}
	srcIP := net.ParseIP(parts[2])
	dstIP := net.ParseIP(parts[3])
	if srcIP == nil || dstIP == nil {
		return nil, ErrMalformedProxy
	}
	srcPort, err := strconv.Atoi(parts[4])
	if err != nil || srcPort < 0 || srcPort > 65535 {
		return nil, ErrMalformedProxy
	}
	dstPort, err := strconv.Atoi(parts[5])
	if err != nil || dstPort < 0 || dstPort > 65535 {
		return nil, ErrMalformedProxy
	}
	// Validate address family consistency.
	if proto == "TCP4" && (srcIP.To4() == nil || dstIP.To4() == nil) {
		return nil, ErrMalformedProxy
	}
	if proto == "TCP6" && (srcIP.To4() != nil || dstIP.To4() != nil) {
		return nil, ErrMalformedProxy
	}
	return &net.TCPAddr{IP: srcIP, Port: srcPort, Zone: ""}, nil
}

// WriteHeader writes a PROXY v1 header describing client and proxy to w.
// Both addresses must be *net.TCPAddr. It is intended for clients/proxies
// that produce PROXY headers (not for the TACACS+ server itself).
func WriteHeader(w io.Writer, client, proxy net.Addr) error {
	c, ok := client.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("proxy: client must be *net.TCPAddr, got %T", client)
	}
	p, ok := proxy.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("proxy: proxy must be *net.TCPAddr, got %T", proxy)
	}
	proto := "TCP4"
	if c.IP.To4() == nil {
		proto = "TCP6"
	}
	_, err := fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n",
		proto, c.IP, p.IP, c.Port, p.Port)
	return err
}
