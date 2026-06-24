// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
// Package proxy implements parsing of the HAProxy PROXY protocol v1
// (ASCII), used to convey the real client address through a TCP load
// balancer. Only v1 is supported, matching the scope of tacquito's proxy
// package.
//
// Reference: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
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

// ReadHeader reads a PROXY v1 header from r and returns the real client
// address. If the connection does not begin with the PROXY signature,
// ErrNoProxyHeader is returned without consuming any bytes (the reader's
// position is left at the start so the caller can fall back to normal
// TACACS+ framing).
//
// On success the entire header line including the trailing CRLF has been
// consumed.
func ReadHeader(r *bufio.Reader) (net.Addr, error) {
	// Peek the first byte; if it's not 'P', there's no PROXY header.
	peek, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	if peek[0] != 'P' {
		return nil, ErrNoProxyHeader
	}
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
