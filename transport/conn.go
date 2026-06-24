// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package transport

import (
	"net"
	"time"

	"github.com/wxccs/tacacs/crypto"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/types"
)

// Mode indicates whether a transport uses legacy MD5 obfuscation (plain TCP)
// or TLS (which obsoletes obfuscation and forces the unencrypted flag).
type Mode int

// Transport modes.
const (
	// ModeLegacy uses the MD5 pseudo-pad obfuscation over plain TCP.
	ModeLegacy Mode = iota
	// ModeTLS uses TLS 1.3; obfuscation is forbidden and the unencrypted flag
	// MUST be set on every packet.
	ModeTLS
)

// Conn wraps a network connection and frames TACACS+ packets, applying the
// appropriate body protection for the mode: MD5 obfuscation for legacy TCP,
// and no obfuscation (cleartext body) for TLS.
type Conn struct {
	raw    net.Conn
	mode   Mode
	secret []byte
	// idleTimeout bounds the wait for the next packet's header to arrive; it
	// defends against idle/slow-loris connections that open and then stall. A
	// value <= 0 disables the bound (single-connection deployments that
	// legitimately keep a connection open between sessions may prefer this).
	idleTimeout time.Duration
	// readTimeout bounds the time to read a packet body once its header has
	// arrived; it defends against a peer that dribbles a body slowly. A value
	// <= 0 disables the bound.
	readTimeout time.Duration
}

// NewConn wraps an established network connection. For ModeLegacy, secret is
// the shared key used for MD5 obfuscation; for ModeTLS, secret is ignored.
func NewConn(c net.Conn, mode Mode, secret []byte) *Conn {
	return &Conn{raw: c, mode: mode, secret: secret}
}

// Mode returns the transport mode.
func (c *Conn) Mode() Mode { return c.mode }

// SetTimeouts configures the per-packet read deadlines applied by ReadPacket.
// idle bounds the wait for the next packet's header; read bounds the body read
// once the header has arrived. A value <= 0 for either disables that bound.
// SetTimeouts is not safe for concurrent use with ReadPacket; callers should
// set timeouts before serving the connection.
func (c *Conn) SetTimeouts(idle, read time.Duration) {
	c.idleTimeout = idle
	c.readTimeout = read
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.raw.Close() }

// SetDeadline sets the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// RemoteAddr returns the address of the remote peer.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// LocalAddr returns the address of the local end.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// UnderlyingConn returns the wrapped network connection, primarily for
// inspecting TLS state (e.g. ConnectionState).
func (c *Conn) UnderlyingConn() net.Conn { return c.raw }

// ReadPacket reads one TACACS+ packet and de-obfuscates the body if the mode
// is legacy and the unencrypted flag is clear. For TLS, the body is already
// cleartext (protected by TLS); the unencrypted flag MUST be set.
//
// When idle/read timeouts are configured (see SetTimeouts) they are applied as
// read deadlines: the idle timeout bounds the wait for the header, the read
// timeout bounds the body read. Any configured deadline is cleared before
// returning so it does not leak into subsequent writes.
func (c *Conn) ReadPacket() (packet.Header, []byte, error) {
	if c.idleTimeout > 0 || c.readTimeout > 0 {
		defer func() { _ = c.raw.SetReadDeadline(time.Time{}) }()
	}
	if c.idleTimeout > 0 {
		if err := c.raw.SetReadDeadline(time.Now().Add(c.idleTimeout)); err != nil {
			return packet.Header{}, nil, err
		}
	}
	hdr, err := ReadHeader(c.raw)
	if err != nil {
		return hdr, nil, err
	}
	if c.readTimeout > 0 {
		if err := c.raw.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return hdr, nil, err
		}
	}
	body, err := ReadBody(c.raw, hdr)
	if err != nil {
		return hdr, nil, err
	}
	if c.mode == ModeLegacy && !hdr.Flags.Has(types.FlagUnencrypted) && len(body) > 0 {
		crypto.DeobfuscateInPlace(body, c.secret, hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
	}
	return hdr, body, nil
}

// WritePacket obfuscates the body (legacy) or leaves it cleartext (TLS), sets
// the header length, and writes the packet. For TLS the unencrypted flag is
// forced on; for legacy it is left as configured by the caller.
func (c *Conn) WritePacket(hdr packet.Header, body []byte) error {
	out := body
	if c.mode == ModeLegacy && !hdr.Flags.Has(types.FlagUnencrypted) && len(body) > 0 {
		out = crypto.Obfuscate(body, c.secret, hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
	}
	if c.mode == ModeTLS {
		hdr.Flags |= types.FlagUnencrypted
	}
	return WritePacket(c.raw, hdr, out)
}
