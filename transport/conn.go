// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
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
}

// NewConn wraps an established network connection. For ModeLegacy, secret is
// the shared key used for MD5 obfuscation; for ModeTLS, secret is ignored.
func NewConn(c net.Conn, mode Mode, secret []byte) *Conn {
	return &Conn{raw: c, mode: mode, secret: secret}
}

// Mode returns the transport mode.
func (c *Conn) Mode() Mode { return c.mode }

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
func (c *Conn) ReadPacket() (packet.Header, []byte, error) {
	hdr, body, err := ReadPacket(c.raw)
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
