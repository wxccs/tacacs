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
	"context"
	"crypto/tls"
	"net"
)

// Dial connects to a TACACS+ server over plain TCP (legacy, port 49) using MD5
// obfuscation with the given shared secret. Per RFC 9887 §5.1.1 a client MUST
// NOT fail back to a non-TLS connection if a TLS connection fails; the caller
// is responsible for not retrying over TLS after this returns an error.
func Dial(ctx context.Context, network, address string, secret []byte) (*Conn, error) {
	d := net.Dialer{}
	nc, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewConn(nc, ModeLegacy, secret), nil
}

// DialTLS connects to a TACACS+ server over TLS 1.3 (port 300). It performs the
// TLS handshake before returning; the caller MUST NOT send 0-RTT data
// (RFC 9887 §5.1.2).
func DialTLS(ctx context.Context, network, address string, cfg *tls.Config) (*Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	nc, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewConn(nc, ModeTLS, nil), nil
}

// Listen starts a TCP listener on the address (legacy, port 49).
func Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

// ListenTLS starts a TLS 1.3 listener on the address (port 300).
func ListenTLS(network, address string, cfg *tls.Config) (net.Listener, error) {
	return tls.Listen(network, address, cfg)
}

// Accept wraps a raw server-side connection using the given mode and secret.
func Accept(nc net.Conn, mode Mode, secret []byte) *Conn {
	return NewConn(nc, mode, secret)
}
