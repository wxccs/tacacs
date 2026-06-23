// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

package server_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

func startUsersServerLoop(t *testing.T, secret []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := server.New(server.Config{Handler: &usersHandler{users: map[string]string{"a": "p"}, cmds: map[string]bool{}, t: t}, Secret: secret, Mode: transport.ModeLegacy})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conn := transport.Accept(c, transport.ModeLegacy, secret)
			go func() { _ = srv.ServeConn(context.Background(), conn) }()
		}
	}()
	return ln
}

func TestServerMalformedAuthenStart(t *testing.T) {
	ln := startUsersServerLoop(t, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	// Send an authen packet with a body too short to be a valid START.
	hdr := makeHeader(types.PacketAuthentication, 1)
	body := []byte{0x01, 0x02} // too short
	cryptoObfInPlace(body, hdr)
	writeRawPacket(t, conn, hdr, body)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, uint32(0), rhdr.Length, "malformed START -> generic header-only error")
	assert.Empty(t, rbody)
}

func TestServerMalformedAuthorRequest(t *testing.T) {
	ln := startUsersServerLoop(t, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	hdr := makeHeader(types.PacketAuthorization, 1)
	body := []byte{0x01} // too short
	cryptoObfInPlace(body, hdr)
	writeRawPacket(t, conn, hdr, body)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, uint32(0), rhdr.Length, "malformed author REQUEST -> generic error")
	assert.Empty(t, rbody)
}

func TestServerMalformedAcctRequest(t *testing.T) {
	ln := startUsersServerLoop(t, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	hdr := makeHeader(types.PacketAccounting, 1)
	body := []byte{0x02} // too short
	cryptoObfInPlace(body, hdr)
	writeRawPacket(t, conn, hdr, body)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, uint32(0), rhdr.Length)
	assert.Empty(t, rbody)
}

func TestServerUnknownPacketType(t *testing.T) {
	ln := startUsersServerLoop(t, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	hdr := makeHeader(types.PacketType(0x09), 1) // unsupported type
	body := []byte{}
	writeRawPacket(t, conn, hdr, body)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, uint32(0), rhdr.Length, "unknown type -> generic error")
	assert.Empty(t, rbody)
}

func TestServerRemoteAddr(t *testing.T) {
	ln := startUsersServerLoop(t, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()
	// A normal PAP auth exercises remoteAddr (non-empty client address).
	writeAuthenStart(t, conn, types.AuthenTypePAP, "a", []byte("p"))
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, byte(2), rhdr.SeqNo)
	assert.NotEmpty(t, rbody)
}
