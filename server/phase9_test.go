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

package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// noopHandler succeeds on everything and tracks calls.
type noopHandler struct{}

func (noopHandler) Authenticate(context.Context, server.AuthenContext, *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
}
func (noopHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
}
func (noopHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

func startNoopServerLoop(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	secret := []byte("key")
	srv := server.New(server.Config{Handler: noopHandler{}, Secret: secret, Mode: transport.ModeLegacy})
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

func TestServerAuthorArgParseError(t *testing.T) {
	ln := startNoopServerLoop(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	// Author request with an argument lacking a separator -> parse error ->
	// sendAuthorError (status 0x11).
	hdr := makeHeader(types.PacketAuthorization, 1)
	// Build a minimal author request with one bad arg (no '=' or '*').
	req := []byte{0x06, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03} // arg_cnt=1, arg_len=3
	req = append(req, []byte("bad")...)                                 // arg "bad" has no separator
	cryptoObfInPlace(req, hdr)
	writeRawPacket(t, conn, hdr, req)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, byte(2), rhdr.SeqNo)
	require.NotEmpty(t, rbody)
	assert.Equal(t, byte(0x11), rbody[0], "author ERROR on unparseable arg")
}

func TestServerAcctArgParseError(t *testing.T) {
	ln := startNoopServerLoop(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	hdr := makeHeader(types.PacketAccounting, 1)
	// acct: flags=start, then fields, arg_cnt=1, arg_len=3, bad arg.
	req := []byte{0x02, 0x06, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03}
	req = append(req, []byte("bad")...)
	cryptoObfInPlace(req, hdr)
	writeRawPacket(t, conn, hdr, req)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, byte(2), rhdr.SeqNo)
	require.NotEmpty(t, rbody)
	assert.Equal(t, byte(0x02), rbody[4], "acct ERROR on unparseable arg")
}

func TestServeConnContextCancel(t *testing.T) {
	// A connection that is idle: ServeConn blocks on ReadPacket. Cancelling the
	// context (and closing the peer so the blocking read returns) should make
	// ServeConn return an error.
	a, b := net.Pipe()
	conn := transport.Accept(b, transport.ModeLegacy, []byte("key"))
	srv := server.New(server.Config{Handler: noopHandler{}, Secret: []byte("key"), Mode: transport.ModeLegacy})

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.ServeConn(ctx, conn)
		assert.Error(t, err)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	a.Close() // unblock the read so ServeConn observes the cancellation/EOF
	wg.Wait()
	b.Close()
}

func TestServerServesMultiplePackets(t *testing.T) {
	// Drive two sequential requests on one connection to exercise the
	// ServeConn loop beyond the first packet.
	ln := startNoopServerLoop(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	// First: authz pass.
	writeAuthorRequest(t, conn, "alice", []string{"cmd=show"})
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, byte(2), rhdr.SeqNo)
	assert.Equal(t, byte(0x01), rbody[0], "PASS_ADD")

	// Second: acct success (new session_id).
	writeAcctRequest(t, conn, types.AcctFlagStart, "alice", []string{"task_id=1"})
	rhdr2, rbody2 := readPacket(t, conn)
	assert.Equal(t, byte(2), rhdr2.SeqNo)
	assert.Equal(t, byte(0x01), rbody2[4], "acct SUCCESS")
}
