// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// erroringHandler returns errors for each method to exercise the typed-error paths.
type erroringHandler struct{}

func (erroringHandler) Authenticate(context.Context, server.AuthenContext, *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{}, errors.New("boom")
}
func (erroringHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{}, errors.New("boom")
}
func (erroringHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{}, errors.New("boom")
}

func startErrServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	secret := []byte("key")
	srv := server.New(server.Config{Handler: erroringHandler{}, Secret: secret, Mode: transport.ModeLegacy})
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

func TestServerAuthenHandlerErrorReturnsErrorStatus(t *testing.T) {
	ln := startErrServer(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	// Send a PAP START; handler errors, server replies with ERROR status.
	writeAuthenStart(t, conn, types.AuthenTypePAP, "alice", []byte("pw"))
	hdr, body := readPacket(t, conn)
	assert.Equal(t, byte(2), hdr.SeqNo)
	assert.Contains(t, string(body), "\x07", "status byte == ERROR (0x07)")
}

func TestServerAuthorHandlerErrorReturnsErrorStatus(t *testing.T) {
	ln := startErrServer(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	writeAuthorRequest(t, conn, "alice", []string{"cmd=show"})
	hdr, body := readPacket(t, conn)
	assert.Equal(t, byte(2), hdr.SeqNo)
	assert.NotEmpty(t, body)
	assert.Equal(t, byte(0x11), body[0], "author ERROR status 0x11")
}

func TestServerAcctHandlerErrorReturnsErrorStatus(t *testing.T) {
	ln := startErrServer(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dialRaw(t, port)
	defer conn.Close()

	writeAcctRequest(t, conn, types.AcctFlagStart, "alice", []string{"task_id=1"})
	hdr, body := readPacket(t, conn)
	assert.Equal(t, byte(2), hdr.SeqNo)
	assert.Equal(t, byte(0x02), body[4], "acct ERROR status 0x02 (at offset 4)")
}

func TestServerFlagPolicyRejectsUnencrypted(t *testing.T) {
	// A legacy server without AllowUnencrypted should reject a packet with the
	// unencrypted flag set, returning a generic header-only error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	secret := []byte("key")
	srv := server.New(server.Config{Handler: erroringHandler{}, Secret: secret, Mode: transport.ModeLegacy})
	go func() {
		c, _ := ln.Accept()
		conn := transport.Accept(c, transport.ModeLegacy, secret)
		_ = srv.ServeConn(context.Background(), conn)
	}()

	// Use a transport.Conn but force the unencrypted flag on the write.
	conn := dialRaw(t, port)
	defer conn.Close()
	hdr := makeHeader(types.PacketAuthentication, 1)
	hdr.Flags = types.FlagUnencrypted
	body := mustMarshalAuthenStart(types.AuthenTypePAP, "alice", []byte("pw"))
	writeRawPacket(t, conn, hdr, body)

	// Server returns a header-only error (length 0).
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, uint32(0), rhdr.Length)
	assert.Empty(t, rbody)
}

func TestServerAllowUnencryptedAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	secret := []byte("key")
	srv := server.New(server.Config{Handler: &usersHandler{users: map[string]string{"alice": "pw"}, t: t}, Secret: secret, Mode: transport.ModeLegacy, AllowUnencrypted: true})
	go func() {
		c, _ := ln.Accept()
		conn := transport.Accept(c, transport.ModeLegacy, secret)
		_ = srv.ServeConn(context.Background(), conn)
	}()

	conn := dialRaw(t, port)
	defer conn.Close()
	// Write with unencrypted flag set; body is cleartext (no obfuscation).
	hdr := makeHeader(types.PacketAuthentication, 1)
	hdr.Flags = types.FlagUnencrypted
	body := mustMarshalAuthenStart(types.AuthenTypePAP, "alice", []byte("pw"))
	writeRawPacket(t, conn, hdr, body)
	rhdr, rbody := readPacket(t, conn)
	assert.Equal(t, byte(2), rhdr.SeqNo)
	assert.NotEmpty(t, rbody)
}

func TestHandlerFunc(t *testing.T) {
	hf := server.HandlerFunc{
		AuthenFunc: func(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
			return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
		},
		AuthorFunc: func(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
			return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
		},
		AcctFunc: func(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
			return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
		},
	}
	d, err := hf.Authenticate(context.Background(), server.AuthenContext{}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, d.Status)
	_, err = hf.Authorize(context.Background(), server.AuthorContext{})
	require.NoError(t, err)
	_, err = hf.Account(context.Background(), server.AcctContext{})
	require.NoError(t, err)
}
