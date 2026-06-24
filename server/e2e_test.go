// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// usersHandler is a simple test Handler backed by an in-memory user table.
type usersHandler struct {
	users map[string]string // username -> password
	cmds  map[string]bool   // allowed commands
	t     *testing.T
}

func (h *usersHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	if cont == nil {
		// START. For PAP, the password is in Start.Data.
		if ac.Start.Type == types.AuthenTypePAP {
			pw := string(ac.Start.Data)
			if h.users[ac.Start.User] == pw {
				return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
			}
			return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad credentials"}, nil
		}
		// ASCII: ask for the password.
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}
	// CONTINUE: the user message is the password.
	pw := cont.UserMsg
	if h.users[ac.Start.User] == pw {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad credentials"}, nil
}

func (h *usersHandler) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
	cmd := ""
	for _, a := range ac.Args {
		if a.Name == "cmd" {
			cmd = a.Value
		}
	}
	if h.cmds[cmd] {
		return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
	}
	return server.AuthorDecision{Status: types.AuthorStatusFail}, nil
}

func (h *usersHandler) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// runServer launches a server goroutine that accepts one connection and serves
// it. It returns immediately so the test can dial.
func runServer(t *testing.T, cfg server.Config, ln net.Listener) {
	srv := server.New(cfg)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := transport.Accept(c, cfg.Mode, cfg.Secret)
		_ = srv.ServeConn(context.Background(), conn)
	}()
}

func newTCPListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestE2EPAPAuthSuccess(t *testing.T) {
	h := &usersHandler{
		users: map[string]string{"alice": "secret123"},
		t:     t,
	}
	ln, port := newTCPListener(t)
	defer ln.Close()
	secret := []byte("sharedkey")
	runServer(t, server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), secret)
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	reply, err := cl.Authenticate(ctx, client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("secret123"),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status)
}

func TestE2EPAPAuthFail(t *testing.T) {
	h := &usersHandler{users: map[string]string{"alice": "secret123"}, t: t}
	ln, port := newTCPListener(t)
	defer ln.Close()
	secret := []byte("sharedkey")
	runServer(t, server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), secret)
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	reply, err := cl.Authenticate(ctx, client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("wrongpw"),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusFail, reply.Status)
	assert.Equal(t, "bad credentials", reply.ServerMsg)
}

func TestE2EASCIIAuthInteractive(t *testing.T) {
	h := &usersHandler{users: map[string]string{"bob": "hunter2"}, t: t}
	ln, port := newTCPListener(t)
	defer ln.Close()
	secret := []byte("sharedkey")
	runServer(t, server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), secret)
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	// Interactive: the server asks for a password, the contFn supplies it.
	var prompted bool
	reply, err := cl.Authenticate(ctx, client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
		User: "bob",
	}, func(r client.AuthenReply) (string, error) {
		assert.Equal(t, types.AuthenStatusGetPass, r.Status)
		prompted = true
		return "hunter2", nil
	})
	require.NoError(t, err)
	assert.True(t, prompted, "contFn should have been called for GETPASS")
	assert.Equal(t, types.AuthenStatusPass, reply.Status)
}

func TestE2EAuthorize(t *testing.T) {
	h := &usersHandler{
		users: map[string]string{"alice": "pw"},
		cmds:  map[string]bool{"show": true, "configure": false},
		t:     t,
	}
	ln, port := newTCPListener(t)
	defer ln.Close()
	secret := []byte("sharedkey")
	runServer(t, server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), secret)
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	// Allowed command.
	res, err := cl.Authorize(ctx, client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "service", Value: "shell"}, {Mandatory: true, Name: "cmd", Value: "show"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, res.Status)

	// Disallowed command.
	res, err = cl.Authorize(ctx, client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "configure"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, res.Status)
}

func TestE2EAccountingStartStop(t *testing.T) {
	h := &usersHandler{users: map[string]string{}, cmds: map[string]bool{}, t: t}
	ln, port := newTCPListener(t)
	defer ln.Close()
	secret := []byte("sharedkey")
	runServer(t, server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), secret)
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	res, err := cl.Account(ctx, client.AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "task_id", Value: "1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, res.Status)

	res, err = cl.Account(ctx, client.AcctRequest{
		Flags: types.AcctFlagStop, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "task_id", Value: "1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, res.Status)
}

func TestE2EAccountingInvalidFlags(t *testing.T) {
	h := &usersHandler{users: map[string]string{}, cmds: map[string]bool{}, t: t}
	ln, port := newTCPListener(t)
	defer ln.Close()
	secret := []byte("sharedkey")
	runServer(t, server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), secret)
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	// Invalid flag combination (start+stop): server MUST respond ERROR.
	res, err := cl.Account(ctx, client.AcctRequest{
		Flags: types.AcctFlagStart | types.AcctFlagStop, Method: types.AuthenMethodTacacsPlus,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusError, res.Status)
}

func TestE2ESecretMismatch(t *testing.T) {
	h := &usersHandler{users: map[string]string{"alice": "pw"}, t: t}
	ln, port := newTCPListener(t)
	defer ln.Close()
	serverSecret := []byte("correct-secret")
	runServer(t, server.Config{Handler: h, Secret: serverSecret, Mode: transport.ModeLegacy}, ln)

	ctx := context.Background()
	// Client uses a wrong secret; the server's length-sum integrity check
	// fails on the first packet, so the server returns an error/terminates.
	conn, err := transport.Dial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), []byte("wrong-secret"))
	require.NoError(t, err)
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)

	_, err = cl.Authenticate(ctx, client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("pw"),
	}, nil)
	assert.Error(t, err, "secret mismatch should surface as an error")
}

func TestE2ETLSAuth(t *testing.T) {
	// Reuse the transport test CA generator indirectly by building certs here.
	ca := newTestCA(t, "ca")
	serverCert := ca.leaf(t, "localhost")
	clientCert := ca.leaf(t, "client")

	h := &usersHandler{users: map[string]string{"alice": "secret123"}, t: t}
	serverCfg := transport.ServerTLSConfig(serverCert, ca.pool())
	ln, err := transport.ListenTLS("tcp", "127.0.0.1:0", serverCfg)
	require.NoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Start the TACACS+ server over TLS.
	srv := server.New(server.Config{Handler: h, Mode: transport.ModeTLS})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := transport.Accept(c, transport.ModeTLS, nil)
		_ = srv.ServeConn(context.Background(), conn)
	}()

	clientTLS, err := transport.TLSConfig{ServerName: "localhost", CACertPool: ca.pool(), ClientCert: clientCert}.ClientTLSConfig()
	require.NoError(t, err)
	conn, err := transport.DialTLS(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port), clientTLS)
	require.NoError(t, err)
	defer conn.Close()

	// Verify TLS 1.3 negotiated.
	st := conn.UnderlyingConn().(*tls.Conn).ConnectionState()
	assert.Equal(t, uint16(tls.VersionTLS13), st.Version)

	cl, err := client.New(conn)
	require.NoError(t, err)
	reply, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("secret123"),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status)
}
