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

package client_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// memHandler is a simple in-memory AAA handler for client tests.
type memHandler struct {
	users map[string]string
	cmds  map[string]bool
}

func (h *memHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	if cont == nil {
		if ac.Start.Type == types.AuthenTypePAP {
			if h.users[ac.Start.User] == string(ac.Start.Data) {
				return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
			}
			return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad"}, nil
		}
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}
	if h.users[ac.Start.User] == cont.UserMsg {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "bad"}, nil
}

func (h *memHandler) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
	for _, a := range ac.Args {
		if a.Name == "cmd" && h.cmds[a.Value] {
			return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
		}
	}
	return server.AuthorDecision{Status: types.AuthorStatusFail}, nil
}

func (h *memHandler) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

func startServer(t *testing.T, secret []byte) (*server.Server, net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := server.New(server.Config{Handler: &memHandler{
		users: map[string]string{"alice": "secret123", "bob": "hunter2"},
		cmds:  map[string]bool{"show": true},
	}, Secret: secret, Mode: transport.ModeLegacy})
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
	return srv, ln, ln.Addr().(*net.TCPAddr).Port
}

func dial(t *testing.T, port int, secret []byte) *transport.Conn {
	// Use a dialer with a timeout rather than a cancellable context: cancelling
	// the context after Dial returns would close the established connection.
	d := net.Dialer{Timeout: 5 * time.Second}
	nc, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	return transport.NewConn(nc, transport.ModeLegacy, secret)
}

func TestClientPAPAuth(t *testing.T) {
	_, ln, port := startServer(t, []byte("key"))
	defer ln.Close()
	conn := dial(t, port, []byte("key"))
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)
	reply, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("secret123"),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status)

	// Wrong password.
	conn2 := dial(t, port, []byte("key"))
	defer conn2.Close()
	cl2, _ := client.New(conn2)
	reply, err = cl2.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("nope"),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusFail, reply.Status)
}

func TestClientASCIIInteractive(t *testing.T) {
	_, ln, port := startServer(t, []byte("key"))
	defer ln.Close()
	conn := dial(t, port, []byte("key"))
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)
	reply, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
		User: "bob",
	}, func(r client.AuthenReply) (string, error) {
		assert.Equal(t, types.AuthenStatusGetPass, r.Status)
		return "hunter2", nil
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, reply.Status)
}

func TestClientAuthorize(t *testing.T) {
	_, ln, port := startServer(t, []byte("key"))
	defer ln.Close()
	conn := dial(t, port, []byte("key"))
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "show"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, res.Status)

	res, err = cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "reboot"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, res.Status)
}

func TestClientAccounting(t *testing.T) {
	_, ln, port := startServer(t, []byte("key"))
	defer ln.Close()
	conn := dial(t, port, []byte("key"))
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)
	res, err := cl.Account(context.Background(), client.AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "task_id", Value: "42"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, res.Status)
}

func TestClientSecretMismatch(t *testing.T) {
	_, ln, port := startServer(t, []byte("right"))
	defer ln.Close()
	conn := dial(t, port, []byte("wrong"))
	defer conn.Close()

	cl, err := client.New(conn)
	require.NoError(t, err)
	_, err = cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("secret123"),
	}, nil)
	assert.Error(t, err)
}

func TestClientTLSPAPAuth(t *testing.T) {
	ca := newClientTestCA(t, "ca")
	serverCert := ca.leaf(t, "localhost")
	clientCert := ca.leaf(t, "client")

	srvCfg := transport.ServerTLSConfig(serverCert, ca.pool())
	ln, err := transport.ListenTLS("tcp", "127.0.0.1:0", srvCfg)
	require.NoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	srv := server.New(server.Config{Handler: &memHandler{
		users: map[string]string{"alice": "secret123"}, cmds: map[string]bool{},
	}, Mode: transport.ModeTLS})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := transport.Accept(c, transport.ModeTLS, nil)
		_ = srv.ServeConn(context.Background(), conn)
	}()

	cfg, err := transport.TLSConfig{ServerName: "localhost", CACertPool: ca.pool(), ClientCert: clientCert}.ClientTLSConfig()
	require.NoError(t, err)
	td := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
	nc, err := td.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	conn := transport.NewConn(nc, transport.ModeTLS, nil)
	defer conn.Close()

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

func TestClientConnAccessor(t *testing.T) {
	_, ln, port := startServer(t, []byte("key"))
	defer ln.Close()
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, err := client.New(conn)
	require.NoError(t, err)
	assert.Same(t, conn, cl.Conn())
}
