// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
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
	"errors"
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

// getPassNoEchoHandler: ASCII flow that first asks for the password (GETPASS
// with NOECHO), then returns PASS on the CONTINUE.
type getPassHandler struct{}

func (getPassHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	if cont == nil {
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, Flags: types.ReplyFlagNoEcho, ServerMsg: "Password:"}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
}
func (getPassHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
}
func (getPassHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

func startCustomServer(t *testing.T, h server.Handler, secret []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := server.New(server.Config{Handler: h, Secret: secret, Mode: transport.ModeLegacy})
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

func TestClientASCIIWithoutContFnErrors(t *testing.T) {
	ln := startCustomServer(t, getPassHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	// ASCII needs a CONTINUE but contFn is nil -> error.
	_, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "bob",
	}, nil)
	assert.Error(t, err)
}

func TestClientASCIIContFnError(t *testing.T) {
	ln := startCustomServer(t, getPassHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	_, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "bob",
	}, func(r client.AuthenReply) (string, error) {
		assert.Equal(t, types.AuthenStatusGetPass, r.Status)
		return "", errors.New("user aborted")
	})
	assert.Error(t, err)
}

func TestClientAuthorizeWithArgs(t *testing.T) {
	ln := startCustomServer(t, &memHandler{users: map[string]string{"a": "p"}, cmds: map[string]bool{"show": true}}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "a",
		Args: []types.Argument{{Mandatory: true, Name: "service", Value: "shell"}, {Mandatory: true, Name: "cmd", Value: "show"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, res.Status)
}

func TestClientAccountingWatchdog(t *testing.T) {
	ln := startCustomServer(t, &memHandler{users: map[string]string{}, cmds: map[string]bool{}}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Account(context.Background(), client.AcctRequest{
		Flags: types.AcctFlagWatchdog, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "a",
		Args: []types.Argument{{Mandatory: true, Name: "task_id", Value: "9"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, res.Status)
}

func TestClientContextCancel(t *testing.T) {
	ln := startCustomServer(t, getPassHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call
	_, err := cl.Authenticate(ctx, client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin, User: "a", Data: []byte("p"),
	}, nil)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestClientAuthorSecretMismatch(t *testing.T) {
	ln := startCustomServer(t, &memHandler{users: map[string]string{"a": "p"}, cmds: map[string]bool{}}, []byte("right"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("wrong"))
	defer conn.Close()
	cl, _ := client.New(conn)
	_, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "a",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "x"}},
	})
	assert.Error(t, err)
}

func TestClientAcctSecretMismatch(t *testing.T) {
	ln := startCustomServer(t, &memHandler{users: map[string]string{}, cmds: map[string]bool{}}, []byte("right"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("wrong"))
	defer conn.Close()
	cl, _ := client.New(conn)
	_, err := cl.Account(context.Background(), client.AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "a",
	})
	assert.Error(t, err)
}

func TestClientReadTimeout(t *testing.T) {
	// A server that accepts but never responds -> client read deadline fires.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, _ := ln.Accept()
		// Hold the connection open without writing.
		_ = c
		select {}
	}()
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(100*time.Millisecond)))
	cl, _ := client.New(conn)
	_, err = cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin, User: "a", Data: []byte("p"),
	}, nil)
	assert.Error(t, err)
}
