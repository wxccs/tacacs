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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// argsHandler returns authorization PASS_ADD with a result argument.
type argsHandler struct{}

func (argsHandler) Authenticate(context.Context, server.AuthenContext, *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
}
func (argsHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{
		Status: types.AuthorStatusPassAdd,
		Args:   []types.Argument{{Mandatory: true, Name: "priv-lvl", Value: "15"}},
	}, nil
}
func (argsHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

func TestClientAuthorizeWithResultArgs(t *testing.T) {
	ln := startCustomServer(t, argsHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "show"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, res.Status)
	require.Len(t, res.Args, 1)
	assert.Equal(t, "priv-lvl", res.Args[0].Name)
	assert.Equal(t, "15", res.Args[0].Value)
}

func TestClientPAPFailStatus(t *testing.T) {
	ln := startCustomServer(t, &memHandler{users: map[string]string{"alice": "right"}, cmds: map[string]bool{}}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	reply, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "alice", Data: []byte("wrong"),
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusFail, reply.Status)
	assert.Equal(t, "bad", reply.ServerMsg)
}

// errAcctHandler returns an accounting ERROR decision.
type errAcctHandler struct{}

func (errAcctHandler) Authenticate(context.Context, server.AuthenContext, *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
}
func (errAcctHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
}
func (errAcctHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusError, ServerMsg: "recording failed"}, nil
}

func TestClientAccountErrorStatus(t *testing.T) {
	ln := startCustomServer(t, errAcctHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Account(context.Background(), client.AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusError, res.Status)
	assert.Equal(t, "recording failed", res.ServerMsg)
}

func TestClientAuthorFailStatus(t *testing.T) {
	ln := startCustomServer(t, &memHandler{users: map[string]string{}, cmds: map[string]bool{}}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "reboot"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, res.Status)
}

// errAuthorHandler returns an authorization ERROR decision.
type errAuthorHandler struct{}

func (errAuthorHandler) Authenticate(context.Context, server.AuthenContext, *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
}
func (errAuthorHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusError, ServerMsg: "authz error"}, nil
}
func (errAuthorHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
}

func TestClientAuthorErrorStatusFromHandler(t *testing.T) {
	ln := startCustomServer(t, errAuthorHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "alice",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "x"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusError, res.Status)
	assert.Equal(t, "authz error", res.ServerMsg)
}
