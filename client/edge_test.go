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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wxccs/tacacs/client"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// restartHandler replies with RESTART on the first START.
type restartHandler struct{}

func (restartHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{Status: types.AuthenStatusRestart}, nil
}
func (restartHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusError}, nil
}
func (restartHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusError}, nil
}

func TestClientRestartReturnsError(t *testing.T) {
	ln := startCustomServer(t, restartHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	_, err := cl.Authenticate(context.Background(), client.AuthenRequest{
		Action: types.AuthenLogin, Type: types.AuthenTypePAP, Service: types.AuthenServiceLogin,
		User: "a", Data: []byte("p"),
	}, nil)
	assert.Error(t, err)
}

func TestClientAuthorFollowNormalizedToFail(t *testing.T) {
	// A handler that returns FOLLOW; the client normalizes it to FAIL.
	ln := startCustomServer(t, followHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "a",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "x"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, res.Status, "FOLLOW normalizes to FAIL")
}

type followHandler struct{}

func (followHandler) Authenticate(context.Context, server.AuthenContext, *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{Status: types.AuthenStatusFollow}, nil
}
func (followHandler) Authorize(context.Context, server.AuthorContext) (server.AuthorDecision, error) {
	return server.AuthorDecision{Status: types.AuthorStatusFollow}, nil
}
func (followHandler) Account(context.Context, server.AcctContext) (server.AcctDecision, error) {
	return server.AcctDecision{Status: types.AcctStatusFollow}, nil
}

func TestClientAcctFollowNormalized(t *testing.T) {
	ln := startCustomServer(t, followHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Account(context.Background(), client.AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin, User: "a",
	})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusError, res.Status, "FOLLOW normalizes to ERROR for accounting")
}

func TestClientAuthorErrorStatus(t *testing.T) {
	ln := startCustomServer(t, restartHandler{}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, _ := client.New(conn)
	res, err := cl.Authorize(context.Background(), client.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "a",
		Args: []types.Argument{{Mandatory: true, Name: "cmd", Value: "x"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusError, res.Status)
}

func TestClientNewConnAccessorAndDial(t *testing.T) {
	// New error path is hard to trigger (only on RNG failure); here we confirm
	// New works on a connection that will be used for Account.
	ln := startCustomServer(t, &memHandler{users: map[string]string{}, cmds: map[string]bool{}}, []byte("key"))
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn := dial(t, port, []byte("key"))
	defer conn.Close()
	cl, err := client.New(conn)
	require.NoError(t, err)
	assert.NotNil(t, cl)
}
