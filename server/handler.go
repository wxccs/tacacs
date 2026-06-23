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

package server

import (
	"context"

	"github.com/wxccs/tacacs/types"
)

// AuthenContext carries the inbound authentication request and the session
// identity to a Handler.
type AuthenContext struct {
	// SessionID identifies the TACACS+ session.
	SessionID uint32
	// SeqNo is the inbound packet sequence number.
	SeqNo byte
	// Start is the authentication START.
	Start AuthenStart
	// RemoteAddr is the address of the connected client (best effort).
	RemoteAddr string
}

// AuthenStart mirrors protocol.AuthenStart for the server-facing API.
type AuthenStart struct {
	Action  types.AuthenAction
	PrivLvl types.PrivLevel
	Type    types.AuthenType
	Service types.AuthenService
	User    string
	Port    string
	RemAddr string
	Data    []byte
}

// AuthenContinue carries a CONTINUE from the client during an interactive
// (ASCII) authentication.
type AuthenContinue struct {
	UserMsg string
	Data    []byte
	Flags   byte
}

// AuthenDecision is the Handler's response to an authentication step. For an
// interactive flow the server may return a non-terminal status (GETUSER/
// GETPASS/GETDATA) to solicit a CONTINUE, or a terminal PASS/FAIL/ERROR.
type AuthenDecision struct {
	Status    types.AuthenStatus
	Flags     byte
	ServerMsg string
	Data      []byte
}

// AuthorContext carries an authorization request.
type AuthorContext struct {
	SessionID  uint32
	SeqNo      byte
	Method     types.AuthenMethod
	PrivLvl    types.PrivLevel
	Type       types.AuthenType
	Service    types.AuthenService
	User       string
	Port       string
	RemAddr    string
	Args       []types.Argument
	RemoteAddr string
}

// AuthorDecision is the Handler's authorization response.
type AuthorDecision struct {
	Status    types.AuthorStatus
	Args      []types.Argument
	ServerMsg string
}

// AcctContext carries an accounting request.
type AcctContext struct {
	SessionID  uint32
	SeqNo      byte
	Flags      types.AcctFlags
	Method     types.AuthenMethod
	PrivLvl    types.PrivLevel
	Type       types.AuthenType
	Service    types.AuthenService
	User       string
	Port       string
	RemAddr    string
	Args       []types.Argument
	RemoteAddr string
}

// AcctDecision is the Handler's accounting response.
type AcctDecision struct {
	Status    types.AcctStatus
	ServerMsg string
}

// Handler is the application-supplied policy interface. Each method returns a
// decision for one request; the Server encodes and sends the response. A
// returned error causes the Server to send a typed ERROR reply (or the generic
// error packet when the body cannot be decoded) and terminate the session.
type Handler interface {
	// Authenticate handles a START and, for interactive flows, subsequent
	// CONTINUE messages identified by seqNo parity.
	Authenticate(ctx context.Context, ac AuthenContext, cont *AuthenContinue) (AuthenDecision, error)
	// Authorize handles an authorization REQUEST.
	Authorize(ctx context.Context, ac AuthorContext) (AuthorDecision, error)
	// Account handles an accounting REQUEST.
	Account(ctx context.Context, ac AcctContext) (AcctDecision, error)
}

// HandlerFunc is a convenience for building a Handler from functions.
type HandlerFunc struct {
	AuthenFunc func(ctx context.Context, ac AuthenContext, cont *AuthenContinue) (AuthenDecision, error)
	AuthorFunc func(ctx context.Context, ac AuthorContext) (AuthorDecision, error)
	AcctFunc   func(ctx context.Context, ac AcctContext) (AcctDecision, error)
}

// Authenticate calls AuthenFunc.
func (h HandlerFunc) Authenticate(ctx context.Context, ac AuthenContext, cont *AuthenContinue) (AuthenDecision, error) {
	return h.AuthenFunc(ctx, ac, cont)
}

// Authorize calls AuthorFunc.
func (h HandlerFunc) Authorize(ctx context.Context, ac AuthorContext) (AuthorDecision, error) {
	return h.AuthorFunc(ctx, ac)
}

// Account calls AcctFunc.
func (h HandlerFunc) Account(ctx context.Context, ac AcctContext) (AcctDecision, error) {
	return h.AcctFunc(ctx, ac)
}
