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

package protocol

import "github.com/wxccs/tacacs/types"

// AuthorRequest is the high-level authorization request assembled by a client
// or decoded by a server. It mirrors packet.AuthorRequest but exposes parsed
// argument-value pairs.
type AuthorRequest struct {
	Method  AuthenMethodAlias
	PrivLvl PrivLevelAlias
	Type    AuthenTypeAlias
	Service AuthenServiceAlias
	User    string
	Port    string
	RemAddr string
	Args    []types.Argument
}

// AuthorResult is the outcome of an authorization decision.
type AuthorResult struct {
	// Status is the authorization REPLY status.
	Status AuthorStatusAlias
	// Args are the argument-value pairs returned with the reply. On FAIL or
	// ERROR the client MUST ignore them; on PASS_ADD they are applied on top
	// of the request args; on PASS_REPL they replace the request args.
	Args []types.Argument
	// ServerMsg is an optional message for the user.
	ServerMsg string
}

// IsTerminal reports whether the authorization status terminates the exchange.
// PASS_ADD, PASS_REPL, FAIL and ERROR are terminal; FOLLOW is deprecated.
func (r AuthorResult) IsTerminal() bool {
	switch r.Status {
	case types.AuthorStatusPassAdd, types.AuthorStatusPassRepl, types.AuthorStatusFail, types.AuthorStatusError:
		return true
	default:
		return false
	}
}

// NormalizeAuthorStatus applies RFC 8907 §6.2 deprecation: FOLLOW (0x21) is
// deprecated and its arg_cnt MUST be 0; clients SHOULD treat it as FAIL.
func NormalizeAuthorStatus(status AuthorStatusAlias) AuthorStatusAlias {
	if status == types.AuthorStatusFollow {
		return types.AuthorStatusFail
	}
	return status
}
