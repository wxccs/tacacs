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

package types

// AuthorStatus is the authorization REPLY status (REPLY byte 0).
type AuthorStatus byte

// Authorization statuses (RFC 8907 §6.2). AuthorStatusFollow is deprecated and
// its arg_cnt MUST be 0.
const (
	AuthorStatusPassAdd  AuthorStatus = 0x01
	AuthorStatusPassRepl AuthorStatus = 0x02
	AuthorStatusFail     AuthorStatus = 0x10
	AuthorStatusError    AuthorStatus = 0x11
	AuthorStatusFollow   AuthorStatus = 0x21
)

// AuthenMethod is the authentication method reported in authorization and
// accounting requests (RFC 8907 §6.1). It MUST NOT be used in policy
// evaluation because it cannot be verified.
type AuthenMethod byte

// Authentication methods (RFC 8907 §6.1).
const (
	AuthenMethodNotSet     AuthenMethod = 0x00
	AuthenMethodNone       AuthenMethod = 0x01
	AuthenMethodKrb5       AuthenMethod = 0x02
	AuthenMethodLine       AuthenMethod = 0x03
	AuthenMethodEnable     AuthenMethod = 0x04
	AuthenMethodLocal      AuthenMethod = 0x05
	AuthenMethodTacacsPlus AuthenMethod = 0x06
	AuthenMethodGuest      AuthenMethod = 0x08
	AuthenMethodRadius     AuthenMethod = 0x10
	AuthenMethodKrb4       AuthenMethod = 0x11
	AuthenMethodRcmd       AuthenMethod = 0x20
)
