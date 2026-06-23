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

// Package-level aliases for the named enumeration types, so protocol files
// read concisely. These are zero-cost type aliases.
type (
	AuthenStatusAlias  = types.AuthenStatus
	AuthorStatusAlias  = types.AuthorStatus
	AcctStatusAlias    = types.AcctStatus
	AuthenTypeAlias    = types.AuthenType
	AuthenActionAlias  = types.AuthenAction
	AuthenServiceAlias = types.AuthenService
	AuthenMethodAlias  = types.AuthenMethod
	PrivLevelAlias     = types.PrivLevel
	AcctFlagsAlias     = types.AcctFlags
	HeaderFlagsAlias   = types.HeaderFlags
)

// Named enum values for use across protocol files.
var (
	authenLogin    = types.AuthenLogin
	authenChpass   = types.AuthenChpass
	authenSendauth = types.AuthenSendauth
)

const (
	authenPass    = types.AuthenStatusPass
	authenFail    = types.AuthenStatusFail
	authenGetData = types.AuthenStatusGetData
	authenGetUser = types.AuthenStatusGetUser
	authenGetPass = types.AuthenStatusGetPass
	authenRestart = types.AuthenStatusRestart
	authenError   = types.AuthenStatusError
	authenFollow  = types.AuthenStatusFollow
)
