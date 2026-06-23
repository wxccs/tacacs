// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
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
