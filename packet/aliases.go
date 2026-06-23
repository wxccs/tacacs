// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import "github.com/wxccs/tacacs/types"

// Package-level type aliases so body struct fields read concisely. These are
// zero-cost aliases of the named types in the types package.
type (
	typesAuthenAction  = types.AuthenAction
	typesPrivLevel     = types.PrivLevel
	typesAuthenType    = types.AuthenType
	typesAuthenService = types.AuthenService
	typesAuthenStatus  = types.AuthenStatus
	typesAuthenMethod  = types.AuthenMethod
	typesAuthorStatus  = types.AuthorStatus
	typesAcctFlags     = types.AcctFlags
	typesAcctStatus    = types.AcctStatus
)
