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
