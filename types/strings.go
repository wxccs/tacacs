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

package types

import "fmt"

// String returns a human-readable name for the authentication status.
func (s AuthenStatus) String() string {
	switch s {
	case AuthenStatusPass:
		return "pass"
	case AuthenStatusFail:
		return "fail"
	case AuthenStatusGetData:
		return "getdata"
	case AuthenStatusGetUser:
		return "getuser"
	case AuthenStatusGetPass:
		return "getpass"
	case AuthenStatusRestart:
		return "restart"
	case AuthenStatusError:
		return "error"
	case AuthenStatusFollow:
		return "follow"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// String returns a human-readable name for the authorization status.
func (s AuthorStatus) String() string {
	switch s {
	case AuthorStatusPassAdd:
		return "pass-add"
	case AuthorStatusPassRepl:
		return "pass-repl"
	case AuthorStatusFail:
		return "fail"
	case AuthorStatusError:
		return "error"
	case AuthorStatusFollow:
		return "follow"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// String returns a human-readable name for the accounting status.
func (s AcctStatus) String() string {
	switch s {
	case AcctStatusSuccess:
		return "success"
	case AcctStatusError:
		return "error"
	case AcctStatusFollow:
		return "follow"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}
