// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

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
