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

import (
	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

// AcctRequest is the high-level accounting request assembled by a client or
// decoded by a server.
type AcctRequest struct {
	Flags   AcctFlagsAlias
	Method  AuthenMethodAlias
	PrivLvl PrivLevelAlias
	Type    AuthenTypeAlias
	Service AuthenServiceAlias
	User    string
	Port    string
	RemAddr string
	Args    []types.Argument
}

// Record returns the accounting record classification derived from the flags
// (RFC 8907 Table 2). It returns ErrInvalidArgument for an invalid flag
// combination, which the server MUST answer with TAC_PLUS_ACCT_STATUS_ERROR.
func (a AcctRequest) Record() (types.AcctRecord, error) {
	rec := a.Flags.Record()
	if rec == types.AcctRecordInvalid {
		return 0, errors.NewValidationError("acct_flags", "invalid combination", errors.ErrInvalidArgument)
	}
	return rec, nil
}

// TaskID returns the value of the task_id argument if present. Per RFC 8907
// §7.2 the task_id must match between the start and stop records of the same
// event, and a client MUST NOT reuse a task_id in a start record until it has
// sent a stop for it.
func (a AcctRequest) TaskID() (string, bool) {
	for _, arg := range a.Args {
		if arg.Name == "task_id" {
			return arg.Value, true
		}
	}
	return "", false
}

// AcctResult is the outcome of an accounting request.
type AcctResult struct {
	// Status is the accounting REPLY status.
	Status AcctStatusAlias
	// ServerMsg is an optional message.
	ServerMsg string
}

// NormalizeAcctStatus applies RFC 8907 §8.3 deprecation: FOLLOW (0x21) is
// deprecated.
func NormalizeAcctStatus(status AcctStatusAlias) AcctStatusAlias {
	if status == types.AcctStatusFollow {
		// FOLLOW is deprecated; map to ERROR as the conservative outcome.
		return types.AcctStatusError
	}
	return status
}
