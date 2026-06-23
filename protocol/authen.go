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

// AuthenStart describes an authentication START in high-level terms.
type AuthenStart struct {
	Action  AuthenActionAlias
	PrivLvl PrivLevelAlias
	Type    AuthenTypeAlias
	Service AuthenServiceAlias
	User    string
	Port    string
	RemAddr string
	Data    []byte
}

// Validate checks the START fields for protocol validity per RFC 8907 §5.4.1.
// It returns a wrapped error on any violation.
func (s AuthenStart) Validate() error {
	// ENABLE: authen_service MUST be ENABLE and MUST NOT be set otherwise.
	if s.Action == authenLogin && s.Type == types.AuthenTypeASCII && s.Service == types.AuthenServiceEnable {
		// Valid enable request; ASCII enable is the only enable form.
		return nil
	}
	// SENDAUTH/CHPASS/SENDAUTH are deprecated; allow but flag at higher layer.
	if s.Action == authenChpass && s.Type != types.AuthenTypeASCII {
		return errors.NewValidationError("authen_start", "CHPASS only valid for ASCII", errors.ErrInvalidArgument)
	}
	// SENDAUTH is deprecated (RFC 8907 §1); reject at this layer for safety.
	if s.Action == authenSendauth {
		return errors.NewValidationError("authen_start", "SENDAUTH is deprecated and disabled", errors.ErrInvalidArgument)
	}
	// PAP/CHAP/MSCHAP/MSCHAPv2 require minor_version 1 and a single START+REPLY.
	switch s.Type {
	case types.AuthenTypePAP, types.AuthenTypeCHAP, types.AuthenTypeMSCHAP, types.AuthenTypeMSCHAPv2:
		if s.Action != authenLogin {
			return errors.NewValidationError("authen_start", "challenge types require LOGIN action", errors.ErrInvalidArgument)
		}
		if s.User == "" {
			return errors.NewValidationError("authen_start", "challenge types require a username", errors.ErrInvalidArgument)
		}
	}
	// ASCII: data field in START and CONTINUE MUST be ignored.
	return nil
}

// NeedsMinorVersionOne reports whether the START requires minor_version 1,
// i.e. PAP/CHAP/MSCHAP/MSCHAPv2 LOGIN (RFC 8907 §5.4.1, Table 1).
func (s AuthenStart) NeedsMinorVersionOne() bool {
	return types.MinorVersionFor(s.Type) == types.MinorVersionOne
}

// IsSingleExchange reports whether the authentication is a single START+REPLY
// exchange (PAP/CHAP/MSCHAP/MSCHAPv2) with no CONTINUE, as opposed to ASCII
// which may involve GETUSER/GETPASS/GETDATA round trips.
func (s AuthenStart) IsSingleExchange() bool {
	switch s.Type {
	case types.AuthenTypePAP, types.AuthenTypeCHAP, types.AuthenTypeMSCHAP, types.AuthenTypeMSCHAPv2:
		return true
	default:
		return false
	}
}

// AuthenReply is the high-level authentication reply.
type AuthenReply struct {
	Status    AuthenStatusAlias
	Flags     byte
	ServerMsg string
	Data      []byte
}

// IsTerminal reports whether the reply status ends the session (PASS/FAIL/ERROR).
// FOLLOW is deprecated and treated as terminal (clients normalize it to FAIL).
func (r AuthenReply) IsTerminal() bool {
	return IsTerminal(NormalizeAuthenStatus(r.Status))
}

// NeedsContinue reports whether the reply requests more data (GETUSER/GETPASS/
// GETDATA), expecting a CONTINUE from the client. RESTART also terminates the
// current exchange (the client restarts with a new START).
func (r AuthenReply) NeedsContinue() bool {
	switch NormalizeAuthenStatus(r.Status) {
	case authenGetUser, authenGetPass, authenGetData:
		return true
	default:
		return false
	}
}
