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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenStatusString(t *testing.T) {
	cases := []struct {
		s    AuthenStatus
		want string
	}{
		{AuthenStatusPass, "pass"},
		{AuthenStatusFail, "fail"},
		{AuthenStatusGetData, "getdata"},
		{AuthenStatusGetUser, "getuser"},
		{AuthenStatusGetPass, "getpass"},
		{AuthenStatusRestart, "restart"},
		{AuthenStatusError, "error"},
		{AuthenStatusFollow, "follow"},
		{AuthenStatus(0x99), "unknown(153)"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.s.String())
	}
}

func TestAuthorStatusString(t *testing.T) {
	cases := []struct {
		s    AuthorStatus
		want string
	}{
		{AuthorStatusPassAdd, "pass-add"},
		{AuthorStatusPassRepl, "pass-repl"},
		{AuthorStatusFail, "fail"},
		{AuthorStatusError, "error"},
		{AuthorStatusFollow, "follow"},
		{AuthorStatus(0x99), "unknown(153)"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.s.String())
	}
}

func TestAcctStatusString(t *testing.T) {
	cases := []struct {
		s    AcctStatus
		want string
	}{
		{AcctStatusSuccess, "success"},
		{AcctStatusError, "error"},
		{AcctStatusFollow, "follow"},
		{AcctStatus(0x99), "unknown(153)"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.s.String())
	}
}
