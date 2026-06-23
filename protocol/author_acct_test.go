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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

func TestAuthorResultIsTerminal(t *testing.T) {
	assert.True(t, AuthorResult{Status: types.AuthorStatusPassAdd}.IsTerminal())
	assert.True(t, AuthorResult{Status: types.AuthorStatusPassRepl}.IsTerminal())
	assert.True(t, AuthorResult{Status: types.AuthorStatusFail}.IsTerminal())
	assert.True(t, AuthorResult{Status: types.AuthorStatusError}.IsTerminal())
}

func TestNormalizeAuthorStatusFollow(t *testing.T) {
	assert.Equal(t, types.AuthorStatusFail, NormalizeAuthorStatus(types.AuthorStatusFollow))
	assert.Equal(t, types.AuthorStatusPassAdd, NormalizeAuthorStatus(types.AuthorStatusPassAdd))
}

func TestAcctRequestRecord(t *testing.T) {
	cases := []struct {
		flags types.AcctFlags
		want  types.AcctRecord
		err   bool
	}{
		{types.AcctFlagStart, types.AcctRecordStart, false},
		{types.AcctFlagStop, types.AcctRecordStop, false},
		{types.AcctFlagWatchdog, types.AcctRecordWatchdogNoUpdate, false},
		{types.AcctFlagWatchdog | types.AcctFlagStart, types.AcctRecordWatchdogWithUpdate, false},
		{types.AcctFlagStart | types.AcctFlagStop, 0, true},
		{0, 0, true},
	}
	for _, c := range cases {
		rec, err := AcctRequest{Flags: AcctFlagsAlias(c.flags)}.Record()
		if c.err {
			require.Error(t, err, "flags=%#02x", byte(c.flags))
			assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
		} else {
			require.NoError(t, err, "flags=%#02x", byte(c.flags))
			assert.Equal(t, c.want, rec, "flags=%#02x", byte(c.flags))
		}
	}
}

func TestAcctRequestTaskID(t *testing.T) {
	a := AcctRequest{
		Args: []types.Argument{
			{Mandatory: true, Name: "task_id", Value: "1234"},
			{Mandatory: true, Name: "service", Value: "shell"},
		},
	}
	id, ok := a.TaskID()
	assert.True(t, ok)
	assert.Equal(t, "1234", id)

	b := AcctRequest{Args: []types.Argument{{Name: "service", Value: "shell"}}}
	_, ok = b.TaskID()
	assert.False(t, ok)
}

func TestNormalizeAcctStatusFollow(t *testing.T) {
	assert.Equal(t, types.AcctStatusError, NormalizeAcctStatus(types.AcctStatusFollow))
	assert.Equal(t, types.AcctStatusSuccess, NormalizeAcctStatus(types.AcctStatusSuccess))
}
