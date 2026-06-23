// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
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
