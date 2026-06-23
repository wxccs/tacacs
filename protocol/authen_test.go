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

func TestAuthenStartValidateASCII(t *testing.T) {
	s := AuthenStart{Action: authenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin}
	assert.NoError(t, s.Validate())
	assert.False(t, s.NeedsMinorVersionOne())
	assert.False(t, s.IsSingleExchange())
}

func TestAuthenStartValidateEnable(t *testing.T) {
	s := AuthenStart{Action: authenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceEnable}
	assert.NoError(t, s.Validate())
}

func TestAuthenStartValidateCHAP(t *testing.T) {
	s := AuthenStart{Action: authenLogin, Type: types.AuthenTypeCHAP, Service: types.AuthenServicePPP, User: "alice"}
	assert.NoError(t, s.Validate())
	assert.True(t, s.NeedsMinorVersionOne())
	assert.True(t, s.IsSingleExchange())
}

func TestAuthenStartCHAPRequiresUser(t *testing.T) {
	s := AuthenStart{Action: authenLogin, Type: types.AuthenTypeCHAP, Service: types.AuthenServicePPP}
	err := s.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestAuthenStartCHAPRequiresLogin(t *testing.T) {
	s := AuthenStart{Action: authenChpass, Type: types.AuthenTypeCHAP, Service: types.AuthenServicePPP, User: "alice"}
	err := s.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestAuthenStartSendauthDisabled(t *testing.T) {
	s := AuthenStart{Action: authenSendauth, Type: types.AuthenTypePAP, Service: types.AuthenServicePPP, User: "alice"}
	err := s.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestAuthenStartMinorVersionForTypes(t *testing.T) {
	assert.False(t, AuthenStart{Type: types.AuthenTypeASCII}.NeedsMinorVersionOne())
	assert.True(t, AuthenStart{Type: types.AuthenTypePAP}.NeedsMinorVersionOne())
	assert.True(t, AuthenStart{Type: types.AuthenTypeMSCHAPv2}.NeedsMinorVersionOne())
}

func TestAuthenReplyTerminal(t *testing.T) {
	assert.True(t, AuthenReply{Status: authenPass}.IsTerminal())
	assert.True(t, AuthenReply{Status: authenFail}.IsTerminal())
	assert.True(t, AuthenReply{Status: authenError}.IsTerminal())
	assert.True(t, AuthenReply{Status: authenFollow}.IsTerminal(), "FOLLOW normalizes to terminal")
	assert.False(t, AuthenReply{Status: authenGetUser}.IsTerminal())
	assert.False(t, AuthenReply{Status: authenGetPass}.IsTerminal())
	assert.False(t, AuthenReply{Status: authenGetData}.IsTerminal())
}

func TestAuthenReplyNeedsContinue(t *testing.T) {
	assert.True(t, AuthenReply{Status: authenGetUser}.NeedsContinue())
	assert.True(t, AuthenReply{Status: authenGetPass}.NeedsContinue())
	assert.True(t, AuthenReply{Status: authenGetData}.NeedsContinue())
	assert.False(t, AuthenReply{Status: authenPass}.NeedsContinue())
	assert.False(t, AuthenReply{Status: authenFail}.NeedsContinue())
	assert.False(t, AuthenReply{Status: authenRestart}.NeedsContinue())
}
