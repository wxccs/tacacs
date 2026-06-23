// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

func TestAuthenStartRoundtrip(t *testing.T) {
	a := AuthenStart{
		Action:  types.AuthenLogin,
		PrivLvl: types.PrivLevelUser,
		Type:    types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin,
		User:    "alice",
		Port:    "tty0",
		RemAddr: "10.0.0.1",
		Data:    "",
	}
	b, err := a.MarshalBinary()
	require.NoError(t, err)
	// Fixed 8 bytes + len(User)+len(Port)+len(RemAddr)+len(Data)
	assert.Equal(t, 8+5+4+8+0, len(b))

	var got AuthenStart
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, a, got)
}

func TestAuthenStartGolden(t *testing.T) {
	// action=01 priv=01 type=01 svc=01 | ul=0 pl=0 rl=0 dl=0
	b, err := AuthenStart{
		Action: types.AuthenLogin, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
	}.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "0101010100000000", hex.EncodeToString(b))
}

func TestAuthenStartLengthMismatch(t *testing.T) {
	b, _ := AuthenStart{
		Action: types.AuthenLogin, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
		User: "ab",
	}.MarshalBinary()
	// Truncate a byte to force mismatch.
	var got AuthenStart
	err := got.UnmarshalBinary(b[:len(b)-1])
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestAuthenStartOverlong(t *testing.T) {
	_, err := AuthenStart{User: strings.Repeat("x", 256)}.MarshalBinary()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestAuthenContinueRoundtrip(t *testing.T) {
	c := AuthenContinue{UserMsg: "password", Data: "", Flags: 0}
	b, err := c.MarshalBinary()
	require.NoError(t, err)
	// 5 fixed + 8
	assert.Equal(t, 13, len(b))
	// user_msg_len is 8 -> 00 08
	assert.Equal(t, "0008", hex.EncodeToString(b[0:2]))
	assert.Equal(t, "0000", hex.EncodeToString(b[2:4]))
	var got AuthenContinue
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, c, got)
}

func TestAuthenContinueAbortFlag(t *testing.T) {
	c := AuthenContinue{Flags: types.ContinueFlagAbort}
	b, err := c.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, byte(1), b[4])
}

func TestAuthenContinueShort(t *testing.T) {
	var got AuthenContinue
	err := got.UnmarshalBinary([]byte{0, 0, 0, 0})
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}

func TestAuthenReplyRoundtrip(t *testing.T) {
	r := AuthenReply{
		Status:    types.AuthenStatusPass,
		Flags:     0,
		ServerMsg: "Welcome",
		Data:      "",
	}
	b, err := r.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, 6+7, len(b))
	var got AuthenReply
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, r, got)
}

func TestAuthenReplyOverlong(t *testing.T) {
	_, err := AuthenReply{ServerMsg: strings.Repeat("y", 1<<16)}.MarshalBinary()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestAuthorRequestRoundtrip(t *testing.T) {
	r := AuthorRequest{
		Method:  types.AuthenMethodTacacsPlus,
		PrivLvl: types.PrivLevelUser,
		Type:    types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin,
		User:    "bob",
		Port:    "tty1",
		RemAddr: "10.0.0.2",
		Args:    []string{"service=shell", "cmd=show", "cmd-arg=version"},
	}
	b, err := r.MarshalBinary()
	require.NoError(t, err)
	var got AuthorRequest
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, r, got)
}

func TestAuthorRequestGolden(t *testing.T) {
	// method=06 priv=01 type=01 svc=01 | ul=0 pl=0 rl=0 | arg_cnt=0
	b, err := AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
	}.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "0601010100000000", hex.EncodeToString(b))
}

func TestAuthorRequestTooManyArgs(t *testing.T) {
	args := make([]string, 256)
	_, err := AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, Args: args,
	}.MarshalBinary()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrTooManyArguments))
}

func TestAuthorRequestArgOverlong(t *testing.T) {
	_, err := AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
		Args: []string{strings.Repeat("z", 256)},
	}.MarshalBinary()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestAuthorRequestLengthMismatch(t *testing.T) {
	b, _ := AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
		User: "ab",
	}.MarshalBinary()
	var got AuthorRequest
	err := got.UnmarshalBinary(b[:len(b)-1])
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestAuthorReplyRoundtrip(t *testing.T) {
	r := AuthorReply{
		Status:    types.AuthorStatusPassAdd,
		ServerMsg: "",
		Data:      "",
		Args:      []string{"priv-lvl=15"},
	}
	b, err := r.MarshalBinary()
	require.NoError(t, err)
	var got AuthorReply
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, r, got)
}

func TestAuthorReplyGolden(t *testing.T) {
	// status=01 arg_cnt=00 server_msg_len=0000 data_len=0000
	b, err := AuthorReply{Status: types.AuthorStatusPassAdd}.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "010000000000", hex.EncodeToString(b))
}

func TestAuthorReplyErrorIgnoresArgs(t *testing.T) {
	// Decoding still parses args; the protocol layer decides to ignore them on
	// ERROR. Here we just verify roundtrip preserves the fields.
	r := AuthorReply{Status: types.AuthorStatusError, Args: []string{"x=1"}}
	b, err := r.MarshalBinary()
	require.NoError(t, err)
	var got AuthorReply
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, r, got)
}

func TestAuthorReplyArgLengthsShort(t *testing.T) {
	// arg_cnt says 2 but no length bytes present.
	b, _ := hex.DecodeString("010000000000") // status, arg_cnt=1 (second byte)
	b[1] = 2
	var got AuthorReply
	err := got.UnmarshalBinary(b)
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}

func TestAcctRequestRoundtrip(t *testing.T) {
	r := AcctRequest{
		Flags:   types.AcctFlagStart,
		Method:  types.AuthenMethodTacacsPlus,
		PrivLvl: types.PrivLevelUser,
		Type:    types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin,
		User:    "carol",
		Port:    "tty2",
		RemAddr: "10.0.0.3",
		Args:    []string{"task_id=42", "service=shell"},
	}
	b, err := r.MarshalBinary()
	require.NoError(t, err)
	var got AcctRequest
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, r, got)
}

func TestAcctRequestGolden(t *testing.T) {
	// flags=02 method=06 priv=01 type=01 svc=01 | user_len=0 port_len=0 rem_addr_len=0 arg_cnt=0
	b, err := AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser,
		Type: types.AuthenTypeASCII, Service: types.AuthenServiceLogin,
	}.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "020601010100000000", hex.EncodeToString(b))
}

func TestAcctRequestLengthMismatch(t *testing.T) {
	b, _ := AcctRequest{
		Flags: types.AcctFlagStart, Method: types.AuthenMethodTacacsPlus, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: "ab",
	}.MarshalBinary()
	var got AcctRequest
	err := got.UnmarshalBinary(b[:len(b)-1])
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestAcctRequestShortBuffer(t *testing.T) {
	var got AcctRequest
	err := got.UnmarshalBinary(make([]byte, 8))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}

func TestAcctReplyRoundtrip(t *testing.T) {
	r := AcctReply{Status: types.AcctStatusSuccess, ServerMsg: "ok", Data: ""}
	b, err := r.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, 5+2, len(b))
	var got AcctReply
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, r, got)
}

func TestAcctReplyGolden(t *testing.T) {
	// server_msg_len=0000 data_len=0000 status=01
	b, err := AcctReply{Status: types.AcctStatusSuccess}.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "0000000001", hex.EncodeToString(b))
}

func TestAcctReplyLengthMismatch(t *testing.T) {
	b, _ := AcctReply{Status: types.AcctStatusSuccess, ServerMsg: "ab"}.MarshalBinary()
	var got AcctReply
	err := got.UnmarshalBinary(b[:len(b)-1])
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}
