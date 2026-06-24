// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package protocol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
)

func makeCHAP(pppID byte, challenge, response []byte) []byte {
	d := make([]byte, 0, 1+len(challenge)+len(response))
	d = append(d, pppID)
	d = append(d, challenge...)
	d = append(d, response...)
	return d
}

func TestParseCHAPData(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xaa}, 8) // min length
	response := bytes.Repeat([]byte{0xbb}, 16)
	data := makeCHAP(0x07, challenge, response)

	got, err := ParseCHAPData(data)
	require.NoError(t, err)
	assert.Equal(t, byte(0x07), got.PPPID)
	assert.Equal(t, challenge, got.Challenge)
	assert.Equal(t, response, got.Response)
}

func TestParseCHAPDataLongerChallenge(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xcc}, 16)
	response := bytes.Repeat([]byte{0xdd}, 16)
	data := makeCHAP(0x01, challenge, response)
	got, err := ParseCHAPData(data)
	require.NoError(t, err)
	assert.Equal(t, challenge, got.Challenge)
	assert.Equal(t, response, got.Response)
}

func TestParseCHAPDataShortChallenge(t *testing.T) {
	challenge := bytes.Repeat([]byte{0xaa}, 7) // below min 8
	response := bytes.Repeat([]byte{0xbb}, 16)
	data := makeCHAP(0x07, challenge, response)
	_, err := ParseCHAPData(data)
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestParseCHAPDataTooShort(t *testing.T) {
	_, err := ParseCHAPData([]byte{0x01})
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestParseMSCHAPData(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x11}, 8)
	response := bytes.Repeat([]byte{0x22}, 49)
	data := make([]byte, 0, 1+8+49)
	data = append(data, 0x09)
	data = append(data, challenge...)
	data = append(data, response...)
	got, err := ParseMSCHAPData(data)
	require.NoError(t, err)
	assert.Equal(t, byte(9), got.PPPID)
	assert.Equal(t, challenge, got.Challenge)
	assert.Equal(t, response, got.Response)
}

func TestParseMSCHAPDataWrongChallengeLen(t *testing.T) {
	// 7-byte challenge -> MUST reject
	challenge := bytes.Repeat([]byte{0x11}, 7)
	response := bytes.Repeat([]byte{0x22}, 49)
	data := makeCHAP(0x09, challenge, response)
	_, err := ParseMSCHAPData(data)
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	// 9-byte challenge -> also reject
	challenge9 := bytes.Repeat([]byte{0x11}, 9)
	_, err = ParseMSCHAPData(makeCHAP(0x09, challenge9, response))
	require.Error(t, err)
}

func TestParseMSCHAPv2Data(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x33}, 16)
	response := bytes.Repeat([]byte{0x44}, 49)
	data := makeCHAP(0x05, challenge, response)
	got, err := ParseMSCHAPv2Data(data)
	require.NoError(t, err)
	assert.Equal(t, byte(5), got.PPPID)
	assert.Equal(t, challenge, got.Challenge)
	assert.Equal(t, response, got.Response)
}

func TestParseMSCHAPv2DataWrongChallengeLen(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x33}, 15) // must be 16
	response := bytes.Repeat([]byte{0x44}, 49)
	_, err := ParseMSCHAPv2Data(makeCHAP(0x05, challenge, response))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestNormalizeAuthenStatusFollow(t *testing.T) {
	assert.Equal(t, authenFail, NormalizeAuthenStatus(authenFollow))
	assert.Equal(t, authenPass, NormalizeAuthenStatus(authenPass))
	assert.Equal(t, authenGetPass, NormalizeAuthenStatus(authenGetPass))
}

func TestIsTerminal(t *testing.T) {
	assert.True(t, IsTerminal(authenPass))
	assert.True(t, IsTerminal(authenFail))
	assert.True(t, IsTerminal(authenError))
	assert.False(t, IsTerminal(authenGetUser))
	assert.False(t, IsTerminal(authenGetPass))
	assert.False(t, IsTerminal(authenGetData))
	assert.False(t, IsTerminal(authenRestart))
}
