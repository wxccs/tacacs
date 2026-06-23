// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

func TestHeaderMarshalGolden(t *testing.T) {
	h := Header{
		Version:   types.VersionOne,
		Type:      types.PacketAuthorization,
		SeqNo:     3,
		Flags:     types.FlagSingleConnect,
		SessionID: 0x12345678,
		Length:    0x100,
	}
	b, err := h.MarshalBinary()
	require.NoError(t, err)
	// c1 02 03 04 12345678 00000100
	want := "c10203041234567800000100"
	assert.Equal(t, want, hex.EncodeToString(b))
}

func TestHeaderUnmarshalGolden(t *testing.T) {
	b, _ := hex.DecodeString("c10203041234567800000100")
	var h Header
	require.NoError(t, h.UnmarshalBinary(b))
	assert.Equal(t, types.VersionOne, h.Version)
	assert.Equal(t, types.PacketAuthorization, h.Type)
	assert.Equal(t, byte(3), h.SeqNo)
	assert.Equal(t, types.FlagSingleConnect, h.Flags)
	assert.Equal(t, uint32(0x12345678), h.SessionID)
	assert.Equal(t, uint32(0x100), h.Length)
}

func TestHeaderRoundtrip(t *testing.T) {
	headers := []Header{
		{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1, Flags: 0, SessionID: 0xdeadbeef, Length: 0},
		{Version: types.VersionOne, Type: types.PacketAccounting, SeqNo: 7, Flags: types.FlagUnencrypted, SessionID: 1, Length: 65535},
	}
	for _, h := range headers {
		b, err := h.MarshalBinary()
		require.NoError(t, err)
		assert.Len(t, b, 12)
		var got Header
		require.NoError(t, got.UnmarshalBinary(b))
		assert.Equal(t, h, got)
	}
}

func TestHeaderUnmarshalErrors(t *testing.T) {
	var h Header
	err := h.UnmarshalBinary(make([]byte, 11))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidHeader))

	// Unsupported version byte.
	err = h.UnmarshalBinary([]byte{0xc2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrUnsupportedVersion))
}

func TestHeaderValidate(t *testing.T) {
	h := Header{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1}
	assert.NoError(t, h.Validate())

	h.Version = 0xc2
	assert.Error(t, h.Validate())

	h = Header{Version: types.VersionDefault, Type: types.PacketType(0x09)}
	err := h.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrUnsupportedType))

	h = Header{Version: types.VersionDefault, Type: types.PacketAuthentication, Length: types.MaxPacketSize + 1}
	err = h.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))

	h = Header{Version: types.VersionDefault, Type: types.PacketAuthentication, Flags: 0x02}
	err = h.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidHeader))
}

func TestErrorHeader(t *testing.T) {
	in := Header{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 5, Flags: 0, SessionID: 42, Length: 99}
	got := ErrorHeader(in)
	assert.Equal(t, byte(6), got.SeqNo)
	assert.Equal(t, uint32(0), got.Length)
	assert.Equal(t, in.SessionID, got.SessionID)
	assert.Equal(t, in.Type, got.Type)
	assert.Equal(t, in.Version, got.Version)
}

func TestSeqNoParity(t *testing.T) {
	assert.True(t, IsClient(1))
	assert.True(t, IsClient(3))
	assert.False(t, IsClient(2))
	assert.True(t, IsServer(2))
	assert.True(t, IsServer(4))
	assert.False(t, IsServer(1))
}
