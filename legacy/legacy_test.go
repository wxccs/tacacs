// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package legacy

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
)

func TestConstantsGolden(t *testing.T) {
	assert.Equal(t, byte(0), UDPVersionSimple)
	assert.Equal(t, byte(128), UDPVersionExtended)
	assert.Equal(t, 6, UDPHeaderLenSimple)
	assert.Equal(t, 26, UDPHeaderLenExtended)
	assert.Equal(t, byte(1), TCPVersion)
	assert.Equal(t, "201", TCPReplyAccepted)
	assert.Equal(t, "502", TCPReplyAccessDenied)
	assert.True(t, IsSimple(0))
	assert.True(t, IsExtended(128))
	assert.False(t, IsSimple(128))
	assert.False(t, IsExtended(0))
}

func TestUDPSimpleRoundtrip(t *testing.T) {
	p := UDPSimple{
		Version: UDPVersionSimple, Type: UDPTypeLogin, Nonce: 0x1234,
		UserLenOrResponse: 3, PwLenOrReason: 2, Data: []byte("abxy"),
	}
	b, err := p.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, 6+4, len(b))
	// 00 01 1234 03 02 + "abxy"
	assert.Equal(t, "000112340302"+hex.EncodeToString([]byte("abxy")), hex.EncodeToString(b))

	var got UDPSimple
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, p, got)
	assert.Equal(t, "abx", got.User())   // first 3 bytes
	assert.Equal(t, "y", got.Password()) // wait, data is "abxy", user_len=3 -> "abx", rest "y"
}

func TestUDPSimpleUserPassword(t *testing.T) {
	p := UDPSimple{Version: UDPVersionSimple, UserLenOrResponse: 5, Data: []byte("alicepw1")}
	assert.Equal(t, "alice", p.User())
	assert.Equal(t, "pw1", p.Password())
}

func TestUDPSimpleWrongVersion(t *testing.T) {
	_, err := UDPSimple{Version: 128}.MarshalBinary()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrUnsupportedVersion))
}

func TestUDPSimpleShort(t *testing.T) {
	var p UDPSimple
	err := p.UnmarshalBinary([]byte{0, 1, 2, 3})
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}

func TestUDPExtendedRoundtrip(t *testing.T) {
	dh := [4]byte{192, 0, 2, 1}
	p := UDPExtended{
		Version: UDPVersionExtended, Type: UDPTypeConnect, Nonce: 0xabcd,
		UserLen: 2, PwLen: 2, Response: 0, Reason: 0,
		Result1: 0x11111111, DestHost: dh, DestPort: 23, Line: 5,
		Result2: 0x22222222, Result3: 0x3333, Data: []byte("abpw"),
	}
	b, err := p.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, 26+4, len(b))
	var got UDPExtended
	require.NoError(t, got.UnmarshalBinary(b))
	assert.Equal(t, p, got)
	assert.Equal(t, "ab", got.User())
	assert.Equal(t, "pw", got.Password())
	assert.Equal(t, uint16(23), got.DestPort)
	assert.Equal(t, uint16(5), got.Line)
	assert.Equal(t, dh, got.DestHost)
}

func TestUDPExtendedWrongVersion(t *testing.T) {
	_, err := UDPExtended{Version: 0}.MarshalBinary()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrUnsupportedVersion))
}

func TestUDPExtendedShort(t *testing.T) {
	var p UDPExtended
	err := p.UnmarshalBinary(make([]byte, 25))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}

func TestTCPRequestRoundtrip(t *testing.T) {
	r := TCPRequest{Type: "LOGIN", Username: "alice", Password: "secret", Line: "0"}
	b, err := r.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "1 LOGIN\r\nalice\r\nsecret\r\n0\r\n", string(b))

	var got TCPRequest
	require.NoError(t, got.UnmarshalText(b))
	assert.Equal(t, r, got)
}

func TestTCPRequestAuthWithStyle(t *testing.T) {
	r := TCPRequest{Type: "AUTH", Style: "mystyle", Username: "u", Password: "p", Line: "0"}
	b, err := r.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "1 AUTH mystyle\r\nu\r\np\r\n0\r\n", string(b))
	var got TCPRequest
	require.NoError(t, got.UnmarshalText(b))
	assert.Equal(t, "mystyle", got.Style)
}

func TestTCPRequestConnectWithDest(t *testing.T) {
	r := TCPRequest{Type: "CONNECT", DestHost: "10.0.0.1", DestPort: "23", Username: "u", Password: "p", Line: "0"}
	b, err := r.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "1 CONNECT 10.0.0.1 23\r\nu\r\np\r\n0\r\n", string(b))
	var got TCPRequest
	require.NoError(t, got.UnmarshalText(b))
	assert.Equal(t, "10.0.0.1", got.DestHost)
	assert.Equal(t, "23", got.DestPort)
}

func TestTCPRequestCRLFRejected(t *testing.T) {
	_, err := TCPRequest{Type: "LOGIN", Username: "bad\rname", Password: "p", Line: "0"}.MarshalText()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestTCPRequestNULRejected(t *testing.T) {
	_, err := TCPRequest{Type: "LOGIN", Username: "bad\x00name", Password: "p", Line: "0"}.MarshalText()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestTCPRequestTooFewLines(t *testing.T) {
	var got TCPRequest
	err := got.UnmarshalText([]byte("1 LOGIN\r\nonly\r\ntwo\r\n"))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}

func TestTCPReplyMarshal(t *testing.T) {
	r := TCPReply{Code: "201", Text: "accepted: 1 2 3"}
	b, err := r.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "201 accepted: 1 2 3\r\n", string(b))

	var got TCPReply
	require.NoError(t, got.UnmarshalText(b))
	assert.Equal(t, r, got)
}

func TestTCPReplyNoText(t *testing.T) {
	r := TCPReply{Code: "502"}
	b, err := r.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "502\r\n", string(b))
}

func TestTCPReplyBadCode(t *testing.T) {
	_, err := TCPReply{Code: "20"}.MarshalText()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestTCPReplyClassification(t *testing.T) {
	assert.True(t, TCPReply{Code: "201"}.Accepted())
	assert.False(t, TCPReply{Code: "201"}.Transient())
	assert.True(t, TCPReply{Code: "401"}.Transient())
	assert.True(t, TCPReply{Code: "502"}.Permanent())
	assert.False(t, TCPReply{Code: "502"}.Accepted())
}

func TestTCPReplyShort(t *testing.T) {
	var r TCPReply
	err := r.UnmarshalText([]byte("20"))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidPacket))
}
