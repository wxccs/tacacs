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

package server_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/crypto"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/types"
)

// dialRaw opens a raw TCP connection to the loopback server.
func dialRaw(t *testing.T, port int) net.Conn {
	t.Helper()
	nc, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	require.NoError(t, err)
	return nc
}

func makeHeader(ptype types.PacketType, seq byte) packet.Header {
	return packet.Header{Version: types.VersionDefault, Type: ptype, SeqNo: seq, SessionID: 0x12345678}
}

func mustMarshalAuthenStart(t types.AuthenType, user string, data []byte) []byte {
	st := packet.AuthenStart{
		Action: types.AuthenLogin, PrivLvl: types.PrivLevelUser, Type: t,
		Service: types.AuthenServiceLogin, User: user, Data: string(data),
	}
	b, err := st.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func writeRawPacket(t *testing.T, w net.Conn, hdr packet.Header, body []byte) {
	t.Helper()
	hdr.Length = uint32(len(body))
	hb, err := hdr.MarshalBinary()
	require.NoError(t, err)
	_, err = w.Write(hb)
	require.NoError(t, err)
	if len(body) > 0 {
		_, err = w.Write(body)
		require.NoError(t, err)
	}
}

// cryptoObfInPlace obfuscates a body in place with the test shared key.
func cryptoObfInPlace(body []byte, hdr packet.Header) {
	crypto.ObfuscateInPlace(body, []byte("key"), hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
}

func writeAuthenStart(t *testing.T, w net.Conn, atype types.AuthenType, user string, data []byte) {
	t.Helper()
	body := mustMarshalAuthenStart(atype, user, data)
	hdr := makeHeader(types.PacketAuthentication, 1)
	// Obfuscate with the shared secret the server expects.
	crypto.ObfuscateInPlace(body, []byte("key"), hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
	writeRawPacket(t, w, hdr, body)
}

func writeAuthorRequest(t *testing.T, w net.Conn, user string, args []string) {
	t.Helper()
	req := packet.AuthorRequest{
		Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: user, Args: args,
	}
	body, err := req.MarshalBinary()
	require.NoError(t, err)
	hdr := makeHeader(types.PacketAuthorization, 1)
	crypto.ObfuscateInPlace(body, []byte("key"), hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
	writeRawPacket(t, w, hdr, body)
}

func writeAcctRequest(t *testing.T, w net.Conn, flags types.AcctFlags, user string, args []string) {
	t.Helper()
	req := packet.AcctRequest{
		Flags: flags, Method: types.AuthenMethodTacacsPlus, PrivLvl: types.PrivLevelUser, Type: types.AuthenTypeASCII,
		Service: types.AuthenServiceLogin, User: user, Args: args,
	}
	body, err := req.MarshalBinary()
	require.NoError(t, err)
	hdr := makeHeader(types.PacketAccounting, 1)
	crypto.ObfuscateInPlace(body, []byte("key"), hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
	writeRawPacket(t, w, hdr, body)
}

func readPacket(t *testing.T, r net.Conn) (packet.Header, []byte) {
	t.Helper()
	hbuf := make([]byte, 12)
	_, err := readFull(r, hbuf)
	require.NoError(t, err)
	var hdr packet.Header
	require.NoError(t, hdr.UnmarshalBinary(hbuf))
	body := make([]byte, hdr.Length)
	if hdr.Length > 0 {
		_, err = readFull(r, body)
		require.NoError(t, err)
		crypto.DeobfuscateInPlace(body, []byte("key"), hdr.SessionID, byte(hdr.Version), hdr.SeqNo)
	}
	return hdr, body
}

func readFull(r net.Conn, buf []byte) (int, error) {
	_ = binary.BigEndian // keep import if unused on some build tags
	got := 0
	for got < len(buf) {
		n, err := r.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
