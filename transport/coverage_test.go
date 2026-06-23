// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
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

package transport

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/types"
)

func TestConnAccessors(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := NewConn(a, ModeTLS, nil)
	assert.Equal(t, ModeTLS, c.Mode())
	require.NoError(t, c.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, c.SetDeadline(time.Time{}))
}

func TestTLSConfigString(t *testing.T) {
	s := TLSConfig{ServerName: "host", InsecureSkipVerify: true}.String()
	assert.Contains(t, s, "host")
	assert.Contains(t, s, "insecure:true")
}

func TestReadPacketInvalidVersion(t *testing.T) {
	// Valid header length (12 bytes) but an unsupported version byte.
	hdr := []byte{0xc2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, _, err := ReadPacket(bytes.NewReader(hdr))
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrUnsupportedVersion))
}

func TestReadPacketLengthExceedsMax(t *testing.T) {
	var buf bytes.Buffer
	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		Length: types.MaxPacketSize + 1,
	}
	hb, _ := hdr.MarshalBinary()
	buf.Write(hb)
	_, _, err := ReadPacket(&buf)
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidLength))
}

func TestWritePacketEmptyBody(t *testing.T) {
	var buf bytes.Buffer
	hdr := packet.Header{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1}
	require.NoError(t, WritePacket(&buf, hdr, nil))
	gotHdr, gotBody, err := ReadPacket(&buf)
	require.NoError(t, err)
	assert.Empty(t, gotBody)
	assert.Equal(t, uint32(0), gotHdr.Length)
}

func TestWritePacketWriteError(t *testing.T) {
	hdr := packet.Header{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1}
	err := WritePacket(errWriter{}, hdr, []byte("x"))
	require.Error(t, err)
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, assert.AnError }

func TestReadPacketEOF(t *testing.T) {
	_, _, err := ReadPacket(bytes.NewReader(nil))
	assert.Error(t, err)
}

func TestDialRefused(t *testing.T) {
	// Port 1 is a privileged port with no listener; the connect is refused.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Dial(ctx, "tcp", "127.0.0.1:1", []byte("k"))
	assert.Error(t, err)
}

func TestDialTLSRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cfg, err := TLSConfig{ServerName: "localhost", InsecureSkipVerify: true}.ClientTLSConfig()
	require.NoError(t, err)
	_, err = DialTLS(ctx, "tcp", "127.0.0.1:1", cfg)
	assert.Error(t, err)
}
