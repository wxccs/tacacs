// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

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

// countingWriter records the number of Write calls and concatenates their
// payloads, so tests can assert both call count and byte ordering.
type countingWriter struct {
	writes int
	buf    bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

func TestWritePacketSingleWriteWithBody(t *testing.T) {
	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		SessionID: 0xdeadbeef,
	}
	body := []byte("the quick brown fox")

	var c countingWriter
	require.NoError(t, WritePacket(&c, hdr, body))

	assert.Equal(t, 1, c.writes, "header+body must be sent in a single Write")

	wantHdr := hdr
	wantHdr.Length = uint32(len(body))
	hb, err := wantHdr.MarshalBinary()
	require.NoError(t, err)

	want := make([]byte, 0, len(hb)+len(body))
	want = append(want, hb...)
	want = append(want, body...)
	assert.Equal(t, want, c.buf.Bytes(), "output must be header followed by body")

	gotHdr, gotBody, err := ReadPacket(&c.buf)
	require.NoError(t, err)
	assert.Equal(t, uint32(len(body)), gotHdr.Length)
	assert.Equal(t, body, gotBody)
}

func TestWritePacketSingleWriteEmptyBody(t *testing.T) {
	hdr := packet.Header{Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1}
	hb, err := hdr.MarshalBinary()
	require.NoError(t, err)

	var c countingWriter
	require.NoError(t, WritePacket(&c, hdr, nil))

	assert.Equal(t, 1, c.writes, "header-only packet must still be a single Write")
	assert.Equal(t, hb, c.buf.Bytes())

	gotHdr, gotBody, err := ReadPacket(&c.buf)
	require.NoError(t, err)
	assert.Empty(t, gotBody)
	assert.Equal(t, uint32(0), gotHdr.Length)
}

func TestWritePacketSingleWriteOnTCPPipe(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 2,
		SessionID: 0xcafef00d,
	}
	body := []byte("huawei-vrp-friendly payload")

	done := make(chan error, 1)
	go func() {
		done <- WritePacket(a, hdr, body)
	}()

	gotHdr, gotBody, err := ReadPacket(b)
	require.NoError(t, err)
	require.NoError(t, <-done)
	assert.Equal(t, uint32(len(body)), gotHdr.Length)
	assert.Equal(t, body, gotBody)
	assert.Equal(t, hdr.SessionID, gotHdr.SessionID)
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
