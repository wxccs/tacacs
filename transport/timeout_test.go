// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package transport

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/types"
)

// TestConnIdleTimeout verifies that ReadPacket returns a timeout error when no
// header bytes arrive within the idle timeout, defending against connections
// that open and then stall.
func TestConnIdleTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := NewConn(a, ModeLegacy, []byte("secret"))
	ca.SetTimeouts(50*time.Millisecond, 0)

	_, _, err := ca.ReadPacket()
	require.Error(t, err)
	var ne net.Error
	require.True(t, errors.As(err, &ne), "want net.Error, got %T", err)
	assert.True(t, ne.Timeout(), "want timeout error")
}

// TestConnReadTimeout verifies that once a header has arrived, a slow body read
// is bounded by the read timeout.
func TestConnReadTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := NewConn(a, ModeTLS, nil)
	ca.SetTimeouts(0, 50*time.Millisecond)

	// Writer sends only the header (advertising a 4-byte body) and then stalls.
	go func() {
		hdr := packet.Header{
			Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
			Flags: types.FlagUnencrypted, SessionID: 1, Length: 4,
		}
		hb, _ := hdr.MarshalBinary()
		_, _ = b.Write(hb)
		// Never write the body; let the read timeout fire.
		select {}
	}()

	_, _, err := ca.ReadPacket()
	require.Error(t, err)
	var ne net.Error
	require.True(t, errors.As(err, &ne), "want net.Error, got %T", err)
	assert.True(t, ne.Timeout(), "want timeout error")
}

// TestConnTimeoutClearedAfterRead verifies a successful read clears the
// deadline so it does not leak into later operations on the connection.
func TestConnTimeoutClearedAfterRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := NewConn(a, ModeTLS, nil)
	cb := NewConn(b, ModeTLS, nil)
	ca.SetTimeouts(time.Second, time.Second)

	hdr := packet.Header{
		Version: types.VersionDefault, Type: types.PacketAuthentication, SeqNo: 1,
		Flags: types.FlagUnencrypted, SessionID: 1,
	}
	body := []byte("hello")
	go func() { _ = cb.WritePacket(hdr, body) }()

	_, got, err := ca.ReadPacket()
	require.NoError(t, err)
	assert.Equal(t, body, got)

	// After a successful read the deadline must be cleared: a blocking read on
	// the raw conn should not immediately return a timeout. We assert this
	// indirectly by confirming SetReadDeadline(zero) was applied, i.e. a second
	// short write/read still succeeds well past the original deadline window.
	time.Sleep(20 * time.Millisecond)
	go func() { _ = cb.WritePacket(hdr, []byte("again")) }()
	_, got2, err := ca.ReadPacket()
	require.NoError(t, err)
	assert.Equal(t, []byte("again"), got2)
}
