// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
)

func TestNewSessionClient(t *testing.T) {
	s, err := NewSession(RoleClient)
	require.NoError(t, err)
	assert.NotZero(t, s.SessionID)
	assert.Equal(t, byte(1), s.PeekSeq(), "client starts at seq 1")

	// First NextSeq returns 1 (odd), then 3, 5 ...
	n1, err := s.NextSeq()
	require.NoError(t, err)
	assert.Equal(t, byte(1), n1)
	assert.Equal(t, byte(3), s.PeekSeq())

	n2, err := s.NextSeq()
	require.NoError(t, err)
	assert.Equal(t, byte(3), n2)
}

func TestNewSessionServer(t *testing.T) {
	s, err := NewSession(RoleServer)
	require.NoError(t, err)
	assert.Equal(t, byte(2), s.PeekSeq(), "server starts at seq 2 (even)")
	n, err := s.NextSeq()
	require.NoError(t, err)
	assert.Equal(t, byte(2), n)
	assert.True(t, n%2 == 0)
}

func TestNewSessionWithID(t *testing.T) {
	s := NewSessionWithID(RoleClient, 0xabcdef01)
	assert.Equal(t, uint32(0xabcdef01), s.SessionID)
	assert.Equal(t, byte(1), s.PeekSeq())
}

func TestSessionSeqNoWrap(t *testing.T) {
	s := NewSessionWithID(RoleClient, 1)
	// Client odd sequence: 1,3,...,255 then the session must terminate.
	// Drain until the 255 boundary is reached and exceeded.
	var last byte
	for {
		n, err := s.NextSeq()
		if err != nil {
			break
		}
		last = n
	}
	assert.Equal(t, byte(255), last, "last valid client seq is 255")
	// Further NextSeq calls must error (no wrap).
	_, err := s.NextSeq()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidSeqNo))
}

func TestSessionRandomID(t *testing.T) {
	ids := map[uint32]bool{}
	for i := 0; i < 100; i++ {
		s, err := NewSession(RoleClient)
		require.NoError(t, err)
		ids[s.SessionID] = true
	}
	// Over 100 draws, expect far more than 1 unique id (extremely high collision
	// probability would indicate a broken RNG).
	assert.Greater(t, len(ids), 50)
}

func TestSessionExpectSeq(t *testing.T) {
	s := NewSessionWithID(RoleClient, 1)
	assert.True(t, s.ExpectSeq(2)) // client expects server (even)
	assert.True(t, s.ExpectSeq(4))
	assert.False(t, s.ExpectSeq(1)) // odd is client's own, not expected

	s2 := NewSessionWithID(RoleServer, 1)
	assert.True(t, s2.ExpectSeq(1)) // server expects client (odd)
	assert.False(t, s2.ExpectSeq(2))
}
