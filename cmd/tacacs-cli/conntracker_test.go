// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/transport"
)

// TestConnTracker verifies add/remove/len and that closeAll closes every
// tracked connection (so a shutdown drain can force-unblock pending reads).
func TestConnTracker(t *testing.T) {
	tr := newConnTracker()
	assert.Equal(t, 0, tr.len())

	a1, b1 := net.Pipe()
	defer b1.Close()
	a2, b2 := net.Pipe()
	defer b2.Close()

	c1 := transport.NewConn(a1, transport.ModeLegacy, nil)
	c2 := transport.NewConn(a2, transport.ModeLegacy, nil)

	tr.add(c1)
	tr.add(c2)
	assert.Equal(t, 2, tr.len())

	tr.remove(c1)
	assert.Equal(t, 1, tr.len())

	// closeAll must close the remaining connection: a subsequent read returns
	// an error rather than blocking.
	tr.closeAll()
	one := make([]byte, 1)
	_, err := a2.Read(one)
	require.Error(t, err)
}
