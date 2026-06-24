// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/transport"
)

// TestServeConnIdleTimeout verifies that a Server configured with IdleTimeout
// terminates a connection that opens and then sends nothing, returning a
// timeout error rather than blocking a goroutine forever.
func TestServeConnIdleTimeout(t *testing.T) {
	h := &usersHandler{users: map[string]string{}, t: t}
	srv := server.New(server.Config{
		Handler:     h,
		Secret:      []byte("k"),
		Mode:        transport.ModeLegacy,
		IdleTimeout: 50 * time.Millisecond,
	})
	defer srv.Close()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn := transport.NewConn(a, transport.ModeLegacy, []byte("k"))

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ServeConn(context.Background(), conn) }()

	select {
	case err := <-errCh:
		require.Error(t, err)
		var ne net.Error
		require.True(t, errors.As(err, &ne), "want net.Error, got %T", err)
		assert.True(t, ne.Timeout(), "want timeout error")
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return on idle timeout")
	}
}
