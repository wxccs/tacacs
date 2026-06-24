// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNopLogger(t *testing.T) {
	// With/WithGroup chain returns a Logger; level methods are invoked as
	// separate statements and must not panic.
	l := NopLogger().With("k", "v", "a", 1).WithGroup("g")
	l.Debug("debug", "x", "y")
	l.Info("info", "x", "y")
	l.Warn("warn", "x", "y")
	l.Error("error", "x", "y")
	l.Log(context.Background(), slog.LevelInfo, "log", "x", "y")
	assert.False(t, l.Enabled(context.Background(), slog.LevelDebug))
	assert.False(t, l.Enabled(context.Background(), slog.LevelInfo))
	assert.False(t, l.Enabled(context.Background(), slog.LevelWarn))
	assert.False(t, l.Enabled(context.Background(), slog.LevelError))
}

func TestWithFunc(t *testing.T) {
	// WithFunc is a convenience wrapper equivalent to l.With("func", name).
	// NopLogger discards everything, so we only verify it returns a non-nil
	// Logger and does not panic when chained.
	l := WithFunc(NopLogger(), "packet.Header.Marshal")
	assert.NotNil(t, l)
	// Verify the wrapped logger still satisfies the interface and chains.
	_ = l.With("k", "v").WithGroup("g")
	l.Info("msg")
}

func TestLevelOrdering(t *testing.T) {
	// Levels use slog.Level numeric ordering: Debug=-4, Info=0, Warn=4, Error=8.
	assert.Equal(t, slog.Level(-4), slog.LevelDebug)
	assert.Equal(t, slog.Level(0), slog.LevelInfo)
	assert.Equal(t, slog.Level(4), slog.LevelWarn)
	assert.Equal(t, slog.Level(8), slog.LevelError)
	assert.Less(t, slog.LevelDebug, slog.LevelInfo)
	assert.Less(t, slog.LevelInfo, slog.LevelWarn)
	assert.Less(t, slog.LevelWarn, slog.LevelError)
}
