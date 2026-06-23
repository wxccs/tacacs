// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNopLogger(t *testing.T) {
	// The With* methods return a Logger and chain; the level methods return
	// nothing, so they are invoked as separate statements.
	l := NopLogger().WithFunc("pkg.Func").WithField("k", "v").WithFields(map[string]any{"a": 1})
	l.Tracef("trace %s", "x")
	l.Debugf("debug %s", "x")
	l.Infof("info %s", "x")
	l.Warnf("warn %s", "x")
	l.Errorf("error %s", "x")
	assert.False(t, l.Enabled(LevelPanic))
	assert.False(t, l.Enabled(LevelError))
	assert.False(t, l.Enabled(LevelInfo))
	assert.False(t, l.Enabled(LevelTrace))
}

func TestLevelOrdering(t *testing.T) {
	// Levels match the logrus numeric ordering: Panic=0..Trace=6.
	assert.Equal(t, Level(0), LevelPanic)
	assert.Equal(t, Level(1), LevelFatal)
	assert.Equal(t, Level(2), LevelError)
	assert.Equal(t, Level(3), LevelWarn)
	assert.Equal(t, Level(4), LevelInfo)
	assert.Equal(t, Level(5), LevelDebug)
	assert.Equal(t, Level(6), LevelTrace)
	assert.Less(t, LevelError, LevelWarn)
	assert.Less(t, LevelWarn, LevelInfo)
	assert.Less(t, LevelInfo, LevelDebug)
	assert.Less(t, LevelDebug, LevelTrace)
}
