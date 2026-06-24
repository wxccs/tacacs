// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package types

import (
	"context"
	"log/slog"
)

// Logger is the structured logging interface used by the library core. It is
// signature-compatible with a subset of *slog.Logger, so a *slog.Logger (or any
// adapter satisfying this interface) can be injected. Callers pass
// msg string, args ...any where args are alternating key/value pairs, and
// levels use slog.Level (slog.LevelDebug, slog.LevelInfo, slog.LevelWarn,
// slog.LevelError).
type Logger interface {
	// Enabled reports whether the given level would be emitted under the
	// given context.
	Enabled(ctx context.Context, level slog.Level) bool
	// Debug logs at Debug level with key-value pairs.
	Debug(msg string, args ...any)
	// Info logs at Info level with key-value pairs.
	Info(msg string, args ...any)
	// Warn logs at Warn level with key-value pairs.
	Warn(msg string, args ...any)
	// Error logs at Error level with key-value pairs.
	Error(msg string, args ...any)
	// Log logs at the given level with context and key-value pairs.
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
	// With returns a Logger annotated with key-value pairs (alternating key,
	// value arguments, matching slog.Logger.With).
	With(args ...any) Logger
	// WithGroup returns a Logger with the given group name.
	WithGroup(name string) Logger
}

// nopLogger is a Logger that discards everything and reports no level enabled.
type nopLogger struct{}

// NopLogger returns a Logger that discards all output. It is the default
// logger used when no logger is configured.
func NopLogger() Logger { return nopLogger{} }

func (nopLogger) Enabled(context.Context, slog.Level) bool        { return false }
func (nopLogger) Debug(string, ...any)                            {}
func (nopLogger) Info(string, ...any)                             {}
func (nopLogger) Warn(string, ...any)                             {}
func (nopLogger) Error(string, ...any)                            {}
func (nopLogger) Log(context.Context, slog.Level, string, ...any) {}
func (nopLogger) With(...any) Logger                              { return nopLogger{} }
func (nopLogger) WithGroup(string) Logger                         { return nopLogger{} }

// WithFunc returns a Logger annotated with a "func" field naming the caller
// using the dotted path from the module root (e.g. "packet.Header.Marshal").
// It is a convenience wrapper for the project-wide "func" field convention,
// equivalent to l.With("func", name).
func WithFunc(l Logger, name string) Logger { return l.With("func", name) }
