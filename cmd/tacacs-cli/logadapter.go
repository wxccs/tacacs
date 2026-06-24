// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"context"
	"log/slog"

	"github.com/sirupsen/logrus"

	"github.com/wxccs/tacacs/types"
)

// logrusLogger adapts a *logrus.Logger to the types.Logger interface, which is
// signature-compatible with a subset of *slog.Logger. Each log call carries a
// "func" field naming the caller using the dotted path from the module root
// (e.g. "packet.Header.Marshal"), set via types.WithFunc.
type logrusLogger struct {
	entry *logrus.Entry
	level slog.Level // Enabled threshold
}

// newLogrusLogger returns a Logger backed by the given logrus logger at the
// given slog level.
func newLogrusLogger(base *logrus.Logger, level slog.Level) *logrusLogger {
	base.SetLevel(toLogrus(level))
	return &logrusLogger{entry: logrus.NewEntry(base), level: level}
}

func (l *logrusLogger) Enabled(_ context.Context, level slog.Level) bool {
	return level >= l.level
}

func (l *logrusLogger) Debug(msg string, args ...any) { l.log(logrus.DebugLevel, msg, args) }
func (l *logrusLogger) Info(msg string, args ...any)  { l.log(logrus.InfoLevel, msg, args) }
func (l *logrusLogger) Warn(msg string, args ...any)  { l.log(logrus.WarnLevel, msg, args) }
func (l *logrusLogger) Error(msg string, args ...any) { l.log(logrus.ErrorLevel, msg, args) }

func (l *logrusLogger) Log(_ context.Context, level slog.Level, msg string, args ...any) {
	l.log(toLogrus(level), msg, args)
}

func (l *logrusLogger) With(args ...any) types.Logger {
	return &logrusLogger{entry: l.entry.WithFields(argsToFields(args)), level: l.level}
}

// WithGroup is a no-op for the logrus adapter; logrus has no native group
// concept. Returns the receiver unchanged so the interface is satisfied.
func (l *logrusLogger) WithGroup(_ string) types.Logger { return l }

func (l *logrusLogger) log(lv logrus.Level, msg string, args []any) {
	if len(args) == 0 {
		l.entry.Log(lv, msg)
		return
	}
	l.entry.WithFields(argsToFields(args)).Log(lv, msg)
}

// argsToFields converts a slog-style alternating key/value slice into a
// logrus.Fields map. Non-string keys are skipped (slog's contract is string
// keys).
func argsToFields(args []any) logrus.Fields {
	fields := make(logrus.Fields, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		if key, ok := args[i].(string); ok {
			fields[key] = args[i+1]
		}
	}
	return fields
}

func toLogrus(level slog.Level) logrus.Level {
	switch {
	case level >= slog.LevelError:
		return logrus.ErrorLevel
	case level >= slog.LevelWarn:
		return logrus.WarnLevel
	case level >= slog.LevelInfo:
		return logrus.InfoLevel
	default:
		return logrus.DebugLevel
	}
}
