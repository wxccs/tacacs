// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package main

import (
	"github.com/sirupsen/logrus"

	"github.com/wxccs/tacacs/types"
)

// logrusLogger adapts a logrus.FieldLogger to the types.Logger interface. Each
// log call carries a "func" field naming the caller using the dotted path from
// the module root (e.g. "packet.Header.Marshal").
type logrusLogger struct {
	entry *logrus.Entry
}

// newLogrusLogger returns a Logger backed by the given logrus logger at the
// given level.
func newLogrusLogger(base *logrus.Logger, level types.Level) *logrusLogger {
	lv := logrus.InfoLevel
	switch level {
	case types.LevelPanic:
		lv = logrus.PanicLevel
	case types.LevelFatal:
		lv = logrus.FatalLevel
	case types.LevelError:
		lv = logrus.ErrorLevel
	case types.LevelWarn:
		lv = logrus.WarnLevel
	case types.LevelInfo:
		lv = logrus.InfoLevel
	case types.LevelDebug:
		lv = logrus.DebugLevel
	case types.LevelTrace:
		lv = logrus.TraceLevel
	}
	base.SetLevel(lv)
	return &logrusLogger{entry: logrus.NewEntry(base)}
}

func (l *logrusLogger) WithFunc(name string) types.Logger {
	return &logrusLogger{entry: l.entry.WithField("func", name)}
}

func (l *logrusLogger) WithField(key string, value any) types.Logger {
	return &logrusLogger{entry: l.entry.WithField(key, value)}
}

func (l *logrusLogger) WithFields(fields map[string]any) types.Logger {
	return &logrusLogger{entry: l.entry.WithFields(logrus.Fields(fields))}
}

func (l *logrusLogger) Enabled(level types.Level) bool {
	return l.entry.Logger.IsLevelEnabled(toLogrus(level))
}

func (l *logrusLogger) Tracef(format string, args ...any) { l.entry.Tracef(format, args...) }
func (l *logrusLogger) Debugf(format string, args ...any) { l.entry.Debugf(format, args...) }
func (l *logrusLogger) Infof(format string, args ...any)  { l.entry.Infof(format, args...) }
func (l *logrusLogger) Warnf(format string, args ...any)  { l.entry.Warnf(format, args...) }
func (l *logrusLogger) Errorf(format string, args ...any) { l.entry.Errorf(format, args...) }

func toLogrus(level types.Level) logrus.Level {
	switch level {
	case types.LevelPanic:
		return logrus.PanicLevel
	case types.LevelFatal:
		return logrus.FatalLevel
	case types.LevelError:
		return logrus.ErrorLevel
	case types.LevelWarn:
		return logrus.WarnLevel
	case types.LevelInfo:
		return logrus.InfoLevel
	case types.LevelDebug:
		return logrus.DebugLevel
	case types.LevelTrace:
		return logrus.TraceLevel
	default:
		return logrus.InfoLevel
	}
}
