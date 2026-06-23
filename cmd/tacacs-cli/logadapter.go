// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

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
