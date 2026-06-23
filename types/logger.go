// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package types

// Level is a logging severity level, matching the logrus numeric ordering
// (Panic=0, Fatal=1, Error=2, Warn=3, Info=4, Debug=5, Trace=6).
type Level int

// Logging levels.
const (
	LevelPanic Level = iota
	LevelFatal
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

// Logger is the structured logging interface used by the library core. The
// core stays free of any logging dependency; the CLI and server inject an
// adapter (e.g. logrus) that produces a "func" field naming the caller using
// the dotted path from the module root, for example "packet.Header.Marshal".
//
// Callers performing expensive formatting (such as hex-dumping packets) should
// guard with Enabled(LevelTrace) so the work is skipped unless trace logging
// is enabled.
type Logger interface {
	// WithFunc returns a logger annotated with the dotted caller name used as
	// the "func" field value.
	WithFunc(name string) Logger
	// WithField returns a logger with an additional structured field.
	WithField(key string, value any) Logger
	// WithFields returns a logger with additional structured fields.
	WithFields(fields map[string]any) Logger
	// Enabled reports whether the given level would be emitted.
	Enabled(level Level) bool
	// Tracef logs at trace level (used for detailed upstream request/response).
	Tracef(format string, args ...any)
	// Debugf logs at debug level.
	Debugf(format string, args ...any)
	// Infof logs at info level.
	Infof(format string, args ...any)
	// Warnf logs at warn level.
	Warnf(format string, args ...any)
	// Errorf logs at error level.
	Errorf(format string, args ...any)
}

// nopLogger is a Logger that discards everything and reports no level enabled.
type nopLogger struct{}

// NopLogger returns a Logger that discards all output. It is the default
// logger used when no logger is configured.
func NopLogger() Logger { return nopLogger{} }

func (nopLogger) WithFunc(string) Logger           { return nopLogger{} }
func (nopLogger) WithField(string, any) Logger     { return nopLogger{} }
func (nopLogger) WithFields(map[string]any) Logger { return nopLogger{} }
func (nopLogger) Enabled(Level) bool               { return false }
func (nopLogger) Tracef(string, ...any)            {}
func (nopLogger) Debugf(string, ...any)            {}
func (nopLogger) Infof(string, ...any)             {}
func (nopLogger) Warnf(string, ...any)             {}
func (nopLogger) Errorf(string, ...any)            {}
