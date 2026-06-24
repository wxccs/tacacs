// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package errors

import (
	stderrors "errors"
	"strings"
)

// New, Is, As, Unwrap and Join wrap the standard library error helpers so
// that callers of the tacacs library can import a single errors package
// instead of aliasing the standard one.
func New(text string) error         { return stderrors.New(text) }
func Is(err, target error) bool     { return stderrors.Is(err, target) }
func As(err error, target any) bool { return stderrors.As(err, target) }
func Unwrap(err error) error        { return stderrors.Unwrap(err) }
func Join(errs ...error) error      { return stderrors.Join(errs...) }

// Sentinel errors describing well-known failure conditions. They are compared
// with errors.Is so that wrapped (e.g. ValidationError) instances still match.
var (
	ErrSecretMismatch      = stderrors.New("tacacs: shared secret mismatch")
	ErrInvalidPacket       = stderrors.New("tacacs: invalid packet")
	ErrInvalidHeader       = stderrors.New("tacacs: invalid header")
	ErrInvalidLength       = stderrors.New("tacacs: invalid length")
	ErrInvalidArgument     = stderrors.New("tacacs: invalid argument")
	ErrTooManyArguments    = stderrors.New("tacacs: too many arguments")
	ErrInvalidSeqNo        = stderrors.New("tacacs: invalid sequence number")
	ErrUnsupportedVersion  = stderrors.New("tacacs: unsupported version")
	ErrUnsupportedType     = stderrors.New("tacacs: unsupported packet type")
	ErrSessionClosed       = stderrors.New("tacacs: session closed")
	ErrSessionAborted      = stderrors.New("tacacs: session aborted")
	ErrFlagMismatch        = stderrors.New("tacacs: flag mismatch")
	ErrNoServerConfigured  = stderrors.New("tacacs: no server configured")
	ErrUnencryptedDisabled = stderrors.New("tacacs: unencrypted flag rejected")
	ErrNotImplemented      = stderrors.New("tacacs: not implemented")
)

// ValidationError describes a packet or field validation failure with enough
// context to locate the problem. The optional Err field carries an underlying
// sentinel so that errors.Is can match it.
type ValidationError struct {
	Field  string
	Reason string
	Err    error
}

// Error implements the error interface. It joins the field, reason and
// underlying error (if any) under the "tacacs" prefix, trimming a duplicate
// "tacacs: " prefix from a wrapped sentinel so the prefix is not repeated.
func (e *ValidationError) Error() string {
	var parts []string
	if e.Field != "" {
		parts = append(parts, e.Field)
	}
	if e.Reason != "" {
		parts = append(parts, e.Reason)
	}
	if e.Err != nil {
		parts = append(parts, strings.TrimPrefix(e.Err.Error(), "tacacs: "))
	}
	if len(parts) == 0 {
		return "tacacs: validation error"
	}
	return "tacacs: " + strings.Join(parts, ": ")
}

// Unwrap returns the underlying error so that errors.Is and errors.As traverse
// the wrapped sentinel.
func (e *ValidationError) Unwrap() error { return e.Err }

// NewValidationError constructs a ValidationError. Any of field, reason or err
// may be the zero value; the resulting message degrades gracefully.
func NewValidationError(field, reason string, err error) *ValidationError {
	return &ValidationError{Field: field, Reason: reason, Err: err}
}
