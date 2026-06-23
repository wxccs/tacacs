// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package types

import "github.com/wxccs/tacacs/errors"

// Argument separators (RFC 8907 §5.1). The separator immediately follows the
// argument name: '=' marks a mandatory argument, '*' marks an optional one.
const (
	ArgSeparatorMandatory byte = '=' // 0x3d
	ArgSeparatorOptional  byte = '*' // 0x2a
)

// Argument is a single authorization or accounting argument-value pair.
type Argument struct {
	// Mandatory is true when the separator is '='. The receiver MUST be able to
	// handle a mandatory argument, otherwise authorization fails (RFC 8907
	// §5.1).
	Mandatory bool
	// Name is the argument name. It MUST NOT contain a separator.
	Name string
	// Value is the argument value. It MAY contain separators and MAY be empty.
	Value string
}

// String encodes the argument as "name=value" (mandatory) or "name*value"
// (optional).
func (a Argument) String() string {
	sep := ArgSeparatorOptional
	if a.Mandatory {
		sep = ArgSeparatorMandatory
	}
	return a.Name + string(sep) + a.Value
}

// ParseArgument parses a single argument-value pair. The separator is the
// first '=' or '*' byte; the name is the text before it and the value is the
// text after it (RFC 8907 §5.1). A pair without a separator, or with an empty
// name, is invalid.
func ParseArgument(s string) (Argument, error) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ArgSeparatorMandatory, ArgSeparatorOptional:
			if i == 0 {
				return Argument{}, errors.NewValidationError("argument", "empty name", errors.ErrInvalidArgument)
			}
			return Argument{
				Mandatory: s[i] == ArgSeparatorMandatory,
				Name:      s[:i],
				Value:     s[i+1:],
			}, nil
		}
	}
	return Argument{}, errors.NewValidationError("argument", "missing separator", errors.ErrInvalidArgument)
}
