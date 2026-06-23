// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import "github.com/wxccs/tacacs/errors"

// Body is a marshalled TACACS+ packet body. Implementations write and read the
// exact field layout and length-prefix scheme specified by RFC 8907 §5-8.
//
// MarshalBinary returns the body bytes; the caller is responsible for
// obfuscation and for filling the header length field with len(body).
type Body interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
}

// checkByteLen returns ErrInvalidLength if v does not fit in a single byte.
func checkByteLen(v int) error {
	if v < 0 || v > 0xff {
		return errors.NewValidationError("field", "length exceeds single byte", errors.ErrInvalidLength)
	}
	return nil
}

// checkU16Len returns ErrInvalidLength if v does not fit in 16 bits.
func checkU16Len(v int) error {
	if v < 0 || v > 0xffff {
		return errors.NewValidationError("field", "length exceeds 16 bits", errors.ErrInvalidLength)
	}
	return nil
}
