// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
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
