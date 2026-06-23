// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import "github.com/wxccs/tacacs/errors"

// encodeArgLengths writes the arg_cnt byte followed by one length byte per
// argument (RFC 8907 §5.1). It returns the byte count written.
func encodeArgLengths(buf []byte, pos int, args []string) (int, error) {
	if len(args) > 0xff {
		return 0, errors.NewValidationError("arg_cnt", "exceeds 255", errors.ErrTooManyArguments)
	}
	buf[pos] = byte(len(args))
	pos++
	for _, a := range args {
		if err := checkByteLen(len(a)); err != nil {
			return 0, err
		}
		buf[pos] = byte(len(a))
		pos++
	}
	return pos, nil
}

// decodeArgLengths reads the arg_cnt byte and the following length bytes from
// data starting at pos. It returns the lengths and the new position.
func decodeArgLengths(data []byte, pos int) (lengths []int, newPos int, err error) {
	if pos >= len(data) {
		return nil, pos, errors.NewValidationError("arg_cnt", "missing", errors.ErrInvalidPacket)
	}
	n := int(data[pos])
	pos++
	if pos+n > len(data) {
		return nil, pos, errors.NewValidationError("arg_lengths", "short buffer", errors.ErrInvalidPacket)
	}
	lengths = make([]int, n)
	for i := 0; i < n; i++ {
		lengths[i] = int(data[pos])
		pos++
	}
	return lengths, pos, nil
}
