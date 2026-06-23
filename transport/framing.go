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

package transport

import (
	"io"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/types"
)

// readFull reads exactly len(buf) bytes, returning io.ErrUnexpectedEOF if the
// reader ends early.
func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

// ReadPacket reads one TACACS+ packet (header + body) from r and returns the
// parsed header and the raw (still obfuscated or cleartext) body bytes. The
// caller is responsible for de-obfuscating the body according to the header
// flags. A short read returns a wrapped ErrInvalidPacket.
func ReadPacket(r io.Reader) (packet.Header, []byte, error) {
	var hdrBuf [types.HeaderLength]byte
	if err := readFull(r, hdrBuf[:]); err != nil {
		return packet.Header{}, nil, err
	}
	var hdr packet.Header
	if err := hdr.UnmarshalBinary(hdrBuf[:]); err != nil {
		return packet.Header{}, nil, err
	}
	if hdr.Length > types.MaxPacketSize {
		return hdr, nil, errors.NewValidationError("length", "exceeds max packet size", errors.ErrInvalidLength)
	}
	body := make([]byte, hdr.Length)
	if hdr.Length > 0 {
		if err := readFull(r, body); err != nil {
			return hdr, nil, err
		}
	}
	return hdr, body, nil
}

// WritePacket writes a TACACS+ packet (header + body) to w. The header length
// field is set to len(body) before marshalling.
func WritePacket(w io.Writer, hdr packet.Header, body []byte) error {
	hdr.Length = uint32(len(body))
	hb, err := hdr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := w.Write(hb); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}
