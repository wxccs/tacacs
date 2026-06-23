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

package legacy

import (
	"encoding/binary"

	"github.com/wxccs/tacacs/errors"
)

// UDPSimple is the 6-byte-header original-TACACS request/reply over UDP
// (RFC 1492 §2.1).
//
//	version(1) | type(1) | nonce(2) | user_len_or_response(1) | pw_len_or_reason(1) | data
type UDPSimple struct {
	Version byte
	Type    byte
	Nonce   uint16
	// On requests: UserLen. On replies: Response.
	UserLenOrResponse byte
	// On requests: PwLen. On replies: Reason.
	PwLenOrReason byte
	// Data is the raw username immediately followed by the password.
	Data []byte
}

// MarshalBinary encodes the simple packet.
func (p UDPSimple) MarshalBinary() ([]byte, error) {
	b := make([]byte, UDPHeaderLenSimple+len(p.Data))
	if p.Version != UDPVersionSimple {
		return nil, errors.NewValidationError("version", "simple packet must use version 0", errors.ErrUnsupportedVersion)
	}
	b[0] = p.Version
	b[1] = p.Type
	binary.BigEndian.PutUint16(b[2:4], p.Nonce)
	b[4] = p.UserLenOrResponse
	b[5] = p.PwLenOrReason
	copy(b[6:], p.Data)
	return b, nil
}

// UnmarshalBinary decodes a simple packet.
func (p *UDPSimple) UnmarshalBinary(data []byte) error {
	if len(data) < UDPHeaderLenSimple {
		return errors.NewValidationError("udp_simple", "short buffer", errors.ErrInvalidPacket)
	}
	p.Version = data[0]
	p.Type = data[1]
	p.Nonce = binary.BigEndian.Uint16(data[2:4])
	p.UserLenOrResponse = data[4]
	p.PwLenOrReason = data[5]
	p.Data = append([]byte(nil), data[6:]...)
	return nil
}

// User returns the username portion of Data (first UserLenOrResponse bytes) for
// a request.
func (p UDPSimple) User() string {
	n := int(p.UserLenOrResponse)
	if n > len(p.Data) {
		n = len(p.Data)
	}
	return string(p.Data[:n])
}

// Password returns the password portion of Data for a request.
func (p UDPSimple) Password() string {
	n := int(p.UserLenOrResponse)
	if n > len(p.Data) {
		return ""
	}
	return string(p.Data[n:])
}

// UDPExtended is the 26-byte-header original-TACACS request/reply over UDP
// (RFC 1492 §2.1).
//
//	version(1) | type(1) | nonce(2) | user_len(1) | pw_len(1) | response(1) |
//	reason(1) | result1(4) | dest_host(4) | dest_port(2) | line(2) |
//	result2(4) | result3(2) | data
type UDPExtended struct {
	Version  byte
	Type     byte
	Nonce    uint16
	UserLen  byte
	PwLen    byte
	Response byte
	Reason   byte
	Result1  uint32
	DestHost [4]byte // IP address
	DestPort uint16
	Line     uint16
	Result2  uint32
	Result3  uint16
	Data     []byte // username immediately followed by password
}

// MarshalBinary encodes the extended packet.
func (p UDPExtended) MarshalBinary() ([]byte, error) {
	b := make([]byte, UDPHeaderLenExtended+len(p.Data))
	if p.Version != UDPVersionExtended {
		return nil, errors.NewValidationError("version", "extended packet must use version 128", errors.ErrUnsupportedVersion)
	}
	b[0] = p.Version
	b[1] = p.Type
	binary.BigEndian.PutUint16(b[2:4], p.Nonce)
	b[4] = p.UserLen
	b[5] = p.PwLen
	b[6] = p.Response
	b[7] = p.Reason
	binary.BigEndian.PutUint32(b[8:12], p.Result1)
	copy(b[12:16], p.DestHost[:])
	binary.BigEndian.PutUint16(b[16:18], p.DestPort)
	binary.BigEndian.PutUint16(b[18:20], p.Line)
	binary.BigEndian.PutUint32(b[20:24], p.Result2)
	binary.BigEndian.PutUint16(b[24:26], p.Result3)
	copy(b[26:], p.Data)
	return b, nil
}

// UnmarshalBinary decodes an extended packet.
func (p *UDPExtended) UnmarshalBinary(data []byte) error {
	if len(data) < UDPHeaderLenExtended {
		return errors.NewValidationError("udp_extended", "short buffer", errors.ErrInvalidPacket)
	}
	p.Version = data[0]
	p.Type = data[1]
	p.Nonce = binary.BigEndian.Uint16(data[2:4])
	p.UserLen = data[4]
	p.PwLen = data[5]
	p.Response = data[6]
	p.Reason = data[7]
	p.Result1 = binary.BigEndian.Uint32(data[8:12])
	copy(p.DestHost[:], data[12:16])
	p.DestPort = binary.BigEndian.Uint16(data[16:18])
	p.Line = binary.BigEndian.Uint16(data[18:20])
	p.Result2 = binary.BigEndian.Uint32(data[20:24])
	p.Result3 = binary.BigEndian.Uint16(data[24:26])
	p.Data = append([]byte(nil), data[26:]...)
	return nil
}

// User returns the username portion of Data.
func (p UDPExtended) User() string {
	n := int(p.UserLen)
	if n > len(p.Data) {
		n = len(p.Data)
	}
	return string(p.Data[:n])
}

// Password returns the password portion of Data.
func (p UDPExtended) Password() string {
	n := int(p.UserLen)
	if n > len(p.Data) {
		return ""
	}
	return string(p.Data[n:])
}

// IsExtended reports whether the version byte selects the extended form.
func IsExtended(version byte) bool { return version == UDPVersionExtended }

// IsSimple reports whether the version byte selects the simple form.
func IsSimple(version byte) bool { return version == UDPVersionSimple }
