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

package types

// MajorVersion is the major protocol version (RFC 8907 §4.4). It is always
// 0xc for TACACS+.
const MajorVersion byte = 0x0c

// Minor version values (RFC 8907 §4.4).
const (
	// MinorVersionNone is the default minor version, used for ASCII
	// authentication, authorization and accounting.
	MinorVersionNone byte = 0x00
	// MinorVersionOne is used for PAP, CHAP, MS-CHAP and MS-CHAPv2
	// authentication (RFC 8907 §5.4.1).
	MinorVersionOne byte = 0x01
)

// Version is the packed header version byte (major<<4 | minor).
type Version byte

// Packed version byte values.
const (
	// VersionDefault is major 0xc | minor 0x0.
	VersionDefault Version = 0xc0
	// VersionOne is major 0xc | minor 0x1.
	VersionOne Version = 0xc1
)

// Major returns the major version nibble.
func (v Version) Major() byte { return byte(v) >> 4 }

// Minor returns the minor version nibble.
func (v Version) Minor() byte { return byte(v) & 0x0f }

// Valid reports whether v is a supported TACACS+ version byte.
func (v Version) Valid() bool {
	switch v {
	case VersionDefault, VersionOne:
		return true
	default:
		return false
	}
}

// MinorVersionFor returns the minor version to use for an authentication
// exchange per RFC 8907 §5.4.1: ASCII uses 0; PAP, CHAP, MS-CHAP and
// MS-CHAPv2 use 1. Authorization and accounting always use 0.
func MinorVersionFor(t AuthenType) byte {
	switch t {
	case AuthenTypePAP, AuthenTypeCHAP, AuthenTypeMSCHAP, AuthenTypeMSCHAPv2:
		return MinorVersionOne
	default:
		return MinorVersionNone
	}
}
