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

// Packet and field size limits (RFC 8907 §4 and §5.1).
const (
	// HeaderLength is the fixed TACACS+ header size in bytes.
	HeaderLength = 12
	// MaxPacketSize is the recommended maximum packet size (RFC 8907 §4.1).
	MaxPacketSize = 1 << 16 // 65536
	// MaxArgCount is the maximum number of arguments, since arg_cnt is a
	// single byte.
	MaxArgCount = 255
	// MaxArgLength is the maximum length in bytes of a single argument-value
	// pair (RFC 8907 §5.1).
	MaxArgLength = 255
	// MinArgLength is the minimum length in bytes of an argument-value pair:
	// one name character plus the separator (RFC 8907 §5.1).
	MinArgLength = 2
)
