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

// PacketType identifies the kind of TACACS+ packet (header byte 1).
type PacketType byte

// Packet types (RFC 8907 §4.1).
const (
	PacketAuthentication PacketType = 0x01
	PacketAuthorization  PacketType = 0x02
	PacketAccounting     PacketType = 0x03
)

// String returns a human-readable name for the packet type.
func (t PacketType) String() string {
	switch t {
	case PacketAuthentication:
		return "authentication"
	case PacketAuthorization:
		return "authorization"
	case PacketAccounting:
		return "accounting"
	default:
		return "unknown"
	}
}

// Valid reports whether t is a defined packet type.
func (t PacketType) Valid() bool {
	switch t {
	case PacketAuthentication, PacketAuthorization, PacketAccounting:
		return true
	default:
		return false
	}
}
