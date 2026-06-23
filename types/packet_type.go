// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
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
