// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
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
