// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

// HeaderFlags is the header flags byte (RFC 8907 §4.2).
type HeaderFlags byte

// Header flag bits (RFC 8907 §4.2).
const (
	// FlagUnencrypted indicates the packet body is cleartext. It is deprecated
	// and MUST NOT be used in production over a non-TLS connection (RFC 8907
	// §10.5.2). Under TLS it MUST be set on every packet in both directions
	// (RFC 9887 §4).
	FlagUnencrypted HeaderFlags = 0x01
	// FlagSingleConnect requests single-connection mode, allowing multiple
	// sessions to be multiplexed over one TCP connection (RFC 8907 §4.3).
	FlagSingleConnect HeaderFlags = 0x04
)

// Has reports whether all of the given flag bits are set.
func (f HeaderFlags) Has(flag HeaderFlags) bool { return f&flag == flag }

// Valid reports whether f uses only defined bits (0x01 and 0x04). Undefined
// bits MUST be ignored on read and SHOULD be zero on write (RFC 8907 §4.2).
func (f HeaderFlags) Valid() bool {
	const defined = FlagUnencrypted | FlagSingleConnect
	return f&^defined == 0
}
