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
