// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package types

// PrivLevel is the privilege level, an ordered value in the range 0..15
// (RFC 8907 §9). Each level is a superset of the next lower level.
type PrivLevel byte

// Privilege levels (RFC 8907 §9).
const (
	// PrivLevelMin is the privilege of an unauthenticated session.
	PrivLevelMin PrivLevel = 0x00
	// PrivLevelUser is the privilege of a regular authenticated session.
	PrivLevelUser PrivLevel = 0x01
	// PrivLevelRoot is a highly privileged level.
	PrivLevelRoot PrivLevel = 0x0f
	// PrivLevelMax is the highest privilege level (same value as Root).
	PrivLevelMax PrivLevel = 0x0f
)
