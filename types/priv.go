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
