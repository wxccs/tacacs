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

// AcctFlags is the accounting REQUEST flags byte.
type AcctFlags byte

// Accounting REQUEST flags (RFC 8907 §7.2 / Table 2).
const (
	AcctFlagStart    AcctFlags = 0x02
	AcctFlagStop     AcctFlags = 0x04
	AcctFlagWatchdog AcctFlags = 0x08
)

// AcctFlagMask is the mask used to classify the accounting record type
// (RFC 8907 Table 2 column "flags & 0xE").
const AcctFlagMask AcctFlags = 0x0e

// AcctRecord classifies an accounting request by its flags (RFC 8907 Table 2).
type AcctRecord byte

// Accounting record classifications (RFC 8907 Table 2).
const (
	AcctRecordInvalid            AcctRecord = 0x00
	AcctRecordStart              AcctRecord = 0x02
	AcctRecordStop               AcctRecord = 0x04
	AcctRecordWatchdogNoUpdate   AcctRecord = 0x08
	AcctRecordWatchdogWithUpdate AcctRecord = 0x0a
)

// Record returns the accounting record classification for the given flags.
// The caller MUST reject AcctRecordInvalid (RFC 8907 Table 2).
func (f AcctFlags) Record() AcctRecord {
	switch f & AcctFlagMask {
	case AcctFlagStart:
		return AcctRecordStart
	case AcctFlagStop:
		return AcctRecordStop
	case AcctFlagWatchdog:
		return AcctRecordWatchdogNoUpdate
	case AcctFlagWatchdog | AcctFlagStart:
		return AcctRecordWatchdogWithUpdate
	default:
		return AcctRecordInvalid
	}
}

// AcctStatus is the accounting REPLY status.
type AcctStatus byte

// Accounting statuses (RFC 8907 §8.3). AcctStatusFollow is deprecated.
const (
	AcctStatusSuccess AcctStatus = 0x01
	AcctStatusError   AcctStatus = 0x02
	AcctStatusFollow  AcctStatus = 0x21
)
