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

package crypto

import "github.com/wxccs/tacacs/errors"

// Policy governs acceptance of the deprecated TAC_PLUS_UNENCRYPTED_FLAG.
// Servers MUST reject requests with the flag set unless the operator has
// explicitly allowed unencrypted operation (RFC 8907 §10.5.2). TLS connections
// require the flag set to 1 on every packet (RFC 9887 §4), handled by the
// transport layer.
type Policy struct {
	// AllowUnencrypted permits packets with TAC_PLUS_UNENCRYPTED_FLAG set. It
	// defaults to false: unencrypted packets are rejected. Operators may set it
	// true for controlled, isolated legacy deployments only.
	AllowUnencrypted bool
}

// CheckUnencryptedFlag reports whether a packet with the given unencrypted-flag
// state is acceptable under the policy. flagSet is true when
// TAC_PLUS_UNENCRYPTED_FLAG is set in the header.
//
// It returns ErrUnencryptedDisabled when the flag is set but not allowed.
func (p Policy) CheckUnencryptedFlag(flagSet bool) error {
	if flagSet && !p.AllowUnencrypted {
		return errors.NewValidationError("flags", "unencrypted flag set but not allowed", errors.ErrUnencryptedDisabled)
	}
	return nil
}
