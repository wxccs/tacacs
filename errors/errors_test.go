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

package errors

import (
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentinelMessages(t *testing.T) {
	assert.Equal(t, "tacacs: shared secret mismatch", ErrSecretMismatch.Error())
	assert.Equal(t, "tacacs: invalid packet", ErrInvalidPacket.Error())
	assert.Equal(t, "tacacs: invalid argument", ErrInvalidArgument.Error())
	assert.Equal(t, "tacacs: invalid header", ErrInvalidHeader.Error())
}

func TestReexportedHelpers(t *testing.T) {
	err := New("boom")
	assert.Equal(t, "boom", err.Error())
	assert.True(t, Is(err, err))

	ve := NewValidationError("field", "reason", ErrInvalidPacket)
	var target *ValidationError
	assert.True(t, As(ve, &target))
	assert.Same(t, ve, target)

	_ = stderrors.Is // the standard library remains reachable via alias
}

func TestValidationErrorUnwrap(t *testing.T) {
	ve := NewValidationError("user_len", "exceeds max", ErrInvalidPacket)
	assert.True(t, Is(ve, ErrInvalidPacket))
	assert.Contains(t, ve.Error(), "user_len")
	assert.Contains(t, ve.Error(), "exceeds max")
	assert.Contains(t, ve.Error(), "invalid packet")

	ve2 := NewValidationError("", "no field", nil)
	assert.Contains(t, ve2.Error(), "no field")
	assert.NotContains(t, ve2.Error(), "::")

	ve3 := NewValidationError("", "", nil)
	assert.Equal(t, "tacacs: validation error", ve3.Error())

	ve4 := NewValidationError("field", "", nil)
	assert.Contains(t, ve4.Error(), "field")
}

func TestJoin(t *testing.T) {
	joined := Join(ErrInvalidPacket, ErrInvalidLength)
	assert.Error(t, joined)
	assert.True(t, Is(joined, ErrInvalidPacket))
	assert.True(t, Is(joined, ErrInvalidLength))
}
