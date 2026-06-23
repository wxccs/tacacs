// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
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
