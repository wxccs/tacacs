// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

//go:build !linux || !cgo

package aaa

import "testing"

// TestPAMUnavailable verifies that on platforms without PAM support the
// constructor fails cleanly rather than pretending to authenticate.
func TestPAMUnavailable(t *testing.T) {
	if _, err := NewPAMAuthenticator(PAMConfig{}); err == nil {
		t.Error("expected NewPAMAuthenticator to error on non-linux/non-cgo build")
	}
}
