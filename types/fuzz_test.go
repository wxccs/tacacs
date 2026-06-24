// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import "testing"

// FuzzParseArgument asserts the argument-value-pair parser never panics on
// arbitrary input and that, when parsing succeeds, String round-trips back to
// a value that parses again (the codec is closed over its own output).
func FuzzParseArgument(f *testing.F) {
	f.Add("service=shell")
	f.Add("cmd*")
	f.Add("priv-lvl=15")
	f.Add("")
	f.Add("=")
	f.Add("a*b=c")
	f.Fuzz(func(t *testing.T, s string) {
		arg, err := ParseArgument(s)
		if err != nil {
			return
		}
		if _, err := ParseArgument(arg.String()); err != nil {
			t.Fatalf("re-parse of %q (from %q) failed: %v", arg.String(), s, err)
		}
	})
}
