// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

//go:build linux && cgo

package aaa

import "testing"

// TestPAMConstruct verifies the Linux/cgo constructor succeeds and applies the
// default service name. It does not invoke the PAM stack (which would require
// a configured /etc/pam.d service and real accounts).
func TestPAMConstruct(t *testing.T) {
	a, err := NewPAMAuthenticator(PAMConfig{})
	if err != nil {
		t.Fatalf("NewPAMAuthenticator: %v", err)
	}
	if a.service != "tacacs" {
		t.Errorf("service = %q, want default \"tacacs\"", a.service)
	}
	a2, err := NewPAMAuthenticator(PAMConfig{Service: "sshd"})
	if err != nil {
		t.Fatalf("NewPAMAuthenticator: %v", err)
	}
	if a2.service != "sshd" {
		t.Errorf("service = %q, want \"sshd\"", a2.service)
	}
}
