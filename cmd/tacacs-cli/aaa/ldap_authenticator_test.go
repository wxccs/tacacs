// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"context"
	"testing"
	"time"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

func TestNewLDAPAuthenticatorValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     LDAPConfig
		wantErr bool
	}{
		{
			name:    "ldaps ok",
			cfg:     LDAPConfig{URL: "ldaps://dir.example.com:636", BaseDN: "dc=x"},
			wantErr: false,
		},
		{
			name:    "ldap cleartext rejected",
			cfg:     LDAPConfig{URL: "ldap://dir.example.com:389", BaseDN: "dc=x"},
			wantErr: true,
		},
		{
			name:    "ldap with starttls ok",
			cfg:     LDAPConfig{URL: "ldap://dir.example.com:389", BaseDN: "dc=x", StartTLS: true},
			wantErr: false,
		},
		{
			name:    "ldap with allowinsecure ok",
			cfg:     LDAPConfig{URL: "ldap://dir.example.com:389", BaseDN: "dc=x", AllowInsecure: true},
			wantErr: false,
		},
		{
			name:    "missing basedn rejected",
			cfg:     LDAPConfig{URL: "ldaps://dir.example.com:636"},
			wantErr: true,
		},
		{
			name:    "bad scheme rejected",
			cfg:     LDAPConfig{URL: "http://dir.example.com", BaseDN: "dc=x"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLDAPAuthenticator(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestLDAPAuthenticatorDefaults verifies the constructor fills in a default
// user filter and timeout.
func TestLDAPAuthenticatorDefaults(t *testing.T) {
	a, err := NewLDAPAuthenticator(LDAPConfig{URL: "ldaps://dir:636", BaseDN: "dc=x"})
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator: %v", err)
	}
	if a.cfg.UserFilter != "(uid=%s)" {
		t.Errorf("UserFilter = %q, want default (uid=%%s)", a.cfg.UserFilter)
	}
	if a.cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", a.cfg.Timeout)
	}
}

// TestLDAPAuthenticatorEmptyPassword verifies an empty password is rejected as
// a failure WITHOUT contacting the directory (no anonymous/unauthenticated
// bind). The endpoint is unroutable, so reaching the network would error.
func TestLDAPAuthenticatorEmptyPassword(t *testing.T) {
	a, err := NewLDAPAuthenticator(LDAPConfig{
		URL:    "ldaps://127.0.0.1:1", // would fail to connect if dialed
		BaseDN: "dc=x",
	})
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator: %v", err)
	}
	ac := server.AuthenContext{Start: server.AuthenStart{
		User: "alice",
		Type: types.AuthenTypePAP,
		Data: []byte(""),
	}}
	dec, err := a.Authenticate(context.Background(), ac, nil)
	if err != nil {
		t.Fatalf("Authenticate: %v (empty password must not dial)", err)
	}
	if dec.Status != types.AuthenStatusFail {
		t.Errorf("status = %v, want FAIL for empty password", dec.Status)
	}
}

// TestLDAPAuthenticatorGetPass verifies the interactive ASCII flow returns
// GETPASS on the first step without dialing.
func TestLDAPAuthenticatorGetPass(t *testing.T) {
	a, err := NewLDAPAuthenticator(LDAPConfig{URL: "ldaps://127.0.0.1:1", BaseDN: "dc=x"})
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator: %v", err)
	}
	ac := server.AuthenContext{Start: server.AuthenStart{User: "bob", Type: types.AuthenTypeASCII}}
	dec, err := a.Authenticate(context.Background(), ac, nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if dec.Status != types.AuthenStatusGetPass {
		t.Errorf("status = %v, want GETPASS", dec.Status)
	}
}
