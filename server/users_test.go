// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/wxccs/tacacs/types"
)

func mustBcrypt(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func TestUserVerifyBcrypt(t *testing.T) {
	u := User{Username: "a", PasswordHash: mustBcrypt(t, "secret")}
	assert.True(t, u.VerifyPassword("secret", u.PasswordHash, false))
	assert.False(t, u.VerifyPassword("wrong", u.PasswordHash, false))
}

func TestUserVerifyPlaintext(t *testing.T) {
	u := User{Username: "a", PasswordHash: "cleartext"}
	// Disallowed by default.
	assert.False(t, u.VerifyPassword("cleartext", u.PasswordHash, false))
	// Allowed when explicitly opted in.
	assert.True(t, u.VerifyPassword("cleartext", u.PasswordHash, true))
	assert.False(t, u.VerifyPassword("nope", u.PasswordHash, true))
}

func TestUserVerifyDisabled(t *testing.T) {
	u := User{Username: "a", PasswordHash: ""}
	assert.False(t, u.VerifyPassword("x", "", false))
}

func TestMemoryUserStore(t *testing.T) {
	s := NewMemoryUserStore([]User{{Username: "alice"}, {Username: "bob"}})
	u, ok := s.Lookup("alice")
	assert.True(t, ok)
	assert.Equal(t, "alice", u.Username)
	_, ok = s.Lookup("carol")
	assert.False(t, ok)
}

func TestPolicyAllows(t *testing.T) {
	p := Policy{
		AllowCommands: []string{"show *", "exit"},
		DenyCommands:  []string{"show secret"},
	}
	assert.True(t, p.Allows("show version"))
	assert.True(t, p.Allows("exit"))
	// Deny takes precedence.
	assert.False(t, p.Allows("show secret"))
	assert.False(t, p.Allows("configure terminal"))
	// Empty policy denies all.
	assert.False(t, Policy{}.Allows("anything"))
}

func TestUserConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  UserConfig
		ok   bool
	}{
		{"bcrypt user", UserConfig{Users: []User{{Username: "a", PasswordHash: "$2a$abc"}}}, true},
		{"missing username", UserConfig{Users: []User{{PasswordHash: "$2a$abc"}}}, false},
		{"empty password", UserConfig{Users: []User{{Username: "a"}}}, false},
		{"duplicate", UserConfig{Users: []User{{Username: "a", PasswordHash: "$2a$1"}, {Username: "a", PasswordHash: "$2a$2"}}}, false},
		{"plaintext without opt-in", UserConfig{Users: []User{{Username: "a", PasswordHash: "plain"}}}, false},
		{"plaintext with opt-in", UserConfig{AllowPlaintext: true, Users: []User{{Username: "a", PasswordHash: "plain"}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func writeUserConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

func TestLoadUserConfig(t *testing.T) {
	hash := mustBcrypt(t, "pw123")
	yaml := "users:\n" +
		"  - username: admin\n" +
		"    password: " + hash + "\n" +
		"    auth-type: pap\n" +
		"policy:\n" +
		"  allow-commands:\n" +
		"    - \"show *\"\n" +
		"  deny-commands:\n" +
		"    - \"show secret\"\n"
	cfg, err := LoadUserConfig(writeUserConfig(t, yaml))
	require.NoError(t, err)
	require.Len(t, cfg.Users, 1)
	assert.Equal(t, "admin", cfg.Users[0].Username)
	assert.Equal(t, "pap", cfg.Users[0].AuthType)
	assert.Equal(t, []string{"show *"}, cfg.Policy.AllowCommands)
}

func TestConfigHandlerAuthPAP(t *testing.T) {
	cfg := &UserConfig{Users: []User{{Username: "admin", PasswordHash: mustBcrypt(t, "pw123"), AuthType: "pap"}}}
	h, err := NewConfigHandler(cfg)
	require.NoError(t, err)

	// Correct password (PAP carries the password in Start.Data).
	dec, err := h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("pw123")},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, dec.Status)

	// Wrong password.
	dec, err = h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("wrong")},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusFail, dec.Status)

	// Unknown user.
	dec, err = h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "nobody", Type: types.AuthenTypePAP, Data: []byte("x")},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusFail, dec.Status)
}

func TestConfigHandlerAuthASCII(t *testing.T) {
	cfg := &UserConfig{Users: []User{{Username: "bob", PasswordHash: mustBcrypt(t, "hunter2")}}}
	h, err := NewConfigHandler(cfg)
	require.NoError(t, err)

	// START -> GETPASS.
	dec, err := h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "bob", Type: types.AuthenTypeASCII},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusGetPass, dec.Status)

	// CONTINUE with correct password.
	dec, err = h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "bob", Type: types.AuthenTypeASCII},
	}, &AuthenContinue{UserMsg: "hunter2"})
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, dec.Status)

	// CONTINUE with wrong password.
	dec, err = h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "bob", Type: types.AuthenTypeASCII},
	}, &AuthenContinue{UserMsg: "nope"})
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusFail, dec.Status)
}

func TestConfigHandlerAuthTypeRestriction(t *testing.T) {
	cfg := &UserConfig{Users: []User{{Username: "u", PasswordHash: mustBcrypt(t, "p"), AuthType: "pap"}}}
	h, err := NewConfigHandler(cfg)
	require.NoError(t, err)
	// ASCII not allowed for a pap-only user.
	dec, _ := h.Authenticate(context.Background(), AuthenContext{
		Start: AuthenStart{User: "u", Type: types.AuthenTypeASCII},
	}, nil)
	assert.Equal(t, types.AuthenStatusFail, dec.Status)
}

func TestConfigHandlerAuthorize(t *testing.T) {
	cfg := &UserConfig{
		Users: []User{{Username: "admin", PasswordHash: mustBcrypt(t, "p")}},
		Policy: Policy{
			AllowCommands: []string{"show *", "exit"},
			DenyCommands:  []string{"show secret"},
		},
	}
	h, err := NewConfigHandler(cfg)
	require.NoError(t, err)

	// Allowed.
	dec, err := h.Authorize(context.Background(), AuthorContext{
		User: "admin",
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, dec.Status)

	// Denied by deny rule.
	dec, err = h.Authorize(context.Background(), AuthorContext{
		User: "admin",
		Args: []types.Argument{{Name: "cmd", Value: "show secret"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, dec.Status)

	// Not in allow list.
	dec, err = h.Authorize(context.Background(), AuthorContext{
		User: "admin",
		Args: []types.Argument{{Name: "cmd", Value: "configure terminal"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, dec.Status)

	// Unknown user.
	dec, err = h.Authorize(context.Background(), AuthorContext{
		User: "nobody",
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, dec.Status)
}

func TestConfigHandlerAccount(t *testing.T) {
	h, err := NewConfigHandler(&UserConfig{Users: []User{{Username: "a", PasswordHash: "$2a$x"}}})
	require.NoError(t, err)
	dec, err := h.Account(context.Background(), AcctContext{User: "a"})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, dec.Status)
}

func TestLoadUserConfigFromBytesJSON(t *testing.T) {
	hash := mustBcrypt(t, "p")
	json := `{"users":[{"username":"a","password":"` + hash + `"}]}`
	cfg, err := LoadUserConfigFromBytes([]byte(json), "json")
	require.NoError(t, err)
	require.Len(t, cfg.Users, 1)
}

func TestAuthTypeMatches(t *testing.T) {
	assert.True(t, authTypeMatches("ascii", types.AuthenTypeASCII))
	assert.False(t, authTypeMatches("ascii", types.AuthenTypePAP))
	assert.True(t, authTypeMatches("pap", types.AuthenTypePAP))
	assert.True(t, authTypeMatches("", types.AuthenTypeCHAP))
	assert.True(t, authTypeMatches("any", types.AuthenTypeMSCHAPv2))
	assert.False(t, authTypeMatches("bogus", types.AuthenTypeASCII))
}
