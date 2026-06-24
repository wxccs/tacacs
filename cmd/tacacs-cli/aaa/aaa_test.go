// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// helper to build a UserConfig with bcrypt-hashable plaintext-ish entries.
// We use allow-plaintext to avoid bcrypt cost in unit tests.
func cfgForTest() *server.UserConfig {
	return &server.UserConfig{
		AllowPlaintext: true,
		Users: []server.User{
			{Username: "admin", PasswordHash: "admin123", AuthType: "pap"},
			{Username: "operator", PasswordHash: "op123", AuthType: "ascii"},
		},
	}
}

func TestBcryptAuthenticator_PAPPass(t *testing.T) {
	a := NewBcryptAuthenticator(cfgForTest())
	dec, err := a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("admin123")},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, types.AuthenStatusPass, dec.Status)
}

func TestBcryptAuthenticator_PAPFailWrongPassword(t *testing.T) {
	a := NewBcryptAuthenticator(cfgForTest())
	dec, _ := a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("WRONG")},
	}, nil)
	assert.Equal(t, types.AuthenStatusFail, dec.Status)
}

func TestBcryptAuthenticator_PAPFailUnknownUser(t *testing.T) {
	a := NewBcryptAuthenticator(cfgForTest())
	dec, _ := a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "ghost", Type: types.AuthenTypePAP, Data: []byte("x")},
	}, nil)
	// Must NOT surface a distinct "unknown user" status: same as bad password.
	assert.Equal(t, types.AuthenStatusFail, dec.Status)
}

func TestBcryptAuthenticator_ASCIIGetPassThenPass(t *testing.T) {
	a := NewBcryptAuthenticator(cfgForTest())
	dec, _ := a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "operator", Type: types.AuthenTypeASCII},
	}, nil)
	assert.Equal(t, types.AuthenStatusGetPass, dec.Status)

	dec, _ = a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "operator", Type: types.AuthenTypeASCII},
	}, &server.AuthenContinue{UserMsg: "op123"})
	assert.Equal(t, types.AuthenStatusPass, dec.Status)
}

func TestBcryptAuthenticator_AuthTypeMismatch(t *testing.T) {
	a := NewBcryptAuthenticator(cfgForTest())
	// admin is configured "pap"; presenting an ASCII start should be rejected.
	dec, _ := a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypeASCII},
	}, nil)
	assert.Equal(t, types.AuthenStatusFail, dec.Status)
}

func TestBcryptAuthenticator_Reload(t *testing.T) {
	a := NewBcryptAuthenticator(cfgForTest())
	dec, _ := a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("admin123")},
	}, nil)
	assert.Equal(t, types.AuthenStatusPass, dec.Status)

	// Reload with a config that has a different password.
	a.Reload(&server.UserConfig{
		AllowPlaintext: true,
		Users: []server.User{
			{Username: "admin", PasswordHash: "newpw", AuthType: "pap"},
		},
	})
	dec, _ = a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("admin123")},
	}, nil)
	assert.Equal(t, types.AuthenStatusFail, dec.Status, "old password should fail after reload")
	dec, _ = a.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("newpw")},
	}, nil)
	assert.Equal(t, types.AuthenStatusPass, dec.Status, "new password should pass after reload")
}

func TestCommandAuthorizer_PermitByPattern(t *testing.T) {
	rules := []CommandRule{
		{Action: ActionPermit, Pattern: `^show `},
		{Action: ActionDeny, Pattern: `^configure `},
	}
	az, err := NewCommandAuthorizer(rules)
	require.NoError(t, err)

	dec, _ := az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	assert.Equal(t, types.AuthorStatusPassAdd, dec.Status)

	dec, _ = az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "configure terminal"}},
	})
	assert.Equal(t, types.AuthorStatusFail, dec.Status)
}

func TestCommandAuthorizer_FirstMatchWins(t *testing.T) {
	rules := []CommandRule{
		{Action: ActionPermit, Pattern: `^show`},      // matches "show"
		{Action: ActionDeny, Pattern: `^show secret`}, // never reached for "show"
	}
	az, _ := NewCommandAuthorizer(rules)
	dec, _ := az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	assert.Equal(t, types.AuthorStatusPassAdd, dec.Status)
}

func TestCommandAuthorizer_NoMatchDenies(t *testing.T) {
	az, _ := NewCommandAuthorizer([]CommandRule{
		{Action: ActionPermit, Pattern: `^show `},
	})
	dec, _ := az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "reboot"}},
	})
	assert.Equal(t, types.AuthorStatusFail, dec.Status)
}

func TestCommandAuthorizer_PassReplWithSetValues(t *testing.T) {
	az, _ := NewCommandAuthorizer([]CommandRule{
		{
			Action:    ActionPermit,
			Pattern:   `^shell`,
			PassRepl:  true,
			SetValues: []types.Argument{{Name: "priv-lvl", Value: "5"}},
		},
	})
	dec, _ := az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "shell"}},
	})
	assert.Equal(t, types.AuthorStatusPassRepl, dec.Status)
	require.Len(t, dec.Args, 1)
	assert.Equal(t, "priv-lvl", dec.Args[0].Name)
	assert.Equal(t, "5", dec.Args[0].Value)
}

func TestCommandAuthorizer_BadPatternFails(t *testing.T) {
	_, err := NewCommandAuthorizer([]CommandRule{
		{Action: ActionPermit, Pattern: `(unbalanced`},
	})
	require.Error(t, err)
}

func TestCommandAuthorizer_Reload(t *testing.T) {
	az, _ := NewCommandAuthorizer([]CommandRule{
		{Action: ActionPermit, Pattern: `^show`},
	})
	dec, _ := az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	assert.Equal(t, types.AuthorStatusPassAdd, dec.Status)

	require.NoError(t, az.Reload([]CommandRule{
		{Action: ActionDeny, Pattern: `^show`},
	}))
	dec, _ = az.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	assert.Equal(t, types.AuthorStatusFail, dec.Status)
}

func TestFileAccounter_WritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acct.jsonl")
	ac, err := NewFileAccounter(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ac.Close() })

	_, err = ac.Account(context.Background(), server.AcctContext{
		SessionID: 42,
		SeqNo:     1,
		Flags:     types.AcctFlagStart,
		User:      "admin",
		Args: []types.Argument{
			{Name: "cmd", Value: "show version"},
			{Name: "password", Value: "hunter2"}, // must be redacted
		},
	})
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)

	var rec AcctRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	assert.Equal(t, uint32(42), rec.SessionID)
	assert.Equal(t, "start", rec.Record)
	assert.Equal(t, "admin", rec.User)

	// Find the password AVP and verify it was redacted.
	var pwVal string
	for _, a := range rec.Args {
		if a.Name == "password" {
			pwVal = a.Value
		}
	}
	assert.Equal(t, "REDACTED", pwVal)
}

func TestFileAccounter_AppendsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acct.jsonl")
	ac, err := NewFileAccounter(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ac.Close() })

	for i := 0; i < 3; i++ {
		_, _ = ac.Account(context.Background(), server.AcctContext{
			SessionID: uint32(i),
			Flags:     types.AcctFlagStart,
		})
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, 3)
}

func TestFileAccounter_FilePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acct.jsonl")
	ac, err := NewFileAccounter(path)
	require.NoError(t, err)
	_ = ac.Close()

	info, err := os.Stat(path)
	require.NoError(t, err)
	// 0600 on POSIX; only check the low 9 bits.
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCompositeHandler_NilAccounterReturnsSuccess(t *testing.T) {
	h := &CompositeHandler{}
	dec, err := h.Account(context.Background(), server.AcctContext{})
	require.NoError(t, err)
	assert.Equal(t, types.AcctStatusSuccess, dec.Status)
}

func TestCompositeHandler_NilAuthenticatorReturnsError(t *testing.T) {
	h := &CompositeHandler{}
	dec, err := h.Authenticate(context.Background(), server.AuthenContext{}, nil)
	assert.Error(t, err)
	assert.Equal(t, types.AuthenStatusError, dec.Status)
}

func TestCompositeHandler_NilAuthorizerDenies(t *testing.T) {
	h := &CompositeHandler{}
	dec, _ := h.Authorize(context.Background(), server.AuthorContext{})
	assert.Equal(t, types.AuthorStatusFail, dec.Status)
}

func TestCompositeHandler_Delegates(t *testing.T) {
	// Wire a CompositeHandler with real BcryptAuthenticator + CommandAuthorizer
	// to confirm end-to-end delegation.
	h := &CompositeHandler{
		Auth: NewBcryptAuthenticator(cfgForTest()),
		Az: mustNewAuthorizer(t, []CommandRule{
			{Action: ActionPermit, Pattern: `^show `},
		}),
	}
	dec, _ := h.Authenticate(context.Background(), server.AuthenContext{
		Start: server.AuthenStart{User: "admin", Type: types.AuthenTypePAP, Data: []byte("admin123")},
	}, nil)
	assert.Equal(t, types.AuthenStatusPass, dec.Status)

	dec2, _ := h.Authorize(context.Background(), server.AuthorContext{
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	assert.Equal(t, types.AuthorStatusPassAdd, dec2.Status)
}

func mustNewAuthorizer(t *testing.T, rules []CommandRule) *CommandAuthorizer {
	t.Helper()
	az, err := NewCommandAuthorizer(rules)
	require.NoError(t, err)
	return az
}

// Compile-time sanity: confirm a few regexp compiles we expect to handle.
var _ = regexp.MustCompile(`^show `)
var _ = bytes.NewBuffer
