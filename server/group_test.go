// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/types"
)

func TestUserConfig_Resolve_Empty(t *testing.T) {
	c := &UserConfig{}
	r, err := c.Resolve()
	require.NoError(t, err)
	assert.Empty(t, r)
}

func TestUserConfig_Resolve_NoGroups(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "admin", PasswordHash: "$2a$x"}},
	}
	r, err := c.Resolve()
	require.NoError(t, err)
	require.Contains(t, r, "admin")
	assert.Empty(t, r["admin"].Commands)
	assert.Empty(t, r["admin"].Services)
}

func TestUserConfig_Resolve_GroupMerge(t *testing.T) {
	c := &UserConfig{
		Users: []User{
			{
				Username: "alice",
				Groups:   []string{"operators"},
				Commands: []CommandRule{{Action: ActionPermit, Pattern: "^show version$"}},
			},
		},
		Groups: []Group{
			{
				Name: "operators",
				Commands: []CommandRule{
					{Action: ActionPermit, Pattern: "^show "},
					{Action: ActionDeny, Pattern: "^configure "},
				},
			},
		},
	}
	r, err := c.Resolve()
	require.NoError(t, err)

	// User-level rule should appear BEFORE group rules.
	require.Len(t, r["alice"].Commands, 3)
	assert.Equal(t, "^show version$", r["alice"].Commands[0].Pattern)
	assert.Equal(t, "^show ", r["alice"].Commands[1].Pattern)
	assert.Equal(t, "^configure ", r["alice"].Commands[2].Pattern)
}

func TestUserConfig_Resolve_UnknownGroupFails(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "alice", Groups: []string{"nonexistent"}}},
	}
	_, err := c.Resolve()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown group")
}

func TestUserConfig_Resolve_UnknownServiceFails(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "alice", Services: []string{"nonexistent"}}},
	}
	_, err := c.Resolve()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
}

func TestUserConfig_Resolve_GroupUnknownServiceFails(t *testing.T) {
	c := &UserConfig{
		Groups: []Group{{Name: "ops", Services: []string{"missing"}}},
	}
	_, err := c.Resolve()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
}

func TestUserConfig_Resolve_BadPatternFails(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "alice", Commands: []CommandRule{{Action: ActionPermit, Pattern: "(unclosed"}}}},
	}
	_, err := c.Resolve()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compile pattern")
}

func TestUserConfig_Resolve_DuplicateGroupNameFails(t *testing.T) {
	c := &UserConfig{
		Groups: []Group{{Name: "ops"}, {Name: "ops"}},
	}
	_, err := c.Resolve()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate group")
}

func TestUserConfig_Resolve_AuthTypeInheritance(t *testing.T) {
	c := &UserConfig{
		Users:  []User{{Username: "alice", Groups: []string{"ops"}}},
		Groups: []Group{{Name: "ops", AuthType: "pap"}},
	}
	r, err := c.Resolve()
	require.NoError(t, err)
	assert.Equal(t, "pap", r["alice"].User.AuthType, "user should inherit group AuthType when unset")
}

func TestUserConfig_Resolve_AuthTypeUserOverridesGroup(t *testing.T) {
	c := &UserConfig{
		Users:  []User{{Username: "alice", AuthType: "ascii", Groups: []string{"ops"}}},
		Groups: []Group{{Name: "ops", AuthType: "pap"}},
	}
	r, err := c.Resolve()
	require.NoError(t, err)
	assert.Equal(t, "ascii", r["alice"].User.AuthType, "user-level AuthType wins over group")
}

func TestUserConfig_Resolve_ServiceMerge(t *testing.T) {
	c := &UserConfig{
		Users:  []User{{Username: "alice", Groups: []string{"ops"}, Services: []string{"direct"}}},
		Groups: []Group{{Name: "ops", Services: []string{"group-only"}}},
		Services: []Service{
			{Name: "group-only", SetValues: []types.Argument{{Name: "x", Value: "1"}}},
			{Name: "direct", SetValues: []types.Argument{{Name: "y", Value: "2"}}},
		},
	}
	r, err := c.Resolve()
	require.NoError(t, err)
	require.Len(t, r["alice"].Services, 2)
	// User-direct services come before group-contributed ones.
	assert.Equal(t, "direct", r["alice"].Services[0].Name)
	assert.Equal(t, "group-only", r["alice"].Services[1].Name)
}

func TestConfigHandler_Authorize_StructuredRulesWin(t *testing.T) {
	c := &UserConfig{
		Users: []User{
			{
				Username: "admin",
				Commands: []CommandRule{{Action: ActionDeny, Pattern: "^show secret$"}},
			},
		},
		// Legacy policy would allow "show secret", but the structured rule
		// should take precedence.
		Policy: Policy{AllowCommands: []string{"show *"}},
	}
	h, err := NewConfigHandler(c)
	require.NoError(t, err)

	dec, err := h.Authorize(context.Background(), AuthorContext{
		User: "admin",
		Args: []types.Argument{{Name: "cmd", Value: "show secret"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusFail, dec.Status, "structured deny must win over policy allow")

	dec, err = h.Authorize(context.Background(), AuthorContext{
		User: "admin",
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassAdd, dec.Status, "policy fallback should apply when no structured rule matches")
}

func TestConfigHandler_Authorize_ServiceMatch(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "alice", Services: []string{"ppp-default"}}},
		Services: []Service{
			{
				Name:      "ppp-default",
				Match:     []types.Argument{{Name: "service", Value: "ppp"}},
				SetValues: []types.Argument{{Name: "addr", Value: "10.0.0.1"}},
			},
		},
	}
	h, err := NewConfigHandler(c)
	require.NoError(t, err)

	dec, err := h.Authorize(context.Background(), AuthorContext{
		User: "alice",
		Args: []types.Argument{{Name: "service", Value: "ppp"}},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AuthorStatusPassRepl, dec.Status)
	require.Len(t, dec.Args, 1)
	assert.Equal(t, "addr", dec.Args[0].Name)
	assert.Equal(t, "10.0.0.1", dec.Args[0].Value)
}

func TestConfigHandler_Authorize_GroupInheritedRules(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "alice", Groups: []string{"ops"}}},
		Groups: []Group{
			{
				Name: "ops",
				Commands: []CommandRule{
					{Action: ActionPermit, Pattern: "^show "},
					{Action: ActionDeny, Pattern: "^configure "},
				},
			},
		},
	}
	h, err := NewConfigHandler(c)
	require.NoError(t, err)

	dec, _ := h.Authorize(context.Background(), AuthorContext{
		User: "alice",
		Args: []types.Argument{{Name: "cmd", Value: "show version"}},
	})
	assert.Equal(t, types.AuthorStatusPassAdd, dec.Status)

	dec, _ = h.Authorize(context.Background(), AuthorContext{
		User: "alice",
		Args: []types.Argument{{Name: "cmd", Value: "configure terminal"}},
	})
	assert.Equal(t, types.AuthorStatusFail, dec.Status)

	dec, _ = h.Authorize(context.Background(), AuthorContext{
		User: "alice",
		Args: []types.Argument{{Name: "cmd", Value: "reboot"}},
	})
	assert.Equal(t, types.AuthorStatusFail, dec.Status, "no match and no policy → fail")
}

func TestConfigHandler_NewReturnsErrorOnBadConfig(t *testing.T) {
	c := &UserConfig{
		Users: []User{{Username: "alice", Groups: []string{"nonexistent"}}},
	}
	_, err := NewConfigHandler(c)
	require.Error(t, err)
}

func TestNewConfigHandler_NilSafe(t *testing.T) {
	// A nil config must not panic; it yields an empty handler.
	h, err := NewConfigHandler(nil)
	require.NoError(t, err)
	require.NotNil(t, h)
}

func TestCommandRule_Compile_EmptyPattern(t *testing.T) {
	r := CommandRule{Action: ActionPermit}
	require.NoError(t, r.Compile())
	assert.Nil(t, r.re)
}

func TestCommandRule_Matches_AVPFilter(t *testing.T) {
	r := CommandRule{
		Action:  ActionPermit,
		Pattern: "^show ",
		Match:   []types.Argument{{Name: "service", Value: "shell"}},
	}
	require.NoError(t, r.Compile())

	// cmd matches but AVP missing → no match.
	assert.False(t, r.Matches("show version", []types.Argument{{Name: "cmd", Value: "show version"}}))
	// cmd matches and AVP present → match.
	assert.True(t, r.Matches("show version", []types.Argument{
		{Name: "cmd", Value: "show version"},
		{Name: "service", Value: "shell"},
	}))
}
