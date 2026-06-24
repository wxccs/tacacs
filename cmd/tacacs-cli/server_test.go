// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wxccs/tacacs/cmd/tacacs-cli/aaa"
	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

func TestGlobToRegex_Exact(t *testing.T) {
	re := globToRegex("exit")
	assert.Equal(t, `^exit$`, re)
}

func TestGlobToRegex_Wildcard(t *testing.T) {
	re := globToRegex("show *")
	assert.Equal(t, `^show .*$`, re)
}

func TestGlobToRegex_MetacharsQuoted(t *testing.T) {
	// A user-supplied pattern with regex metacharacters must be quoted
	// so it cannot inject regex operators.
	re := globToRegex("foo.bar+baz")
	assert.Equal(t, `^foo\.bar\+baz$`, re)
}

// policyToRules is a test-only helper that translates a flat server.Policy
// into the aaa.CommandRule slice. It is the Policy-only subset of
// userConfigToRules, kept here to exercise the glob→regex translation in
// isolation.
func policyToRules(p server.Policy) []aaa.CommandRule {
	rules := make([]aaa.CommandRule, 0, len(p.DenyCommands)+len(p.AllowCommands))
	for _, pat := range p.DenyCommands {
		rules = append(rules, aaa.CommandRule{
			Action:  aaa.ActionDeny,
			Pattern: globToRegex(pat),
		})
	}
	for _, pat := range p.AllowCommands {
		rules = append(rules, aaa.CommandRule{
			Action:  aaa.ActionPermit,
			Pattern: globToRegex(pat),
		})
	}
	return rules
}

func TestPolicyToRules_DenyFirst(t *testing.T) {
	rules := policyToRules(server.Policy{
		AllowCommands: []string{"show *"},
		DenyCommands:  []string{"show secret"},
	})
	// Deny rules must be emitted before allow rules so they win on overlap.
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 rules, got %d", len(rules))
	}
	assert.Equal(t, aaa.ActionDeny, rules[0].Action, "first rule must be deny")
	assert.Equal(t, aaa.ActionPermit, rules[1].Action, "second rule must be permit")
}

func TestPolicyToRules_RoundTrip(t *testing.T) {
	// Verify the translated rules behave the same as server.Policy.Allows.
	policy := server.Policy{
		AllowCommands: []string{"show *", "exit"},
		DenyCommands:  []string{"show secret", "configure *"},
	}
	rules := policyToRules(policy)
	az, err := aaa.NewCommandAuthorizer(rules)
	require.NoError(t, err)

	cases := []struct {
		cmd  string
		want bool
	}{
		{"show version", true},
		{"show secret", false}, // deny wins
		{"exit", true},
		{"configure terminal", false},
		{"reboot", false}, // no match
	}
	for _, c := range cases {
		// The policy.Allows check is the oracle.
		gotPolicy := policy.Allows(c.cmd)
		assert.Equalf(t, c.want, gotPolicy, "policy.Allows(%q)", c.cmd)

		// And run the same command through the authorizer.
		dec, _ := az.Authorize(context.Background(), server.AuthorContext{
			Args: []types.Argument{{Name: "cmd", Value: c.cmd}},
		})
		if c.want {
			assert.Equalf(t, types.AuthorStatusPassAdd, dec.Status, "authorizer.Authorize(%q)", c.cmd)
		} else {
			assert.Equalf(t, types.AuthorStatusFail, dec.Status, "authorizer.Authorize(%q)", c.cmd)
		}
	}
}

func TestUserConfigToRules_FlattensGroupRules(t *testing.T) {
	uc := &server.UserConfig{
		Users: []server.User{
			{Username: "alice", Groups: []string{"ops"}},
		},
		Groups: []server.Group{
			{
				Name: "ops",
				Commands: []server.CommandRule{
					{Action: server.ActionPermit, Pattern: "^show "},
				},
			},
		},
	}
	rules, err := userConfigToRules(uc)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "^show ", rules[0].Pattern)
}

func TestUserConfigToRules_BadConfigFails(t *testing.T) {
	uc := &server.UserConfig{
		Users: []server.User{{Username: "alice", Groups: []string{"nonexistent"}}},
	}
	_, err := userConfigToRules(uc)
	require.Error(t, err)
}
