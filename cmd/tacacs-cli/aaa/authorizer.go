// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package aaa

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// CommandRule aliases server.CommandRule so the aaa package shares the
// canonical rule type with the library core. This avoids two parallel
// definitions and lets configs loaded via server.UserConfig.Resolve flow
// directly into a CommandAuthorizer without conversion.
type CommandRule = server.CommandRule

// CommandAction aliases server.CommandAction.
type CommandAction = server.CommandAction

// Action aliases the server package action constants, so existing aaa
// callers using aaa.ActionPermit / aaa.ActionDeny continue to compile.
const (
	ActionPermit = server.ActionPermit
	ActionDeny   = server.ActionDeny
)

// CommandAuthorizer applies an ordered list of CommandRules to authorization
// requests. The first matching rule wins; if no rule matches the request is
// denied. Rules can be reloaded at runtime via Reload.
type CommandAuthorizer struct {
	mu    sync.RWMutex
	rules []CommandRule
}

// NewCommandAuthorizer builds a CommandAuthorizer from the given rules. Each
// rule's Pattern is compiled; a compilation error aborts the build.
func NewCommandAuthorizer(rules []CommandRule) (*CommandAuthorizer, error) {
	for i := range rules {
		if err := rules[i].Compile(); err != nil {
			return nil, fmt.Errorf("compile rule %d pattern %q: %w", i, rules[i].Pattern, err)
		}
	}
	return &CommandAuthorizer{rules: rules}, nil
}

// Reload atomically replaces the rule set. Rules are compiled before the
// pointer is swapped, so a compilation failure leaves the existing rules in
// place and returns the error.
func (a *CommandAuthorizer) Reload(rules []CommandRule) error {
	for i := range rules {
		if err := rules[i].Compile(); err != nil {
			return fmt.Errorf("compile rule %d pattern %q: %w", i, rules[i].Pattern, err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = rules
	return nil
}

// Authorize applies the rule list to the request. A request with no "cmd" AVP
// is treated as a service-level (non-command) authorization and permitted
// when at least one rule exists with an empty Pattern and a matching AVP set;
// otherwise it is denied.
func (a *CommandAuthorizer) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
	a.mu.RLock()
	rules := a.rules
	a.mu.RUnlock()

	cmd := ""
	for _, arg := range ac.Args {
		if strings.EqualFold(arg.Name, "cmd") {
			cmd = arg.Value
			break
		}
	}
	for i := range rules {
		r := &rules[i]
		if !r.Matches(cmd, ac.Args) {
			continue
		}
		if r.Action == ActionDeny {
			return server.AuthorDecision{Status: types.AuthorStatusFail, ServerMsg: "command denied by policy"}, nil
		}
		status := types.AuthorStatusPassAdd
		if r.PassRepl {
			status = types.AuthorStatusPassRepl
		}
		return server.AuthorDecision{Status: status, Args: append([]types.Argument(nil), r.SetValues...)}, nil
	}
	return server.AuthorDecision{Status: types.AuthorStatusFail, ServerMsg: "no matching rule"}, nil
}
