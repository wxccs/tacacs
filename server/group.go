// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

// CommandAction is the verdict a CommandRule emits when its pattern matches.
// It is a string so YAML/JSON configs can use the bare token "permit" or
// "deny" without quoting.
type CommandAction string

const (
	// ActionPermit authorizes the command (subject to AVP matchers).
	ActionPermit CommandAction = "permit"
	// ActionDeny rejects the command.
	ActionDeny CommandAction = "deny"
)

// CommandRule is a single authorization rule. A request matches the rule when:
//   - Pattern (Go regexp anchored at the start by default; use ^ $ explicitly
//     for stricter matching) matches the "cmd" AVP value, or Pattern is empty
//     (matches any command), AND
//   - every AVP in Match is present in the request with an equal value.
//
// On a match the rule's Action is the verdict. PassRepl, when true, causes a
// matching permit to emit AuthorStatusPassRepl rather than PassAdd; the
// Authorizer then sets Args to the rule's SetValues.
//
// CommandRule is the canonical rule type for both the ConfigHandler
// (server package) and the CLI's CommandAuthorizer (aaa package, via a
// type alias).
type CommandRule struct {
	// Action is "permit" or "deny". An empty action is treated as "deny".
	Action CommandAction `yaml:"action" json:"action"`
	// Pattern is a Go regexp that must match the "cmd" AVP value. An empty
	// pattern matches any command (so the rule reduces to an AVP-only check).
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	// Match is the list of AVPs that must all be present in the request
	// (with equal values) for the rule to match.
	Match []types.Argument `yaml:"match,omitempty" json:"match,omitempty"`
	// SetValues is the list of AVPs to return in the authorization reply
	// when the rule matches and Action is permit. Ignored for deny rules.
	SetValues []types.Argument `yaml:"set-values,omitempty" json:"set-values,omitempty"`
	// PassRepl, when true on a permit rule, emits AuthorStatusPassRepl
	// rather than PassAdd. Use this when the rule replaces the request's
	// AVP set rather than augmenting it.
	PassRepl bool `yaml:"pass-repl,omitempty" json:"pass-repl,omitempty"`

	// re is the compiled form of Pattern; nil when Pattern is empty.
	// Populated by Compile, which NewConfigHandler and Resolve call.
	re *regexp.Regexp
}

// Compile compiles Pattern into a regexp. It MUST be called before the rule
// is used. An empty Pattern is a no-op (matches any command).
func (r *CommandRule) Compile() error {
	if r.Pattern == "" {
		return nil
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("compile pattern %q: %w", r.Pattern, err)
	}
	r.re = re
	return nil
}

// Matches reports whether the rule matches the request. cmd is the value of
// the "cmd" AVP (or empty when absent); args is the full inbound AVP list.
// It is exported so external packages consuming CommandRule (e.g. the CLI's
// aaa.CommandAuthorizer) can reuse the matching logic without re-implementing
// the AVP filter.
func (r *CommandRule) Matches(cmd string, args []types.Argument) bool {
	if r.re != nil && !r.re.MatchString(cmd) {
		return false
	}
	for _, m := range r.Match {
		if !argPresentAVP(args, m) {
			return false
		}
	}
	return true
}

// argPresentAVP reports whether args contains the given AVP with a matching
// value. The Mandatory flag on the match AVP is not consulted: the rule
// explicitly listed the AVP, so the request must carry it regardless of
// separator.
func argPresentAVP(args []types.Argument, want types.Argument) bool {
	for _, a := range args {
		if a.Name == want.Name && a.Value == want.Value {
			return true
		}
	}
	return false
}

// Group is a reusable bundle of command rules and service references. Users
// reference a group by name via User.Groups; the group's Commands and
// Services are merged into the user's resolved rule set at config load time.
//
// Groups do NOT reference other groups: cross-group inheritance would
// require cycle detection, and the existing schema has no need for it.
type Group struct {
	// Name is the group identifier referenced by User.Groups.
	Name string `yaml:"name" json:"name"`
	// Commands is the ordered list of command rules contributed by this
	// group. User-level rules are matched first; group rules fill in the
	// remaining cases.
	Commands []CommandRule `yaml:"commands,omitempty" json:"commands,omitempty"`
	// Services is the list of named services this group contributes.
	// Each entry must match a Service.Name in the same UserConfig.
	Services []string `yaml:"services,omitempty" json:"services,omitempty"`
	// AuthType, when set, restricts the authentication type for users in
	// this group. A user-level AuthType takes precedence over the group's.
	AuthType string `yaml:"auth-type,omitempty" json:"auth-type,omitempty"`
}

// Service is a named AVP-based authorization unit (RFC 8907 §5.2). A
// request matches a service when every AVP in Match is present with an equal
// value; on a match the SetValues AVPs are returned in the authorization
// reply (via AuthorStatusPassRepl).
//
// Services are typically used for non-command authorization (e.g. PPP
// sessions): the inbound REQUEST carries service=ppp and the AVP set in
// Match, and the server replies with the AVPs in SetValues.
type Service struct {
	// Name is the service identifier referenced by User.Services or
	// Group.Services.
	Name string `yaml:"name" json:"name"`
	// Match is the AVP set that must all be present in the request for
	// the service to match.
	Match []types.Argument `yaml:"match,omitempty" json:"match,omitempty"`
	// SetValues is the AVP set returned in the authorization reply when
	// the service matches.
	SetValues []types.Argument `yaml:"set-values,omitempty" json:"set-values,omitempty"`
}

// ResolvedUser is the fully expanded form of a User: the original User
// record plus the merged Commands and Services from the user's own
// declarations and all referenced groups. It is the read-only snapshot
// consumed by Authorize at runtime.
type ResolvedUser struct {
	User     User
	Commands []CommandRule
	Services []Service
}

// Resolve expands all users in the config, merging group-contributed rules
// and services into each user's resolved form. The result is a map keyed
// by username suitable for direct lookup at request time.
//
// Resolve performs the following validations:
//   - Every User.Groups entry references an existing Group.Name.
//   - Every User.Services and Group.Services entry references an existing
//     Service.Name.
//   - Every CommandRule.Pattern compiles as a Go regexp.
//
// On any validation failure Resolve returns a wrapped error and a nil map.
// Callers SHOULD treat the config as unusable on error and surface the
// message to the operator.
func (c *UserConfig) Resolve() (map[string]ResolvedUser, error) {
	if c == nil {
		return map[string]ResolvedUser{}, nil
	}

	// Index groups and services for O(1) lookup.
	groups := make(map[string]Group, len(c.Groups))
	for i, g := range c.Groups {
		if g.Name == "" {
			return nil, errors.NewValidationError("groups", fmt.Sprintf("entry %d missing name", i), errors.ErrInvalidArgument)
		}
		if _, dup := groups[g.Name]; dup {
			return nil, errors.NewValidationError("groups", fmt.Sprintf("duplicate group name %q", g.Name), errors.ErrInvalidArgument)
		}
		// Compile group rules in place.
		for j := range g.Commands {
			if err := g.Commands[j].Compile(); err != nil {
				return nil, errors.NewValidationError("groups", fmt.Sprintf("group %q rule %d: %s", g.Name, j, err), errors.ErrInvalidArgument)
			}
		}
		groups[g.Name] = g
	}
	services := make(map[string]Service, len(c.Services))
	for i, s := range c.Services {
		if s.Name == "" {
			return nil, errors.NewValidationError("services", fmt.Sprintf("entry %d missing name", i), errors.ErrInvalidArgument)
		}
		if _, dup := services[s.Name]; dup {
			return nil, errors.NewValidationError("services", fmt.Sprintf("duplicate service name %q", s.Name), errors.ErrInvalidArgument)
		}
		services[s.Name] = s
	}

	// Validate group service references against the service index.
	for _, g := range c.Groups {
		for _, ref := range g.Services {
			if _, ok := services[ref]; !ok {
				return nil, errors.NewValidationError("groups", fmt.Sprintf("group %q references unknown service %q", g.Name, ref), errors.ErrInvalidArgument)
			}
		}
	}

	resolved := make(map[string]ResolvedUser, len(c.Users))
	for _, u := range c.Users {
		ru, err := resolveUser(u, groups, services)
		if err != nil {
			return nil, err
		}
		resolved[u.Username] = ru
	}
	return resolved, nil
}

// resolveUser merges a user's own rules with the rules contributed by each
// referenced group. User-level rules are placed BEFORE group rules so the
// user can override group policy. Group rules are appended in the order the
// groups are listed in User.Groups; within a group, the group's own order is
// preserved.
func resolveUser(u User, groups map[string]Group, services map[string]Service) (ResolvedUser, error) {
	// Compile user-level rules.
	for i := range u.Commands {
		if err := u.Commands[i].Compile(); err != nil {
			return ResolvedUser{}, errors.NewValidationError("users", fmt.Sprintf("user %q rule %d: %s", u.Username, i, err), errors.ErrInvalidArgument)
		}
	}

	// Validate direct service references.
	for _, ref := range u.Services {
		if _, ok := services[ref]; !ok {
			return ResolvedUser{}, errors.NewValidationError("users", fmt.Sprintf("user %q references unknown service %q", u.Username, ref), errors.ErrInvalidArgument)
		}
	}

	ru := ResolvedUser{User: u, Commands: append([]CommandRule(nil), u.Commands...), Services: append([]Service(nil), userServices(u, services)...)}

	// Merge each referenced group.
	for _, ref := range u.Groups {
		g, ok := groups[ref]
		if !ok {
			return ResolvedUser{}, errors.NewValidationError("users", fmt.Sprintf("user %q references unknown group %q", u.Username, ref), errors.ErrInvalidArgument)
		}
		ru.Commands = append(ru.Commands, g.Commands...)
		for _, sref := range g.Services {
			ru.Services = append(ru.Services, services[sref])
		}
		// Inherit AuthType when the user has none.
		if ru.User.AuthType == "" && g.AuthType != "" {
			ru.User.AuthType = g.AuthType
		}
	}
	return ru, nil
}

// userServices expands the user's Services references into the named Service
// records. Unknown references are rejected upstream (Resolve validates them
// before reaching here, but this helper is also called by Resolve which
// already checks).
func userServices(u User, services map[string]Service) []Service {
	out := make([]Service, 0, len(u.Services))
	for _, ref := range u.Services {
		if s, ok := services[ref]; ok {
			out = append(out, s)
		}
	}
	return out
}

// matchCommand applies the resolved command rules to a request. It is the
// shared evaluation logic used by ConfigHandler.Authorize. The first
// matching rule wins; a deny rule rejects, a permit rule returns PassAdd (or
// PassRepl when the rule sets it). When no rule matches the caller decides
// the default (typically fail).
func matchCommand(rules []CommandRule, cmd string, args []types.Argument) (AuthorDecision, bool) {
	for i := range rules {
		r := &rules[i]
		if !r.Matches(cmd, args) {
			continue
		}
		if r.Action == ActionDeny {
			return AuthorDecision{Status: types.AuthorStatusFail, ServerMsg: "command denied by policy"}, true
		}
		status := types.AuthorStatusPassAdd
		if r.PassRepl {
			status = types.AuthorStatusPassRepl
		}
		return AuthorDecision{Status: status, Args: append([]types.Argument(nil), r.SetValues...)}, true
	}
	return AuthorDecision{}, false
}

// matchService applies the resolved services to a request. The first service
// whose Match AVP set is fully present wins; it returns PassRepl with the
// service's SetValues. Used for non-command authorization (e.g. PPP).
func matchService(services []Service, args []types.Argument) (AuthorDecision, bool) {
	for _, s := range services {
		if !serviceMatches(s, args) {
			continue
		}
		return AuthorDecision{
			Status: types.AuthorStatusPassRepl,
			Args:   append([]types.Argument(nil), s.SetValues...),
		}, true
	}
	return AuthorDecision{}, false
}

// serviceMatches reports whether every AVP in s.Match is present in args
// with an equal value. An empty Match matches any request.
func serviceMatches(s Service, args []types.Argument) bool {
	for _, m := range s.Match {
		if !argPresentAVP(args, m) {
			return false
		}
	}
	return true
}

// extractCmd returns the value of the first AVP whose name is "cmd"
// (case-insensitive), or the empty string when absent.
func extractCmd(args []types.Argument) string {
	for _, a := range args {
		if strings.EqualFold(a.Name, "cmd") {
			return a.Value
		}
	}
	return ""
}
