// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is a single configured user account. PasswordHash is a bcrypt hash by
// convention; the leading scheme marker selects the verifier (see
// VerifyPassword). An empty hash denotes a disabled account.
//
// In addition to credentials, a User may reference named Groups and Services
// declared at the UserConfig level; those are expanded into the user's
// resolved rule set by UserConfig.Resolve. User-level Commands are evaluated
// BEFORE group-contributed rules, so a user can override group policy.
type User struct {
	// Username is the account name (case-sensitive).
	Username string `yaml:"username" json:"username"`
	// PasswordHash is the stored password verifier. Bcrypt hashes start with
	// "$2"; an empty value disables the account. A bare plaintext password is
	// accepted only when explicitly allowed (AllowPlaintext) for development.
	PasswordHash string `yaml:"password" json:"password"`
	// AuthType restricts the authentication type this user may use ("ascii",
	// "pap", "chap", "mschap", "mschapv2", or empty for any). When set on a
	// referenced Group, the user inherits it unless overridden here.
	AuthType string `yaml:"auth-type,omitempty" json:"auth-type,omitempty"`
	// Groups is the list of Group.Name entries this user belongs to. The
	// groups' Commands and Services are merged into this user's resolved
	// rule set at Resolve time. Unknown references cause Resolve to fail.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Services is the list of Service.Name entries this user directly
	// references (in addition to any contributed via Groups). Unknown
	// references cause Resolve to fail.
	Services []string `yaml:"services,omitempty" json:"services,omitempty"`
	// Commands is the user-level command authorization rules. They are
	// evaluated before any group-contributed rules, so a user can override
	// group policy. Patterns are Go regexps compiled at Resolve time.
	Commands []CommandRule `yaml:"commands,omitempty" json:"commands,omitempty"`
}

// VerifyPassword reports whether the supplied password matches the stored hash.
// Bcrypt hashes ("$2...") are verified with the bcrypt algorithm. Plaintext
// matches are only accepted when allowPlaintext is true, and never in
// production deployments.
func (u User) VerifyPassword(password, hash string, allowPlaintext bool) bool {
	if hash == "" {
		return false
	}
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	if allowPlaintext {
		return password == hash
	}
	return false
}

// UserStore is a lookup of users by name.
type UserStore interface {
	// Lookup returns the user and whether it exists.
	Lookup(username string) (User, bool)
}

// memoryUserStore is a simple in-memory UserStore.
type memoryUserStore struct {
	users map[string]User
}

// NewMemoryUserStore builds a UserStore from a slice of users.
func NewMemoryUserStore(users []User) UserStore {
	m := make(map[string]User, len(users))
	for _, u := range users {
		m[u.Username] = u
	}
	return &memoryUserStore{users: m}
}

func (s *memoryUserStore) Lookup(username string) (User, bool) {
	u, ok := s.users[username]
	return u, ok
}

// Policy is the authorization policy applied to command authorization requests.
type Policy struct {
	// AllowCommands are command patterns (glob, "*" wildcard) that are
	// permitted. A request is authorized if its cmd matches an allow pattern
	// and no deny pattern.
	AllowCommands []string `yaml:"allow-commands,omitempty" json:"allow-commands,omitempty"`
	// DenyCommands are command patterns that are always rejected.
	DenyCommands []string `yaml:"deny-commands,omitempty" json:"deny-commands,omitempty"`
}

// Allows reports whether the command is permitted by the policy. Deny takes
// precedence over allow. An empty policy (no allow rules) denies everything.
func (p Policy) Allows(cmd string) bool {
	for _, pat := range p.DenyCommands {
		if matchCmd(pat, cmd) {
			return false
		}
	}
	for _, pat := range p.AllowCommands {
		if matchCmd(pat, cmd) {
			return true
		}
	}
	return false
}

// matchCmd matches a command against a glob pattern supporting a trailing "*"
// wildcard (e.g. "show *" matches "show version"). An exact pattern matches
// only itself.
func matchCmd(pattern, cmd string) bool {
	if pattern == cmd {
		return true
	}
	if strings.HasSuffix(pattern, " *") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(cmd, prefix)
	}
	return false
}
