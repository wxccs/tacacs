// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

// UserConfig is the server-side configuration of users and authorization
// policy, loadable from YAML or JSON.
//
// The schema supports two authorization styles, which may coexist:
//
//  1. The legacy flat Policy (AllowCommands/DenyCommands), applied as a
//     top-level fallback when a user has no resolved command rules.
//  2. The structured Group/Service/Command model: groups bundle reusable
//     command rules; services describe AVP-based authorization for non-command
//     requests (e.g. PPP). Users reference groups and services by name;
//     UserConfig.Resolve expands them into a per-user ResolvedUser.
//
// Mixed configs are fine: a user with neither groups nor commands falls
// through to the top-level Policy.Allows check.
type UserConfig struct {
	// Users is the list of configured accounts.
	Users []User `yaml:"users" json:"users"`
	// Groups is the list of reusable group definitions. Users reference
	// groups by name via User.Groups.
	Groups []Group `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Services is the list of named service definitions. Users and groups
	// reference services by name via User.Services / Group.Services.
	Services []Service `yaml:"services,omitempty" json:"services,omitempty"`
	// Policy is the command authorization policy applied when a user has no
	// resolved command rules (the legacy fallback).
	Policy Policy `yaml:"policy,omitempty" json:"policy,omitempty"`
	// AllowPlaintext permits plaintext passwords in the config for development
	// only. It defaults to false; bcrypt hashes are always allowed.
	AllowPlaintext bool `yaml:"allow-plaintext,omitempty" json:"allow-plaintext,omitempty"`
}

// LoadUserConfig reads a user/policy configuration from a YAML or JSON file.
func LoadUserConfig(path string) (*UserConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	return decodeUserConfig(v)
}

// LoadUserConfigFromBytes parses user/policy configuration from raw bytes.
func LoadUserConfigFromBytes(data []byte, format string) (*UserConfig, error) {
	v := viper.New()
	v.SetConfigType(format)
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return decodeUserConfig(v)
}

func decodeUserConfig(v *viper.Viper) (*UserConfig, error) {
	cfg := &UserConfig{}
	if err := v.Unmarshal(cfg, viperDecoderHook); err != nil {
		return nil, errors.NewValidationError("user-config", "failed to decode", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// viperDecoderHook makes mapstructure read the "yaml" struct tag, so the same
// struct tags serve both file formats and decoding.
func viperDecoderHook(dc *mapstructure.DecoderConfig) { dc.TagName = "yaml" }

// Validate checks the user configuration for obvious errors.
func (c *UserConfig) Validate() error {
	seen := make(map[string]bool, len(c.Users))
	for i, u := range c.Users {
		if u.Username == "" {
			return errors.NewValidationError("users", fmt.Sprintf("entry %d missing username", i), errors.ErrInvalidArgument)
		}
		if u.PasswordHash == "" {
			return errors.NewValidationError("users", fmt.Sprintf("user %q has empty password (disabled)", u.Username), errors.ErrInvalidArgument)
		}
		if seen[u.Username] {
			return errors.NewValidationError("users", fmt.Sprintf("duplicate username %q", u.Username), errors.ErrInvalidArgument)
		}
		seen[u.Username] = true
		// Plaintext (non-bcrypt) passwords require explicit opt-in.
		if u.PasswordHash != "" && !strings.HasPrefix(u.PasswordHash, "$2") && !c.AllowPlaintext {
			return errors.NewValidationError("users", fmt.Sprintf("user %q has a plaintext password; set allow-plaintext for development", u.Username), errors.ErrInvalidArgument)
		}
	}
	return nil
}

// ConfigHandler is a Handler driven by a UserConfig: it authenticates users
// against the configured password store and authorizes commands per the
// policy. Authorization prefers the structured Group/Service/Command model
// when present, falling back to the flat Policy when a user has no resolved
// rules.
type ConfigHandler struct {
	store    UserStore
	cfg      *UserConfig
	resolved map[string]ResolvedUser
}

// NewConfigHandler builds a Handler from a loaded UserConfig. It expands
// the structured Group/Service/Command model eagerly: a Resolve failure
// (unknown group/service reference, bad regexp) is returned as an error
// and the Handler is not built. Callers SHOULD surface the error to the
// operator rather than proceeding with a partially-configured handler.
func NewConfigHandler(cfg *UserConfig) (*ConfigHandler, error) {
	if cfg == nil {
		cfg = &UserConfig{}
	}
	resolved, err := cfg.Resolve()
	if err != nil {
		return nil, err
	}
	return &ConfigHandler{
		store:    NewMemoryUserStore(cfg.Users),
		cfg:      cfg,
		resolved: resolved,
	}, nil
}

// Authenticate verifies credentials. For PAP the password is in Start.Data; for
// ASCII it follows an interactive GETPASS/CONTINUE exchange.
func (h *ConfigHandler) Authenticate(ctx context.Context, ac AuthenContext, cont *AuthenContinue) (AuthenDecision, error) {
	user, ok := h.store.Lookup(ac.Start.User)
	if !ok {
		return AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "unknown user"}, nil
	}
	if user.AuthType != "" && !authTypeMatches(user.AuthType, ac.Start.Type) {
		return AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "auth type not allowed for user"}, nil
	}
	if cont == nil {
		if ac.Start.Type == types.AuthenTypePAP {
			if user.VerifyPassword(string(ac.Start.Data), user.PasswordHash, h.cfg.AllowPlaintext) {
				return AuthenDecision{Status: types.AuthenStatusPass}, nil
			}
			return AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
		}
		return AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}
	if user.VerifyPassword(cont.UserMsg, user.PasswordHash, h.cfg.AllowPlaintext) {
		return AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
}

// Authorize applies the command policy to the request. It first consults the
// structured Group/Service/Command rules when present; when a user has no
// resolved command rules it falls back to the flat Policy (Allow/Deny
// command lists). Non-command requests (no "cmd" AVP) are matched against
// the user's resolved Services; a service match returns PassRepl with the
// service's SetValues.
func (h *ConfigHandler) Authorize(ctx context.Context, ac AuthorContext) (AuthorDecision, error) {
	ru, ok := h.resolved[ac.User]
	if !ok {
		// Unknown user: deny. (Authentication would already have rejected
		// this, but Authorize may be called without prior authentication on
		// some deployments.)
		return AuthorDecision{Status: types.AuthorStatusFail}, nil
	}
	cmd := extractCmd(ac.Args)
	if cmd == "" {
		// Non-command request: try service match.
		if dec, matched := matchService(ru.Services, ac.Args); matched {
			return dec, nil
		}
		// No service matched: permit by default to preserve back-compat
		// with prior versions that permitted service-login requests.
		return AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
	}
	// Structured rules take precedence.
	if len(ru.Commands) > 0 {
		if dec, matched := matchCommand(ru.Commands, cmd, ac.Args); matched {
			return dec, nil
		}
		// No structured rule matched: fall through to Policy so an admin
		// can layer structured rules on top of a flat allow-list.
	}
	if h.cfg.Policy.Allows(cmd) {
		return AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
	}
	return AuthorDecision{Status: types.AuthorStatusFail, ServerMsg: "command not authorized"}, nil
}

// Account accepts all accounting records (a real implementation would persist them).
func (h *ConfigHandler) Account(ctx context.Context, ac AcctContext) (AcctDecision, error) {
	return AcctDecision{Status: types.AcctStatusSuccess}, nil
}

// authTypeMatches reports whether the configured type string accepts the
// requested authen_type.
func authTypeMatches(configured string, t types.AuthenType) bool {
	switch strings.ToLower(configured) {
	case "ascii":
		return t == types.AuthenTypeASCII
	case "pap":
		return t == types.AuthenTypePAP
	case "chap":
		return t == types.AuthenTypeCHAP
	case "mschap":
		return t == types.AuthenTypeMSCHAP
	case "mschapv2":
		return t == types.AuthenTypeMSCHAPv2
	case "", "any":
		return true
	default:
		return false
	}
}
