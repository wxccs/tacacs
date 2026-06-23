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
type UserConfig struct {
	// Users is the list of configured accounts.
	Users []User `yaml:"users" json:"users"`
	// Policy is the command authorization policy.
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
// against the configured password store and authorizes commands per the policy.
type ConfigHandler struct {
	store UserStore
	cfg   *UserConfig
}

// NewConfigHandler builds a Handler from a loaded UserConfig.
func NewConfigHandler(cfg *UserConfig) *ConfigHandler {
	return &ConfigHandler{store: NewMemoryUserStore(cfg.Users), cfg: cfg}
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

// Authorize applies the command policy to the request.
func (h *ConfigHandler) Authorize(ctx context.Context, ac AuthorContext) (AuthorDecision, error) {
	if _, ok := h.store.Lookup(ac.User); !ok {
		return AuthorDecision{Status: types.AuthorStatusFail}, nil
	}
	cmd := ""
	for _, a := range ac.Args {
		if a.Name == "cmd" {
			cmd = a.Value
		}
	}
	if cmd == "" {
		// No command to authorize (e.g. a service login): permit.
		return AuthorDecision{Status: types.AuthorStatusPassAdd}, nil
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
