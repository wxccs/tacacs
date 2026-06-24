// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"context"
	"strings"
	"sync"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// BcryptAuthenticator verifies user credentials against a UserConfig-backed
// UserStore. Password hashes are verified with bcrypt (or plaintext when the
// config explicitly opts in via allow-plaintext). The store can be swapped at
// runtime via Reload, enabling hot-reload of the user database without
// restarting the server.
type BcryptAuthenticator struct {
	mu         sync.RWMutex
	store      server.UserStore
	allowPlain bool
}

// NewBcryptAuthenticator builds a BcryptAuthenticator from the given
// UserConfig. The returned authenticator is safe for concurrent use.
func NewBcryptAuthenticator(cfg *server.UserConfig) *BcryptAuthenticator {
	if cfg == nil {
		cfg = &server.UserConfig{}
	}
	return &BcryptAuthenticator{
		store:      server.NewMemoryUserStore(cfg.Users),
		allowPlain: cfg.AllowPlaintext,
	}
}

// Reload atomically replaces the user store and plaintext policy. It is safe
// to call concurrently with Authenticate; in-flight Authenticate calls
// continue against the previous store snapshot.
func (a *BcryptAuthenticator) Reload(cfg *server.UserConfig) {
	if cfg == nil {
		cfg = &server.UserConfig{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.store = server.NewMemoryUserStore(cfg.Users)
	a.allowPlain = cfg.AllowPlaintext
}

// Authenticate verifies credentials presented in a START (and, for interactive
// flows, the subsequent CONTINUE). Unknown users, auth-type mismatches and bad
// passwords all return AuthenStatusFail; the server NEVER distinguishes
// "unknown user" from "bad password" in the protocol-level status to avoid
// user-enumeration side channels (the ServerMsg is descriptive but optional).
func (a *BcryptAuthenticator) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	a.mu.RLock()
	store := a.store
	allowPlain := a.allowPlain
	a.mu.RUnlock()

	user, ok := store.Lookup(ac.Start.User)
	if !ok {
		return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
	}
	if user.AuthType != "" && !authTypeMatches(user.AuthType, ac.Start.Type) {
		return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "auth type not allowed for user"}, nil
	}
	if cont == nil {
		if ac.Start.Type == types.AuthenTypePAP {
			if user.VerifyPassword(string(ac.Start.Data), user.PasswordHash, allowPlain) {
				return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
			}
			return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
		}
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}
	if user.VerifyPassword(cont.UserMsg, user.PasswordHash, allowPlain) {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
}

// authTypeMatches reports whether the configured type string accepts the
// requested authen_type. It mirrors server.authTypeMatches (unexported in the
// server package); kept here so the aaa package is self-contained.
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
