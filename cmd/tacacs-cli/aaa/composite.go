// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"context"
	"fmt"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// Authenticator is the subset of server.Handler concerned with Authenticate.
// BcryptAuthenticator satisfies it; tests may provide fakes.
type Authenticator interface {
	Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error)
}

// Authorizer is the subset of server.Handler concerned with Authorize.
type Authorizer interface {
	Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error)
}

// Accounter is the subset of server.Handler concerned with Account.
type Accounter interface {
	Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error)
}

// CompositeHandler composes an Authenticator, Authorizer and Accounter into a
// single server.Handler. Any field may be nil; a nil Authenticator fails all
// Authenticate calls with AuthenStatusError, a nil Authorizer fails all
// Authorize calls with AuthorStatusFail, and a nil Accounter returns
// AcctStatusSuccess without persisting (the existing staticHandler behavior).
type CompositeHandler struct {
	Auth Authenticator
	Az   Authorizer
	Ac   Accounter
}

// Authenticate delegates to the configured Authenticator. When no
// Authenticator is set, it returns an error reply so the protocol surfaces
// the misconfiguration.
func (h *CompositeHandler) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	if h.Auth == nil {
		return server.AuthenDecision{Status: types.AuthenStatusError, ServerMsg: "no authenticator configured"}, fmt.Errorf("aaa: no authenticator configured")
	}
	return h.Auth.Authenticate(ctx, ac, cont)
}

// Authorize delegates to the configured Authorizer. When no Authorizer is
// set, it denies the request.
func (h *CompositeHandler) Authorize(ctx context.Context, ac server.AuthorContext) (server.AuthorDecision, error) {
	if h.Az == nil {
		return server.AuthorDecision{Status: types.AuthorStatusFail, ServerMsg: "no authorizer configured"}, nil
	}
	return h.Az.Authorize(ctx, ac)
}

// Account delegates to the configured Accounter. When no Accounter is set,
// it returns success without persisting (back-compat with the staticHandler).
func (h *CompositeHandler) Account(ctx context.Context, ac server.AcctContext) (server.AcctDecision, error) {
	if h.Ac == nil {
		return server.AcctDecision{Status: types.AcctStatusSuccess}, nil
	}
	return h.Ac.Account(ctx, ac)
}

// Compile-time assertion that CompositeHandler satisfies server.Handler.
var _ server.Handler = (*CompositeHandler)(nil)
