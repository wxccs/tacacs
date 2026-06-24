// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

//go:build !linux || !cgo

package aaa

import (
	"context"
	"fmt"

	"github.com/wxccs/tacacs/server"
)

// PAMAuthenticator is unavailable on this platform. The functional
// implementation requires Linux with cgo (see pam_authenticator_linux.go).
type PAMAuthenticator struct{}

// PAMConfig configures a PAMAuthenticator.
type PAMConfig struct {
	// Service is the PAM service name (used only by the Linux/cgo build).
	Service string
}

// NewPAMAuthenticator returns an error: PAM is only supported on Linux with
// cgo enabled.
func NewPAMAuthenticator(PAMConfig) (*PAMAuthenticator, error) {
	return nil, fmt.Errorf("aaa: PAM authenticator requires linux with cgo enabled")
}

// Authenticate is never reachable: the constructor fails on this platform. It
// exists so the type satisfies the Authenticator interface for compilation.
func (a *PAMAuthenticator) Authenticate(_ context.Context, _ server.AuthenContext, _ *server.AuthenContinue) (server.AuthenDecision, error) {
	return server.AuthenDecision{}, fmt.Errorf("aaa: PAM authenticator unavailable on this platform")
}

var _ Authenticator = (*PAMAuthenticator)(nil)
