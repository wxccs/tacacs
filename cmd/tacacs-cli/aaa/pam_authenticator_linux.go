// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

//go:build linux && cgo

package aaa

import (
	"context"
	"fmt"

	pam "github.com/msteinert/pam/v2"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// PAMAuthenticator verifies credentials against the host's PAM stack. It is the
// right backend when the device should authenticate against local system
// accounts or any module already wired into PAM (pam_unix, pam_ldap,
// pam_google_authenticator, ...).
//
// Build constraints: this implementation requires Linux and cgo. On other
// platforms (or when cgo is disabled) the stub in pam_authenticator_stub.go is
// compiled instead, and NewPAMAuthenticator returns an error.
//
// Security:
//   - PAM runs the configured module stack with the privileges of the server
//     process. Use a DEDICATED PAM service file (e.g. /etc/pam.d/tacacs) scoped
//     to exactly the modules you intend, rather than reusing "login" or "sshd".
//   - Only PAP and the interactive ASCII flow are supported, since PAM needs a
//     cleartext password to feed the conversation. CHAP/MS-CHAP cannot work.
type PAMAuthenticator struct {
	service string
}

// PAMConfig configures a PAMAuthenticator.
type PAMConfig struct {
	// Service is the PAM service name, i.e. the file under /etc/pam.d. Defaults
	// to "tacacs". Operators should create a dedicated, minimal service file.
	Service string
}

// NewPAMAuthenticator returns a PAMAuthenticator for the given service.
func NewPAMAuthenticator(cfg PAMConfig) (*PAMAuthenticator, error) {
	service := cfg.Service
	if service == "" {
		service = "tacacs"
	}
	return &PAMAuthenticator{service: service}, nil
}

// Authenticate implements the Authenticator interface.
func (a *PAMAuthenticator) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	var password string
	switch {
	case cont != nil:
		password = cont.UserMsg
	case ac.Start.Type == types.AuthenTypePAP:
		password = string(ac.Start.Data)
	default:
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}

	ok, err := a.verify(ctx, ac.Start.User, password)
	if err != nil {
		return server.AuthenDecision{Status: types.AuthenStatusError, ServerMsg: "authentication backend error"}, err
	}
	if ok {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
}

func (a *PAMAuthenticator) verify(ctx context.Context, user, password string) (bool, error) {
	// An empty password would be answered to every prompt; reject it up front.
	if password == "" {
		return false, nil
	}

	tx, err := pam.StartFunc(a.service, user, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return password, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", fmt.Errorf("aaa: pam: unhandled conversation style %v", s)
		}
	})
	if err != nil {
		return false, fmt.Errorf("aaa: pam start: %w", err)
	}
	defer func() { _ = tx.End() }()

	// Authenticate then validate the account (expiry, access rules). PAM
	// auth failure is a clean credential rejection, not a backend error.
	if err := tx.Authenticate(0); err != nil {
		return false, nil
	}
	if err := tx.AcctMgmt(0); err != nil {
		return false, nil
	}
	return true, nil
}

// Compile-time assertion that PAMAuthenticator satisfies Authenticator.
var _ Authenticator = (*PAMAuthenticator)(nil)
