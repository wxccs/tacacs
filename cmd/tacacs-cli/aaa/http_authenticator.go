// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// HTTPAuthenticator delegates credential verification to an external HTTP
// endpoint. It is the universal escape hatch: an operator can front any
// identity system (LDAP, OAuth, a bespoke directory) behind a small HTTP
// service and have the TACACS+ server consult it.
//
// The endpoint receives a JSON POST of the form
//
//	{"username":"alice","password":"...","authen_type":"pap"}
//
// and must reply 200 with {"authenticated":true|false}. Any non-2xx status, a
// transport error, or a malformed body is treated as an error (not a silent
// fail) so misconfiguration surfaces rather than locking everyone out quietly.
//
// Security: the endpoint URL MUST be https unless AllowInsecure is set (for a
// localhost sidecar). The password is sent only in the request body, never in
// the URL or logs.
type HTTPAuthenticator struct {
	endpoint string
	client   *http.Client
}

// HTTPConfig configures an HTTPAuthenticator.
type HTTPConfig struct {
	// Endpoint is the verification URL. Must be https unless AllowInsecure.
	Endpoint string
	// Timeout bounds each verification request. Defaults to 5s if zero.
	Timeout time.Duration
	// AllowInsecure permits a plain-http endpoint (intended for a trusted
	// localhost sidecar only). Defaults to false.
	AllowInsecure bool
	// Client, if non-nil, overrides the default HTTP client (e.g. to inject a
	// custom TLS config or transport in tests).
	Client *http.Client
}

// NewHTTPAuthenticator validates the config and returns an HTTPAuthenticator.
func NewHTTPAuthenticator(cfg HTTPConfig) (*HTTPAuthenticator, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("aaa: parse http endpoint: %w", err)
	}
	if u.Scheme != "https" && (!cfg.AllowInsecure || u.Scheme != "http") {
		return nil, fmt.Errorf("aaa: http authenticator endpoint must be https (set AllowInsecure for a localhost http sidecar)")
	}
	client := cfg.Client
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &HTTPAuthenticator{endpoint: cfg.Endpoint, client: client}, nil
}

type httpAuthRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthenType string `json:"authen_type"`
}

type httpAuthResponse struct {
	Authenticated bool `json:"authenticated"`
}

// Authenticate implements the Authenticator interface.
func (a *HTTPAuthenticator) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
	var password string
	switch {
	case cont != nil:
		password = cont.UserMsg
	case ac.Start.Type == types.AuthenTypePAP:
		password = string(ac.Start.Data)
	default:
		// Interactive ASCII login: ask for the password, verify on CONTINUE.
		return server.AuthenDecision{Status: types.AuthenStatusGetPass, ServerMsg: "Password:"}, nil
	}

	ok, err := a.verify(ctx, ac.Start.User, password, ac.Start.Type)
	if err != nil {
		return server.AuthenDecision{Status: types.AuthenStatusError, ServerMsg: "authentication backend error"}, err
	}
	if ok {
		return server.AuthenDecision{Status: types.AuthenStatusPass}, nil
	}
	return server.AuthenDecision{Status: types.AuthenStatusFail, ServerMsg: "invalid credentials"}, nil
}

func (a *HTTPAuthenticator) verify(ctx context.Context, user, password string, at types.AuthenType) (bool, error) {
	body, err := json.Marshal(httpAuthRequest{Username: user, Password: password, AuthenType: at.String()})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("aaa: http authenticator status %d", resp.StatusCode)
	}
	var out httpAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("aaa: decode http authenticator response: %w", err)
	}
	return out.Authenticated, nil
}

// Compile-time assertion that HTTPAuthenticator satisfies Authenticator.
var _ Authenticator = (*HTTPAuthenticator)(nil)
