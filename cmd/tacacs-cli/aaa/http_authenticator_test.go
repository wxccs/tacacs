// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// newTestServer spins up an httptest server that authenticates a single
// username/password pair and echoes the received authen_type back via a
// header so tests can assert it was forwarded.
func newTestServer(t *testing.T, wantUser, wantPass string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req httpAuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Authen-Type", req.AuthenType)
		ok := req.Username == wantUser && req.Password == wantPass
		_ = json.NewEncoder(w).Encode(httpAuthResponse{Authenticated: ok})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newHTTPAuth(t *testing.T, endpoint string) *HTTPAuthenticator {
	t.Helper()
	a, err := NewHTTPAuthenticator(HTTPConfig{Endpoint: endpoint, AllowInsecure: true})
	if err != nil {
		t.Fatalf("NewHTTPAuthenticator: %v", err)
	}
	return a
}

func TestHTTPAuthenticatorPAPPass(t *testing.T) {
	srv := newTestServer(t, "alice", "s3cret")
	a := newHTTPAuth(t, srv.URL)

	ac := server.AuthenContext{Start: server.AuthenStart{
		User: "alice",
		Type: types.AuthenTypePAP,
		Data: []byte("s3cret"),
	}}
	dec, err := a.Authenticate(context.Background(), ac, nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if dec.Status != types.AuthenStatusPass {
		t.Errorf("status = %v, want PASS", dec.Status)
	}
}

func TestHTTPAuthenticatorPAPFail(t *testing.T) {
	srv := newTestServer(t, "alice", "s3cret")
	a := newHTTPAuth(t, srv.URL)

	ac := server.AuthenContext{Start: server.AuthenStart{
		User: "alice",
		Type: types.AuthenTypePAP,
		Data: []byte("wrong"),
	}}
	dec, err := a.Authenticate(context.Background(), ac, nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if dec.Status != types.AuthenStatusFail {
		t.Errorf("status = %v, want FAIL", dec.Status)
	}
}

// TestHTTPAuthenticatorInteractive verifies the ASCII flow: the first step
// (no continue) returns GETPASS, and the follow-up CONTINUE carrying the
// password verifies against the backend.
func TestHTTPAuthenticatorInteractive(t *testing.T) {
	srv := newTestServer(t, "bob", "hunter2")
	a := newHTTPAuth(t, srv.URL)

	ac := server.AuthenContext{Start: server.AuthenStart{
		User: "bob",
		Type: types.AuthenTypeASCII,
	}}
	dec, err := a.Authenticate(context.Background(), ac, nil)
	if err != nil {
		t.Fatalf("Authenticate(start): %v", err)
	}
	if dec.Status != types.AuthenStatusGetPass {
		t.Fatalf("status = %v, want GETPASS", dec.Status)
	}

	dec, err = a.Authenticate(context.Background(), ac, &server.AuthenContinue{UserMsg: "hunter2"})
	if err != nil {
		t.Fatalf("Authenticate(continue): %v", err)
	}
	if dec.Status != types.AuthenStatusPass {
		t.Errorf("status = %v, want PASS", dec.Status)
	}
}

// TestHTTPAuthenticatorBackendError verifies a non-2xx backend response yields
// an ERROR status plus a non-nil error (so misconfiguration surfaces).
func TestHTTPAuthenticatorBackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	a := newHTTPAuth(t, srv.URL)

	ac := server.AuthenContext{Start: server.AuthenStart{
		User: "alice",
		Type: types.AuthenTypePAP,
		Data: []byte("s3cret"),
	}}
	dec, err := a.Authenticate(context.Background(), ac, nil)
	if err == nil {
		t.Fatal("expected error on 5xx backend")
	}
	if dec.Status != types.AuthenStatusError {
		t.Errorf("status = %v, want ERROR", dec.Status)
	}
}

// TestHTTPAuthenticatorRequiresHTTPS verifies the constructor rejects a plain
// http endpoint unless AllowInsecure is set.
func TestHTTPAuthenticatorRequiresHTTPS(t *testing.T) {
	if _, err := NewHTTPAuthenticator(HTTPConfig{Endpoint: "http://example.com/verify"}); err == nil {
		t.Error("expected error for http endpoint without AllowInsecure")
	}
	if _, err := NewHTTPAuthenticator(HTTPConfig{Endpoint: "https://example.com/verify"}); err != nil {
		t.Errorf("https endpoint should be accepted: %v", err)
	}
	if _, err := NewHTTPAuthenticator(HTTPConfig{Endpoint: "http://localhost:8080/verify", AllowInsecure: true}); err != nil {
		t.Errorf("http endpoint with AllowInsecure should be accepted: %v", err)
	}
}
