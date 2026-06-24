// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/wxccs/tacacs/transport"
)

func TestStaticSecretReturnsConfigured(t *testing.T) {
	s := StaticSecret{Secret: []byte("k"), Mode: transport.ModeTLS}
	sc, err := s.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "k" {
		t.Errorf("secret = %q, want %q", sc.Secret, "k")
	}
	if sc.Mode != transport.ModeTLS {
		t.Errorf("mode = %v, want %v", sc.Mode, transport.ModeTLS)
	}
}

func TestPrefixSecretProviderMatchesCIDR(t *testing.T) {
	rules := []PrefixRule{
		{CIDR: "10.0.0.0/8", Secret: []byte("ten"), Mode: transport.ModeLegacy},
		{CIDR: "192.168.1.0/24", Secret: []byte("cisco"), Mode: transport.ModeTLS},
	}
	p, err := NewPrefixSecretProvider(rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Match 10.0.0.0/8
	sc, err := p.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "ten" {
		t.Errorf("secret = %q, want %q", sc.Secret, "ten")
	}

	// Match 192.168.1.0/24 (first match wins; 10.x rule is first but doesn't match)
	sc, err = p.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(192, 168, 1, 50)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "cisco" {
		t.Errorf("secret = %q, want %q", sc.Secret, "cisco")
	}
	if sc.Mode != transport.ModeTLS {
		t.Errorf("mode = %v, want %v", sc.Mode, transport.ModeTLS)
	}
}

func TestPrefixSecretProviderFallback(t *testing.T) {
	fallback := StaticSecret{Secret: []byte("default"), Mode: transport.ModeLegacy}
	p, err := NewPrefixSecretProvider(nil, fallback)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No rule matches → fallback
	sc, err := p.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(8, 8, 8, 8)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "default" {
		t.Errorf("secret = %q, want %q", sc.Secret, "default")
	}
}

func TestPrefixSecretProviderNoMatchNoFallback(t *testing.T) {
	p, err := NewPrefixSecretProvider(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = p.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(8, 8, 8, 8)})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestPrefixSecretProviderReplace(t *testing.T) {
	p, err := NewPrefixSecretProvider(
		[]PrefixRule{{CIDR: "10.0.0.0/8", Secret: []byte("old"), Mode: transport.ModeLegacy}},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Initial rule matches
	sc, err := p.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "old" {
		t.Errorf("secret = %q, want %q", sc.Secret, "old")
	}

	// Hot-replace
	err = p.Replace(
		[]PrefixRule{{CIDR: "10.0.0.0/8", Secret: []byte("new"), Mode: transport.ModeTLS}},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// New rule takes effect
	sc, err = p.Get(context.Background(), &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "new" {
		t.Errorf("secret = %q, want %q", sc.Secret, "new")
	}
	if sc.Mode != transport.ModeTLS {
		t.Errorf("mode = %v, want %v", sc.Mode, transport.ModeTLS)
	}
}

func TestPrefixSecretProviderInvalidCIDR(t *testing.T) {
	_, err := NewPrefixSecretProvider(
		[]PrefixRule{{CIDR: "not-a-cidr", Secret: []byte("x")}},
		nil,
	)
	if err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

func TestPrefixSecretProviderIPv6(t *testing.T) {
	p, err := NewPrefixSecretProvider(
		[]PrefixRule{{CIDR: "2001:db8::/32", Secret: []byte("v6"), Mode: transport.ModeLegacy}},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sc, err := p.Get(context.Background(), &net.TCPAddr{IP: net.ParseIP("2001:db8::1")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sc.Secret) != "v6" {
		t.Errorf("secret = %q, want %q", sc.Secret, "v6")
	}
}

// errProvider is a SecretProvider that always errors, for testing AcceptConn.
type errProvider struct{ err error }

func (e errProvider) Get(context.Context, net.Addr) (SecretConfig, error) {
	return SecretConfig{}, e.err
}

func TestAcceptConnRejectsOnSecretProviderError(t *testing.T) {
	srv := New(Config{
		Handler:        HandlerFunc{},
		SecretProvider: errProvider{err: errors.New("nope")},
	})
	defer srv.Close()

	// Use a pipe to simulate a connection without a real listener.
	c1, c2 := net.Pipe()
	defer c1.Close()

	err := srv.AcceptConn(context.Background(), c2)
	if err == nil || err.Error() != "nope" {
		t.Fatalf("expected 'nope' error, got %v", err)
	}
}
