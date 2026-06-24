// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package server

import (
	"context"
	"net"
	"sync"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/transport"
)

// SecretConfig is the per-connection secret and mode selected by a
// SecretProvider for an incoming client.
type SecretConfig struct {
	// Secret is the shared key for MD5 obfuscation (legacy TCP only). It is
	// ignored under TLS.
	Secret []byte
	// Mode is the transport mode to apply to this connection. It overrides
	// Server.Config.Mode, allowing different clients to use different modes.
	Mode transport.Mode
}

// SecretProvider resolves the shared secret and transport mode for an
// incoming client connection. It enables multi-NAS deployments where
// different clients use different shared keys or transports.
//
// Implementations MUST be safe for concurrent use: the Server calls Get
// from many goroutines (one per accepted connection).
type SecretProvider interface {
	// Get returns the SecretConfig for the given remote address. Returning
	// an error causes the Server to reject the connection without sending
	// any TACACS+ reply.
	Get(ctx context.Context, remote net.Addr) (SecretConfig, error)
}

// StaticSecret is a SecretProvider that always returns the same secret and
// mode. It is the default when Config.SecretProvider is nil, preserving
// the original single-secret behavior.
type StaticSecret struct {
	Secret []byte
	Mode   transport.Mode
}

// Get implements SecretProvider.
func (s StaticSecret) Get(context.Context, net.Addr) (SecretConfig, error) {
	return SecretConfig{Secret: s.Secret, Mode: s.Mode}, nil
}

// PrefixRule maps a CIDR to a secret and mode. The first matching rule
// wins; rules are evaluated in slice order.
type PrefixRule struct {
	// CIDR is the network prefix to match against the client address,
	// e.g. "10.0.0.0/8" or "2001:db8::/32".
	CIDR string
	// Secret is the shared key for matching clients.
	Secret []byte
	// Mode is the transport mode for matching clients.
	Mode transport.Mode
}

// PrefixSecretProvider is a SecretProvider that selects a secret by
// matching the client's remote address against an ordered list of CIDR
// rules. A fallback provider is consulted when no rule matches; if the
// fallback is nil, Get returns ErrNoServerConfigured.
//
// The rules and fallback may be swapped at runtime via Replace to support
// configuration hot-reload; reads are guarded by an RWMutex.
type PrefixSecretProvider struct {
	mu       sync.RWMutex
	rules    []compiledRule
	fallback SecretProvider
}

type compiledRule struct {
	ipNet  *net.IPNet
	secret []byte
	mode   transport.Mode
}

// NewPrefixSecretProvider compiles the given rules and returns a
// PrefixSecretProvider. A nil fallback causes unmatched lookups to return
// ErrNoServerConfigured.
func NewPrefixSecretProvider(rules []PrefixRule, fallback SecretProvider) (*PrefixSecretProvider, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		_, ipNet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			return nil, errors.NewValidationError("cidr", r.CIDR, err)
		}
		compiled = append(compiled, compiledRule{
			ipNet:  ipNet,
			secret: r.Secret,
			mode:   r.Mode,
		})
	}
	return &PrefixSecretProvider{
		rules:    compiled,
		fallback: fallback,
	}, nil
}

// Replace atomically swaps the rules and fallback. It is safe to call
// while concurrent Get calls are in flight.
func (p *PrefixSecretProvider) Replace(rules []PrefixRule, fallback SecretProvider) error {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		_, ipNet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			return errors.NewValidationError("cidr", r.CIDR, err)
		}
		compiled = append(compiled, compiledRule{
			ipNet:  ipNet,
			secret: r.Secret,
			mode:   r.Mode,
		})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = compiled
	p.fallback = fallback
	return nil
}

// Get implements SecretProvider.
func (p *PrefixSecretProvider) Get(ctx context.Context, remote net.Addr) (SecretConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ip := ipFromAddr(remote)
	if ip == nil {
		if p.fallback != nil {
			return p.fallback.Get(ctx, remote)
		}
		return SecretConfig{}, errors.ErrNoServerConfigured
	}
	for _, r := range p.rules {
		if r.ipNet.Contains(ip) {
			return SecretConfig{Secret: r.secret, Mode: r.mode}, nil
		}
	}
	if p.fallback != nil {
		return p.fallback.Get(ctx, remote)
	}
	return SecretConfig{}, errors.ErrNoServerConfigured
}

// ipFromAddr extracts the net.IP from a net.Addr. It supports the common
// address types returned by net.Listener.Accept; for unknown types it
// falls back to parsing the string form.
func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	if a == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return net.ParseIP(a.String())
	}
	return net.ParseIP(host)
}
