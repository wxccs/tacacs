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

// hostResolver resolves a hostname to IP addresses. *net.Resolver satisfies
// it; tests inject a fake.
type hostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DNSRule maps a hostname to a secret and mode. The hostname is resolved
// (forward DNS, A/AAAA) to a set of allowed client IPs; a client whose
// address is in that set is served this secret. The first matching rule
// wins; rules are evaluated in slice order.
type DNSRule struct {
	// Host is the DNS name whose resolved addresses identify matching
	// clients, e.g. "nas-01.example.net".
	Host string
	// Secret is the shared key for matching clients.
	Secret []byte
	// Mode is the transport mode for matching clients.
	Mode transport.Mode
}

type dnsCompiledRule struct {
	host   string
	secret []byte
	mode   transport.Mode
	ips    map[string]struct{} // set of ipKey(resolved IP)
}

// DNSSecretProvider selects a secret by matching the client's remote address
// against the forward-resolved (A/AAAA) addresses of configured hostnames.
//
// Security model: this provider trusts the A/AAAA records of the configured
// hostnames. It does NOT perform reverse (PTR) lookups on the client address,
// which an attacker could spoof. The authentication boundary is therefore the
// DNS zone serving the configured names, which the operator is expected to
// control. Resolution happens at construction and on Refresh, never on the
// per-connection hot path, so a slow or unavailable resolver cannot stall
// accepted connections.
//
// A fallback provider is consulted when no rule matches; if the fallback is
// nil, Get returns ErrNoServerConfigured.
type DNSSecretProvider struct {
	mu       sync.RWMutex
	rules    []dnsCompiledRule
	fallback SecretProvider
	resolver hostResolver
}

// NewDNSSecretProvider resolves every rule's hostname and returns a provider.
// Resolution is synchronous so misconfigured or unresolvable hostnames surface
// immediately. A nil fallback causes unmatched lookups to return
// ErrNoServerConfigured.
func NewDNSSecretProvider(ctx context.Context, rules []DNSRule, fallback SecretProvider) (*DNSSecretProvider, error) {
	return newDNSSecretProvider(ctx, rules, fallback, net.DefaultResolver)
}

func newDNSSecretProvider(ctx context.Context, rules []DNSRule, fallback SecretProvider, resolver hostResolver) (*DNSSecretProvider, error) {
	compiled, err := resolveRules(ctx, resolver, rules)
	if err != nil {
		return nil, err
	}
	return &DNSSecretProvider{
		rules:    compiled,
		fallback: fallback,
		resolver: resolver,
	}, nil
}

// resolveRules resolves each rule strictly: any lookup failure is fatal so the
// caller can reject a bad configuration at construction time.
func resolveRules(ctx context.Context, resolver hostResolver, rules []DNSRule) ([]dnsCompiledRule, error) {
	compiled := make([]dnsCompiledRule, 0, len(rules))
	for _, r := range rules {
		if r.Host == "" {
			return nil, errors.NewValidationError("host", "", errors.ErrInvalidArgument)
		}
		addrs, err := resolver.LookupIPAddr(ctx, r.Host)
		if err != nil {
			return nil, errors.NewValidationError("host", r.Host, err)
		}
		compiled = append(compiled, dnsCompiledRule{
			host:   r.Host,
			secret: r.Secret,
			mode:   r.Mode,
			ips:    ipSet(addrs),
		})
	}
	return compiled, nil
}

// Refresh re-resolves every configured hostname and atomically swaps the
// resolved address sets. It is safe to call while concurrent Get calls are in
// flight; callers typically invoke it on a ticker at the DNS TTL.
//
// Refresh is lenient: if a hostname fails to resolve, its previous address set
// is retained (stale-while-revalidate) so a transient DNS outage does not drop
// a NAS's secret. Refresh returns an error only if no rule resolved and at
// least one failed, signalling a likely systemic resolver problem.
func (p *DNSSecretProvider) Refresh(ctx context.Context) error {
	p.mu.RLock()
	current := p.rules
	resolver := p.resolver
	p.mu.RUnlock()

	updated := make([]dnsCompiledRule, len(current))
	var resolved, failed int
	for i, r := range current {
		addrs, err := resolver.LookupIPAddr(ctx, r.host)
		if err != nil {
			updated[i] = r // keep stale set
			failed++
			continue
		}
		updated[i] = dnsCompiledRule{host: r.host, secret: r.secret, mode: r.mode, ips: ipSet(addrs)}
		resolved++
	}

	p.mu.Lock()
	p.rules = updated
	p.mu.Unlock()

	if resolved == 0 && failed > 0 {
		return errors.NewValidationError("dns", "refresh", errors.ErrNoServerConfigured)
	}
	return nil
}

// Get implements SecretProvider. It performs an in-memory set lookup only; no
// DNS query is issued on this path.
func (p *DNSSecretProvider) Get(ctx context.Context, remote net.Addr) (SecretConfig, error) {
	ip := ipFromAddr(remote)
	if ip == nil {
		return p.fallbackGet(ctx, remote)
	}
	key := ipKey(ip)

	p.mu.RLock()
	for _, r := range p.rules {
		if _, ok := r.ips[key]; ok {
			cfg := SecretConfig{Secret: r.secret, Mode: r.mode}
			p.mu.RUnlock()
			return cfg, nil
		}
	}
	p.mu.RUnlock()
	return p.fallbackGet(ctx, remote)
}

func (p *DNSSecretProvider) fallbackGet(ctx context.Context, remote net.Addr) (SecretConfig, error) {
	p.mu.RLock()
	fb := p.fallback
	p.mu.RUnlock()
	if fb != nil {
		return fb.Get(ctx, remote)
	}
	return SecretConfig{}, errors.ErrNoServerConfigured
}

// ipSet builds a membership set keyed by the canonical 16-byte form of each
// resolved address.
func ipSet(addrs []net.IPAddr) map[string]struct{} {
	set := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if k := ipKey(a.IP); k != "" {
			set[k] = struct{}{}
		}
	}
	return set
}

// ipKey normalizes an IP to its canonical 16-byte form for use as a map key,
// so 4-byte and 16-byte representations of the same address compare equal.
func ipKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v16 := ip.To16(); v16 != nil {
		return string(v16)
	}
	return ""
}
