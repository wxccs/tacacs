// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerr "github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/transport"
)

// fakeResolver returns canned addresses per host and can be swapped at runtime
// to simulate DNS changes between refreshes.
type fakeResolver struct {
	mu   sync.Mutex
	hits map[string][]net.IPAddr
	err  map[string]error
}

func (f *fakeResolver) set(host string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits == nil {
		f.hits = map[string][]net.IPAddr{}
	}
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		addrs = append(addrs, net.IPAddr{IP: net.ParseIP(s)})
	}
	f.hits[host] = addrs
}

func (f *fakeResolver) fail(host string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		f.err = map[string]error{}
	}
	f.err[host] = err
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.err[host]; ok {
		return nil, err
	}
	addrs, ok := f.hits[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

func tcpAddr(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 49152} }

// TestDNSSecretProviderMatch verifies a client whose IP is in a configured
// host's resolved set receives that host's secret.
func TestDNSSecretProviderMatch(t *testing.T) {
	r := &fakeResolver{}
	r.set("nas-a.example.net", "10.0.0.1", "10.0.0.2")
	r.set("nas-b.example.net", "192.168.1.1")

	p, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "nas-a.example.net", Secret: []byte("secretA"), Mode: transport.ModeLegacy},
		{Host: "nas-b.example.net", Secret: []byte("secretB"), Mode: transport.ModeTLS},
	}, nil, r)
	require.NoError(t, err)

	cfg, err := p.Get(context.Background(), tcpAddr("10.0.0.2"))
	require.NoError(t, err)
	assert.Equal(t, []byte("secretA"), cfg.Secret)
	assert.Equal(t, transport.ModeLegacy, cfg.Mode)

	cfg, err = p.Get(context.Background(), tcpAddr("192.168.1.1"))
	require.NoError(t, err)
	assert.Equal(t, []byte("secretB"), cfg.Secret)
	assert.Equal(t, transport.ModeTLS, cfg.Mode)
}

// TestDNSSecretProviderNoMatchFallback verifies unmatched clients hit the
// fallback, and that a nil fallback yields ErrNoServerConfigured.
func TestDNSSecretProviderNoMatchFallback(t *testing.T) {
	r := &fakeResolver{}
	r.set("nas-a.example.net", "10.0.0.1")

	withFallback, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "nas-a.example.net", Secret: []byte("secretA")},
	}, StaticSecret{Secret: []byte("default")}, r)
	require.NoError(t, err)

	cfg, err := withFallback.Get(context.Background(), tcpAddr("172.16.0.9"))
	require.NoError(t, err)
	assert.Equal(t, []byte("default"), cfg.Secret)

	noFallback, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "nas-a.example.net", Secret: []byte("secretA")},
	}, nil, r)
	require.NoError(t, err)

	_, err = noFallback.Get(context.Background(), tcpAddr("172.16.0.9"))
	require.ErrorIs(t, err, tacerr.ErrNoServerConfigured)
}

// TestDNSSecretProviderConstructFailsOnBadHost verifies an unresolvable host
// fails construction so misconfiguration surfaces at startup.
func TestDNSSecretProviderConstructFailsOnBadHost(t *testing.T) {
	r := &fakeResolver{}
	r.fail("broken.example.net", errors.New("server misbehaving"))

	_, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "broken.example.net", Secret: []byte("x")},
	}, nil, r)
	require.Error(t, err)

	_, err = newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "", Secret: []byte("x")},
	}, nil, r)
	require.ErrorIs(t, err, tacerr.ErrInvalidArgument)
}

// TestDNSSecretProviderRefreshPicksUpChange verifies Refresh re-resolves and
// the new address set takes effect.
func TestDNSSecretProviderRefreshPicksUpChange(t *testing.T) {
	r := &fakeResolver{}
	r.set("nas.example.net", "10.0.0.1")

	p, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "nas.example.net", Secret: []byte("s")},
	}, nil, r)
	require.NoError(t, err)

	// Old address still matches, new one does not yet.
	_, err = p.Get(context.Background(), tcpAddr("10.0.0.1"))
	require.NoError(t, err)
	_, err = p.Get(context.Background(), tcpAddr("10.0.0.5"))
	require.ErrorIs(t, err, tacerr.ErrNoServerConfigured)

	// DNS now points the host at a new address.
	r.set("nas.example.net", "10.0.0.5")
	require.NoError(t, p.Refresh(context.Background()))

	_, err = p.Get(context.Background(), tcpAddr("10.0.0.5"))
	require.NoError(t, err)
	_, err = p.Get(context.Background(), tcpAddr("10.0.0.1"))
	require.ErrorIs(t, err, tacerr.ErrNoServerConfigured)
}

// TestDNSSecretProviderRefreshServesStale verifies a per-host resolve failure
// during Refresh retains the previous address set rather than dropping it.
func TestDNSSecretProviderRefreshServesStale(t *testing.T) {
	r := &fakeResolver{}
	r.set("nas.example.net", "10.0.0.1")

	p, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "nas.example.net", Secret: []byte("s")},
	}, nil, r)
	require.NoError(t, err)

	// Resolver now fails for this host; Refresh should keep the stale set and
	// report an error (all rules failed).
	r.fail("nas.example.net", errors.New("timeout"))
	require.Error(t, p.Refresh(context.Background()))

	cfg, err := p.Get(context.Background(), tcpAddr("10.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, []byte("s"), cfg.Secret)
}

// TestDNSSecretProviderV4V6Normalization verifies a 4-in-6 client address
// matches a host resolved to the equivalent IPv4 address.
func TestDNSSecretProviderV4V6Normalization(t *testing.T) {
	r := &fakeResolver{}
	r.set("nas.example.net", "10.0.0.1")

	p, err := newDNSSecretProvider(context.Background(), []DNSRule{
		{Host: "nas.example.net", Secret: []byte("s")},
	}, nil, r)
	require.NoError(t, err)

	// IPv4-mapped IPv6 form of 10.0.0.1.
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 1}
	cfg, err := p.Get(context.Background(), mapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("s"), cfg.Secret)
}
