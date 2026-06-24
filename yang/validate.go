// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package yang

import (
	"fmt"
	"strings"

	"github.com/wxccs/tacacs/errors"
)

// TLS12 identity names forbidden as min or max (RFC 9950 §2.5, RFC 9887 §3.2).
const (
	tlsVersion12 = "ietf-tls-common:tls12"
	tlsVersion13 = "ietf-tls-common:tls13"
)

// Validate enforces the RFC 9950 data-model constraints:
//   - each server has name, server-type, address, port and a security choice;
//   - (address, port) pairs are unique across servers (§2.4 unique constraint);
//   - sni-enabled requires domain-name (§2.4 must);
//   - TLS servers must have a server-authentication configured (§2.5 must);
//   - hello-params, if present, must not forbid TLS 1.2 as min or max
//     (§2.5 must refinement);
//   - timeout, if non-zero, is at least 1 (range 1..max).
func (c *Config) Validate() error {
	seen := make(map[string]bool, len(c.Servers))
	for _, s := range c.Servers {
		if s.Name == "" {
			return errors.NewValidationError("server.name", "name is required", errors.ErrInvalidArgument)
		}
		if s.ServerType == 0 {
			return errors.NewValidationError("server.server-type", "server-type is required", errors.ErrInvalidArgument)
		}
		if s.Address == "" {
			return errors.NewValidationError("server.address", "address is required", errors.ErrInvalidArgument)
		}
		if s.Port == 0 {
			return errors.NewValidationError("server.port", "port is required (no default)", errors.ErrInvalidArgument)
		}
		if s.Security.TLS == nil && s.Security.SharedSecret == nil {
			return errors.NewValidationError("server.security", "security choice is required", errors.ErrInvalidArgument)
		}
		// unique (address, port).
		key := fmt.Sprintf("%s:%d", s.Address, s.Port)
		if seen[key] {
			return errors.NewValidationError("server", fmt.Sprintf("duplicate address+port: %s", key), errors.ErrInvalidArgument)
		}
		seen[key] = true

		if s.SNIEnabled && s.DomainName == "" {
			return errors.NewValidationError("server.sni-enabled", "sni-enabled requires domain-name", errors.ErrInvalidArgument)
		}
		if s.Security.TLS != nil {
			if err := validateTLS(s.Security.TLS); err != nil {
				return err
			}
		}
		if s.Timeout != 0 && s.Timeout < 1 {
			return errors.NewValidationError("server.timeout", "timeout must be >= 1", errors.ErrInvalidArgument)
		}
	}
	return nil
}

// validateTLS checks the TLS-specific must constraints.
func validateTLS(t *TLSClient) error {
	// server-authentication must have at least one of ref/ca-certs/ee-certs.
	sa := t.ServerAuthentication
	if sa.CredentialsReference == "" && sa.CACerts == nil && sa.EECerts == nil {
		return errors.NewValidationError("server-authentication", "TLS requires server-authentication (ref, ca-certs or ee-certs)", errors.ErrInvalidArgument)
	}
	if t.HelloParams != nil {
		min := strings.TrimSpace(t.HelloParams.TLSVersions.Min)
		max := strings.TrimSpace(t.HelloParams.TLSVersions.Max)
		if min == tlsVersion12 {
			return errors.NewValidationError("hello-params.tls-versions.min", "TLS 1.2 is forbidden (RFC 9887)", errors.ErrInvalidArgument)
		}
		if max == tlsVersion12 {
			return errors.NewValidationError("hello-params.tls-versions.max", "TLS 1.2 is forbidden (RFC 9887)", errors.ErrInvalidArgument)
		}
	}
	return nil
}

// IsTLS13 reports whether a TLS version identityref denotes TLS 1.3 or above.
func IsTLS13(version string) bool {
	return strings.TrimSpace(version) == tlsVersion13
}
