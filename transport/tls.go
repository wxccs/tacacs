// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	tacerrs "github.com/wxccs/tacacs/errors"
)

// DefaultTLSPort is the IANA-allocated TLS TACACS+ port ("tacacss", RFC 9887 §7).
const DefaultTLSPort = 300

// DefaultTCPPort is the legacy non-TLS TACACS+ port (RFC 8907).
const DefaultTCPPort = 49

// TLSConfig holds the parameters for a TACACS+ over TLS 1.3 connection per
// RFC 9887.
type TLSConfig struct {
	// ServerName is the domain name used both for SNI (RFC 9887 §3.4.2) and for
	// server certificate verification. It MUST be set; SNI is mandatory.
	ServerName string
	// CACertPool contains the CA certificates used to verify the server
	// certificate chain (RFC 9887 §3.4.1). Required for mutual authentication.
	CACertPool *x509.CertPool
	// ClientCert is the client certificate presented for mutual TLS. Required
	// unless PSK is used.
	ClientCert tls.Certificate
	// InsecureSkipVerify disables server certificate verification. It MUST NOT
	// be used in production (RFC 9887 §3.4); it exists for testing only.
	InsecureSkipVerify bool
}

// ClientTLSConfig builds a *tls.Config for a TACACS+ TLS client per RFC 9887:
//   - TLS 1.3 only (MinVersion = MaxVersion = VersionTLS13);
//   - 0-RTT is forbidden (no early_data — Go's TLS 1.3 never enables it by
//     default; this is asserted by not configuring session tickets for 0-RTT);
//   - SNI is set from ServerName;
//   - server certificate verification is enabled unless explicitly skipped.
func (c TLSConfig) ClientTLSConfig() (*tls.Config, error) {
	if c.ServerName == "" {
		return nil, errors.New("tacacs: TLS ServerName is required (SNI is mandatory per RFC 9887 3.4.2)")
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         c.ServerName,
		RootCAs:            c.CACertPool,
		InsecureSkipVerify: c.InsecureSkipVerify,
		// 0-RTT is forbidden (RFC 9887 5.1.2). Go never sends 0-RTT by default.
	}
	if c.ClientCert.Certificate != nil {
		cfg.Certificates = []tls.Certificate{c.ClientCert}
	}
	return cfg, nil
}

// ServerTLSConfig builds a *tls.Config for a TACACS+ TLS server per RFC 9887:
//   - TLS 1.3 only;
//   - client authentication is required (ClientAuth = RequireAndVerifyClientCert);
//   - the client CA pool is used to verify client certificates.
func ServerTLSConfig(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	return cfg
}

// EnforceTLSFlagPolicy checks the TAC_PLUS_UNENCRYPTED_FLAG invariant for a
// TLS connection (RFC 9887 §4): the flag MUST be set on every packet in both
// directions. It returns ErrFlagMismatch when the flag is not set, which the
// caller MUST translate into a typed ERROR reply and session termination.
func EnforceTLSFlagPolicy(flagSet bool) error {
	if !flagSet {
		return tacerrs.NewValidationError("flags", "TAC_PLUS_UNENCRYPTED_FLAG must be set under TLS", tacerrs.ErrFlagMismatch)
	}
	return nil
}

// String returns a human-readable description of the TLS config for logging,
// omitting any secret material.
func (c TLSConfig) String() string {
	return fmt.Sprintf("TLSConfig{server:%s, has-ca:%v, has-client-cert:%v, insecure:%v}",
		c.ServerName, c.CACertPool != nil, c.ClientCert.Certificate != nil, c.InsecureSkipVerify)
}
