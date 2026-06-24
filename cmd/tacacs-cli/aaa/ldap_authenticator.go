// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package aaa

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

// LDAPAuthenticator verifies credentials against an LDAP directory using the
// industry-standard search-then-bind flow:
//
//  1. Connect (LDAPS, or LDAP upgraded via StartTLS).
//  2. Bind as an optional service account and search BaseDN with UserFilter to
//     resolve the user's distinguished name.
//  3. Re-bind as that DN with the supplied password to verify it.
//
// Search-then-bind (rather than a fixed DN template) handles directories such
// as Active Directory where a user's DN cannot be derived from the username.
//
// Security:
//   - The connection MUST be encrypted (LDAPS or StartTLS) unless AllowInsecure
//     is explicitly set; otherwise the bind password crosses the wire in clear.
//   - An empty password is rejected outright: many LDAP servers treat a bind
//     with an empty password as an anonymous "unauthenticated bind" that
//     SUCCEEDS, which would otherwise let any user in. We never forward it.
//   - The username is escaped with ldap.EscapeFilter before interpolation to
//     prevent LDAP filter injection.
type LDAPAuthenticator struct {
	cfg LDAPConfig
}

// LDAPConfig configures an LDAPAuthenticator.
type LDAPConfig struct {
	// URL is the directory URL: ldaps://host:636 (implicit TLS) or
	// ldap://host:389 (cleartext, optionally upgraded via StartTLS).
	URL string
	// BindDN / BindPassword are the service-account credentials used for the
	// search step. Empty BindDN performs an anonymous search.
	BindDN       string
	BindPassword string
	// BaseDN is the search base for locating users (e.g.
	// "ou=people,dc=example,dc=com").
	BaseDN string
	// UserFilter is an LDAP filter with a single %s placeholder for the
	// (escaped) username, e.g. "(uid=%s)" or "(sAMAccountName=%s)". Defaults
	// to "(uid=%s)" if empty.
	UserFilter string
	// StartTLS upgrades a cleartext ldap:// connection to TLS before binding.
	StartTLS bool
	// AllowInsecure permits an unencrypted ldap:// connection (no LDAPS, no
	// StartTLS). Intended only for a trusted local directory; the bind
	// password is sent in clear. Defaults to false.
	AllowInsecure bool
	// TLSConfig overrides the TLS configuration for LDAPS/StartTLS.
	TLSConfig *tls.Config
	// Timeout bounds the connect+bind+search sequence. Defaults to 5s.
	Timeout time.Duration

	// dialURL, if set, overrides the dial target (test injection); URL is still
	// used to decide the TLS scheme.
	dialURL string
}

// NewLDAPAuthenticator validates the config and returns an LDAPAuthenticator.
func NewLDAPAuthenticator(cfg LDAPConfig) (*LDAPAuthenticator, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("aaa: parse ldap url: %w", err)
	}
	switch u.Scheme {
	case "ldaps":
		// implicit TLS, fine.
	case "ldap":
		if !cfg.StartTLS && !cfg.AllowInsecure {
			return nil, fmt.Errorf("aaa: ldap:// requires StartTLS or AllowInsecure (cleartext bind password)")
		}
	default:
		return nil, fmt.Errorf("aaa: ldap url scheme must be ldap or ldaps, got %q", u.Scheme)
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("aaa: ldap BaseDN is required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(uid=%s)"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &LDAPAuthenticator{cfg: cfg}, nil
}

// Authenticate implements the Authenticator interface.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, ac server.AuthenContext, cont *server.AuthenContinue) (server.AuthenDecision, error) {
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

func (a *LDAPAuthenticator) verify(ctx context.Context, user, password string) (bool, error) {
	// Reject empty passwords before they reach the server: an empty-password
	// bind is an anonymous (unauthenticated) bind on most directories and
	// would be misread as a successful authentication.
	if password == "" {
		return false, nil
	}

	conn, err := a.dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Search step: bind as the service account (or anonymously) and locate the
	// user's DN.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			return false, fmt.Errorf("aaa: ldap service bind: %w", err)
		}
	}
	filter := fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(user))
	res, err := conn.Search(ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, int(a.cfg.Timeout.Seconds()), false,
		filter,
		[]string{"dn"},
		nil,
	))
	if err != nil {
		return false, fmt.Errorf("aaa: ldap search: %w", err)
	}
	if len(res.Entries) != 1 {
		// Zero or ambiguous match: treat as authentication failure, not error.
		return false, nil
	}
	userDN := res.Entries[0].DN

	// Verify step: bind as the user. Invalid credentials are a clean failure;
	// any other bind error is surfaced.
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, fmt.Errorf("aaa: ldap user bind: %w", err)
	}
	return true, nil
}

func (a *LDAPAuthenticator) dial(ctx context.Context) (*ldap.Conn, error) {
	dialURL := a.cfg.dialURL
	if dialURL == "" {
		dialURL = a.cfg.URL
	}
	opts := []ldap.DialOpt{}
	if a.cfg.TLSConfig != nil {
		opts = append(opts, ldap.DialWithTLSConfig(a.cfg.TLSConfig))
	}
	conn, err := ldap.DialURL(dialURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("aaa: ldap dial: %w", err)
	}
	conn.SetTimeout(a.cfg.Timeout)
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}
	if a.cfg.StartTLS {
		if err := conn.StartTLS(a.cfg.TLSConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("aaa: ldap starttls: %w", err)
		}
	}
	return conn, nil
}

// Compile-time assertion that LDAPAuthenticator satisfies Authenticator.
var _ Authenticator = (*LDAPAuthenticator)(nil)
