// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package yang

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactSharedSecret(t *testing.T) {
	secret := "verysecret"
	cfg := &Config{Servers: []Server{{Name: "s", Security: Security{SharedSecret: &secret}}}}
	r := cfg.Redact()
	require.NotNil(t, r.Servers[0].Security.SharedSecret)
	assert.Equal(t, "**********", *r.Servers[0].Security.SharedSecret)
	// Original unchanged.
	assert.Equal(t, "verysecret", *cfg.Servers[0].Security.SharedSecret)
}

func TestRedactPrivateKey(t *testing.T) {
	cfg := &Config{Servers: []Server{{
		Name: "s", Security: Security{TLS: &TLSClient{
			ClientIdentity: ClientIdentity{Certificate: &Certificate{InlineDefinition: &InlineCertificate{CleartextPrivateKey: "priv"}}},
		}},
	}}}
	r := cfg.Redact()
	assert.Equal(t, "<redacted>", r.Servers[0].Security.TLS.ClientIdentity.Certificate.InlineDefinition.CleartextPrivateKey)
}

func TestRedactNil(t *testing.T) {
	assert.Nil(t, (*Config)(nil).Redact())
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	assert.Error(t, err)
}

func TestLoadBadYAML(t *testing.T) {
	p := writeTemp(t, "bad.yaml", "server: [not a map")
	_, err := Load(p)
	assert.Error(t, err)
}

func TestLoadFromBytesBad(t *testing.T) {
	_, err := LoadFromBytes([]byte(":::not yaml"), "yaml")
	assert.Error(t, err)
}

func TestParseServerTypeList(t *testing.T) {
	// A server-type given as a list of strings.
	yaml := `
server:
  - name: s
    server-type:
      - authentication
      - accounting
    address: 10.0.0.1
    port: 49
    security:
      shared-secret: "k"
`
	p := writeTemp(t, "c.yaml", yaml)
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, ServerTypeAuthentication|ServerTypeAccounting, cfg.Servers[0].ServerType)
}

func TestValidateTLS12MaxForbidden(t *testing.T) {
	cfg := Config{Servers: []Server{{
		Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 300,
		Security: Security{TLS: &TLSClient{
			ServerAuthentication: ServerAuthentication{CACerts: &CertBag{}},
			HelloParams:          &HelloParams{TLSVersions: TLSVersions{Min: "ietf-tls-common:tls13", Max: "ietf-tls-common:tls12"}},
		}},
	}}}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max")
}

func TestValidateTLSEEOnly(t *testing.T) {
	// TLS with ee-certs only (no ca-certs, no ref) is valid.
	cfg := Config{Servers: []Server{{
		Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 300,
		Security: Security{TLS: &TLSClient{ServerAuthentication: ServerAuthentication{EECerts: &CertBag{}}}},
	}}}
	assert.NoError(t, cfg.Validate())
}

func TestValidateTimeoutZeroAllowed(t *testing.T) {
	// timeout == 0 means "not set"; only non-zero values < 1 are invalid.
	cfg := Config{Servers: []Server{{
		Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 49, Timeout: 0,
		Security: Security{SharedSecret: strPtr("k")},
	}}}
	assert.NoError(t, cfg.Validate())
}
