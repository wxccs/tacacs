// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package yang

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tacerrs "github.com/wxccs/tacacs/errors"
)

// sharedSecretYAML mirrors RFC 9950 Appendix A (shared-secret authentication).
const sharedSecretYAML = `
server:
  - name: tac_plus1
    server-type: authentication
    address: 192.0.2.2
    port: 49
    security:
      shared-secret: "QaEfThUkO198010075460923+h3TbE8n"
    source:
      source-ip: 192.0.2.12
    timeout: 10
`

// tlsYAML mirrors RFC 9950 Appendix B.1 (TACACS+ over TLS, inline certs).
const tlsYAML = `
server:
  - name: instance-1
    server-type: authentication
    domain-name: tacacs.example.com
    sni-enabled: true
    address: 2001:db8::1
    port: 1234
    security:
      tls:
        client-identity:
          certificate:
            inline-definition:
              public-key-format: ietf-crypto-types:subject-public-key-info-format
              public-key: BASE64VALUE=
              cert-data: BASE64VALUE=
        server-authentication:
          ca-certs:
            inline-definition:
              certificate:
                - name: CA-Certificate-1
                  cert-data: BASE64VALUE=
        hello-params:
          tls-versions:
            min: ietf-tls-common:tls13
            max: ietf-tls-common:tls13
          cipher-suites:
            cipher-suite:
              - TLS_AES_128_GCM_SHA256
    single-connection: false
    timeout: 10
`

// tlsCredRefYAML mirrors RFC 9950 Appendix B.2 (TLS with credential references).
const tlsCredRefYAML = `
client-credentials:
  - id: client-cred-1
    certificate:
      inline-definition:
        cert-data: BASE64VALUE=
server-credentials:
  - id: server-cred-1
    ca-certs:
      inline-definition:
        certificate:
          - name: CA-1
            cert-data: BASE64VALUE=
server:
  - name: primary-v6
    server-type: authentication
    domain-name: tacacs.example.com
    sni-enabled: true
    address: 2001:db8::1
    port: 1234
    security:
      tls:
        client-identity:
          credentials-reference: client-cred-1
        server-authentication:
          credentials-reference: server-cred-1
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

func TestLoadSharedSecretExample(t *testing.T) {
	p := writeTemp(t, "config.yaml", sharedSecretYAML)
	cfg, err := Load(p)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	s := cfg.Servers[0]
	assert.Equal(t, "tac_plus1", s.Name)
	assert.Equal(t, "192.0.2.2", s.Address)
	assert.Equal(t, uint16(49), s.Port)
	assert.Equal(t, ServerTypeAuthentication, s.ServerType)
	assert.False(t, s.Security.IsTLS())
	require.NotNil(t, s.Security.SharedSecret)
	assert.Equal(t, "QaEfThUkO198010075460923+h3TbE8n", *s.Security.SharedSecret)
	assert.Equal(t, uint16(10), s.Timeout)
}

func TestLoadTLSExample(t *testing.T) {
	p := writeTemp(t, "config.yaml", tlsYAML)
	cfg, err := Load(p)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	s := cfg.Servers[0]
	assert.True(t, s.Security.IsTLS())
	assert.True(t, s.SNIEnabled)
	assert.Equal(t, "tacacs.example.com", s.DomainName)
	require.NotNil(t, s.Security.TLS)
	require.NotNil(t, s.Security.TLS.HelloParams)
	assert.Equal(t, "ietf-tls-common:tls13", s.Security.TLS.HelloParams.TLSVersions.Min)
	require.NotNil(t, s.Security.TLS.ServerAuthentication.CACerts)
}

func TestLoadTLSCredRefExample(t *testing.T) {
	p := writeTemp(t, "config.yaml", tlsCredRefYAML)
	cfg, err := Load(p)
	require.NoError(t, err)
	require.Len(t, cfg.ClientCredentials, 1)
	assert.Equal(t, "client-cred-1", cfg.ClientCredentials[0].ID)
	require.Len(t, cfg.ServerCredentials, 1)
	assert.Equal(t, "server-cred-1", cfg.ServerCredentials[0].ID)
	require.Len(t, cfg.Servers, 1)
	assert.True(t, cfg.Servers[0].Security.IsTLS())
	assert.Equal(t, "client-cred-1", cfg.Servers[0].Security.TLS.ClientIdentity.CredentialsReference)
	assert.Equal(t, "server-cred-1", cfg.Servers[0].Security.TLS.ServerAuthentication.CredentialsReference)
}

func TestLoadFromBytesJSON(t *testing.T) {
	json := `{"server":[{"name":"s1","server-type":"authorization","address":"10.0.0.1","port":49,"security":{"shared-secret":"k"}}]}`
	cfg, err := LoadFromBytes([]byte(json), "json")
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	assert.Equal(t, ServerTypeAuthorization, cfg.Servers[0].ServerType)
}

func TestServerTypeString(t *testing.T) {
	assert.Equal(t, "authentication", ServerTypeAuthentication.String())
	assert.Equal(t, "authentication,authorization", (ServerTypeAuthentication | ServerTypeAuthorization).String())
	assert.Equal(t, "authentication,authorization,accounting", (ServerTypeAuthentication | ServerTypeAuthorization | ServerTypeAccounting).String())
	assert.Equal(t, "", ServerType(0).String())
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing name", Config{Servers: []Server{{Address: "a", Port: 49, Security: Security{SharedSecret: strPtr("k")}}}}},
		{"missing server-type", Config{Servers: []Server{{Name: "s", Address: "a", Port: 49, Security: Security{SharedSecret: strPtr("k")}}}}},
		{"missing address", Config{Servers: []Server{{Name: "s", ServerType: ServerTypeAuthentication, Port: 49, Security: Security{SharedSecret: strPtr("k")}}}}},
		{"missing port", Config{Servers: []Server{{Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Security: Security{SharedSecret: strPtr("k")}}}}},
		{"missing security", Config{Servers: []Server{{Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 49}}}},
		{"sni without domain", Config{Servers: []Server{{Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 49, SNIEnabled: true, Security: Security{TLS: &TLSClient{ServerAuthentication: ServerAuthentication{CACerts: &CertBag{}}}}}}}},
		{"tls no server-auth", Config{Servers: []Server{{Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 300, Security: Security{TLS: &TLSClient{}}}}}},
		{"tls 1.2 min forbidden", Config{Servers: []Server{{Name: "s", ServerType: ServerTypeAuthentication, Address: "a", Port: 300, Security: tls12MinSecurity()}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			require.Error(t, err)
			assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
		})
	}
}

func TestValidateDuplicateAddressPort(t *testing.T) {
	cfg := Config{Servers: []Server{
		{Name: "s1", ServerType: ServerTypeAuthentication, Address: "10.0.0.1", Port: 49, Security: Security{SharedSecret: strPtr("k")}},
		{Name: "s2", ServerType: ServerTypeAuthentication, Address: "10.0.0.1", Port: 49, Security: Security{SharedSecret: strPtr("k")}},
	}}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestValidateDistinctPortsOK(t *testing.T) {
	cfg := Config{Servers: []Server{
		{Name: "s1", ServerType: ServerTypeAuthentication, Address: "10.0.0.1", Port: 49, Security: Security{SharedSecret: strPtr("k")}},
		{Name: "s2", ServerType: ServerTypeAuthentication, Address: "10.0.0.1", Port: 50, Security: Security{SharedSecret: strPtr("k")}},
	}}
	assert.NoError(t, cfg.Validate())
}

func TestIsTLS13(t *testing.T) {
	assert.True(t, IsTLS13("ietf-tls-common:tls13"))
	assert.True(t, IsTLS13("  ietf-tls-common:tls13  "))
	assert.False(t, IsTLS13("ietf-tls-common:tls12"))
}

func strPtr(s string) *string { return &s }

// tls12MinSecurity builds a TLS security with hello-params min set to TLS 1.2,
// which Validate must reject.
func tls12MinSecurity() Security {
	return Security{TLS: &TLSClient{
		ServerAuthentication: ServerAuthentication{CACerts: &CertBag{}},
		HelloParams: &HelloParams{
			TLSVersions: TLSVersions{Min: "ietf-tls-common:tls12", Max: "ietf-tls-common:tls13"},
		},
	}}
}
