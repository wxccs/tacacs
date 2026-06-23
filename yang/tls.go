// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

package yang

// TLSClient mirrors the tls-client grouping (RFC 9950 §2.5): client identity,
// server authentication and TLS hello parameters.
type TLSClient struct {
	// ClientIdentity is the optional client identity credentials (ref or explicit).
	ClientIdentity ClientIdentity `yaml:"client-identity,omitempty" json:"client-identity,omitempty"`
	// ServerAuthentication is how the client authenticates servers.
	ServerAuthentication ServerAuthentication `yaml:"server-authentication" json:"server-authentication"`
	// HelloParams is the optional TLS hello parameters (versions + cipher suites).
	HelloParams *HelloParams `yaml:"hello-params,omitempty" json:"hello-params,omitempty"`
}

// ClientIdentity is the ref-or-explicit choice for the client identity.
type ClientIdentity struct {
	// CredentialsReference references a client-credentials entry by id.
	CredentialsReference string `yaml:"credentials-reference,omitempty" json:"credentials-reference,omitempty"`
	// Explicit, when Certificate is set, selects an inline client certificate.
	Certificate *Certificate `yaml:"certificate,omitempty" json:"certificate,omitempty"`
}

// ServerAuthentication is the ref-or-explicit choice for server auth.
type ServerAuthentication struct {
	// CredentialsReference references a server-credentials entry by id.
	CredentialsReference string `yaml:"credentials-reference,omitempty" json:"credentials-reference,omitempty"`
	// CACerts is the set of CA certificates for chain-of-trust verification.
	CACerts *CertBag `yaml:"ca-certs,omitempty" json:"ca-certs,omitempty"`
	// EECerts is the set of end-entity server certificates for exact-match auth.
	EECerts *CertBag `yaml:"ee-certs,omitempty" json:"ee-certs,omitempty"`
}

// CertBag is an inline-or-truststore certificate bag.
type CertBag struct {
	// InlineDefinition holds inline certificates.
	InlineDefinition *InlineCerts `yaml:"inline-definition,omitempty" json:"inline-definition,omitempty"`
	// CentralTruststoreReference references a truststore bag.
	CentralTruststoreReference string `yaml:"central-truststore-reference,omitempty" json:"central-truststore-reference,omitempty"`
}

// InlineCerts holds a list of inline certificates.
type InlineCerts struct {
	Certificate []NamedCert `yaml:"certificate" json:"certificate"`
}

// NamedCert is a named certificate with its CMS data (base64).
type NamedCert struct {
	Name     string `yaml:"name" json:"name"`
	CertData string `yaml:"cert-data" json:"cert-data"`
}

// Certificate mirrors the certificate grouping (RFC 9950 §2.7): for a config
// loader we capture the inline public/private key material minimally.
type Certificate struct {
	// InlineDefinition holds the inline key material (base64 PEM/CMS).
	InlineDefinition *InlineCertificate `yaml:"inline-definition,omitempty" json:"inline-definition,omitempty"`
}

// InlineCertificate holds the inline client certificate material.
type InlineCertificate struct {
	PublicKeyFormat     string `yaml:"public-key-format,omitempty" json:"public-key-format,omitempty"`
	PublicKey           string `yaml:"public-key,omitempty" json:"public-key,omitempty"`
	PrivateKeyFormat    string `yaml:"private-key-format,omitempty" json:"private-key-format,omitempty"`
	CleartextPrivateKey string `yaml:"cleartext-private-key,omitempty" json:"cleartext-private-key,omitempty"`
	CertData            string `yaml:"cert-data,omitempty" json:"cert-data,omitempty"`
}

// HelloParams mirrors the hello-params grouping (RFC 9950 §2.5) with the
// constraint that TLS 1.2 is forbidden as min or max.
type HelloParams struct {
	// TLSVersions is the allowed TLS version range.
	TLSVersions TLSVersions `yaml:"tls-versions" json:"tls-versions"`
	// CipherSuites is the configurable set of TLS 1.3 cipher suites.
	CipherSuites CipherSuites `yaml:"cipher-suites,omitempty" json:"cipher-suites,omitempty"`
}

// TLSVersions holds the min and max TLS version identityrefs.
type TLSVersions struct {
	Min string `yaml:"min" json:"min"`
	Max string `yaml:"max" json:"max"`
}

// CipherSuites holds the configurable cipher suite list.
type CipherSuites struct {
	CipherSuite []string `yaml:"cipher-suite,omitempty" json:"cipher-suite,omitempty"`
}

// ClientCredential is a registry entry for globally-referenced client identity.
type ClientCredential struct {
	ID          string       `yaml:"id" json:"id"`
	Certificate *Certificate `yaml:"certificate,omitempty" json:"certificate,omitempty"`
}

// ServerCredential is a registry entry for globally-referenced server-auth.
type ServerCredential struct {
	ID      string   `yaml:"id" json:"id"`
	CACerts *CertBag `yaml:"ca-certs,omitempty" json:"ca-certs,omitempty"`
	EECerts *CertBag `yaml:"ee-certs,omitempty" json:"ee-certs,omitempty"`
}
