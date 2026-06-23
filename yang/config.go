// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
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

import "strings"

// Config is the top-level TACACS+ configuration, mirroring the
// ietf-system-tacacs-plus "tacacs-plus" container (RFC 9950 §2).
type Config struct {
	// Servers is the unified, user-ordered list of TACACS+ servers. Order is
	// the failover/priority order (RFC 9950 §2.4, ordered-by user).
	Servers []Server `yaml:"server" json:"server"`
	// ClientCredentials is the optional registry of globally-referenced client
	// identity credentials (RFC 9950 §2.2, feature credential-reference).
	ClientCredentials []ClientCredential `yaml:"client-credentials,omitempty" json:"client-credentials,omitempty"`
	// ServerCredentials is the optional registry of globally-referenced
	// server-auth credentials (RFC 9950 §2.3, feature credential-reference).
	ServerCredentials []ServerCredential `yaml:"server-credentials,omitempty" json:"server-credentials,omitempty"`
}

// Server is a single TACACS+ server entry (RFC 9950 §2.4).
type Server struct {
	// Name is the unique server name (key), distinct from domain-name.
	Name string `yaml:"name" json:"name"`
	// ServerType selects which AAA services this server provides, as a
	// combination of "authentication", "authorization", "accounting". It is
	// populated from RawServerType during loading.
	ServerType ServerType `yaml:"-" json:"-"`
	// RawServerType holds the raw server-type value (a string or list of
	// strings) from the configuration file, decoded into ServerType bits
	// during loading.
	RawServerType any `yaml:"server-type" json:"server-type"`
	// DomainName is the server domain name used for TLS SNI (RFC 9887 §3.4.2),
	// distinct from the transport address.
	DomainName string `yaml:"domain-name,omitempty" json:"domain-name,omitempty"`
	// SNIEnabled enables/disables SNI. Requires DomainName.
	SNIEnabled bool `yaml:"sni-enabled,omitempty" json:"sni-enabled,omitempty"`
	// Address is the IP address or hostname of the server.
	Address string `yaml:"address" json:"address"`
	// Port is the server port. Mandatory with no default; 49 for legacy
	// TACACS+ and 300 for TACACS+ over TLS (RFC 9887 §5.2).
	Port uint16 `yaml:"port" json:"port"`
	// Security is the security choice (TLS or shared-secret obfuscation).
	Security Security `yaml:"security" json:"security"`
	// Source is the optional source selection (source-ip or source-interface).
	Source Source `yaml:"source,omitempty" json:"source,omitempty"`
	// VRFInstance is the optional VRF/VPN instance name.
	VRFInstance string `yaml:"vrf-instance,omitempty" json:"vrf-instance,omitempty"`
	// SingleConnection enables Single Connection Mode (RFC 8907 §4.3).
	SingleConnection bool `yaml:"single-connection,omitempty" json:"single-connection,omitempty"`
	// Timeout is the seconds to wait per server before trying the next
	// (default 5, range 1..max).
	Timeout uint16 `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// ServerType is the bits field selecting AAA services (RFC 9950 §2.4).
type ServerType uint8

// ServerType bits.
const (
	ServerTypeAuthentication ServerType = 1 << iota
	ServerTypeAuthorization
	ServerTypeAccounting
)

// String returns the set bits as a comma-separated string.
func (s ServerType) String() string {
	var parts []string
	if s&ServerTypeAuthentication != 0 {
		parts = append(parts, "authentication")
	}
	if s&ServerTypeAuthorization != 0 {
		parts = append(parts, "authorization")
	}
	if s&ServerTypeAccounting != 0 {
		parts = append(parts, "accounting")
	}
	return strings.Join(parts, ",")
}

// Security is the tagged union for the server security choice (RFC 9950 §2.4):
// either TLS or legacy shared-secret obfuscation.
type Security struct {
	// TLS, when non-nil, selects TACACS+ over TLS 1.3 (RFC 9887).
	TLS *TLSClient `yaml:"tls,omitempty" json:"tls,omitempty"`
	// SharedSecret selects legacy MD5 obfuscation. Deprecated in favor of TLS.
	// It is treated as sensitive and MUST NOT be logged in cleartext.
	SharedSecret *string `yaml:"shared-secret,omitempty" json:"shared-secret,omitempty"`
}

// IsTLS reports whether the security choice is TLS.
func (s Security) IsTLS() bool { return s.TLS != nil }

// Source is the tagged union for the source selection choice.
type Source struct {
	// SourceIP is the source IP address.
	SourceIP *string `yaml:"source-ip,omitempty" json:"source-ip,omitempty"`
	// SourceInterface is the interface whose IP is used as source.
	SourceInterface *string `yaml:"source-interface,omitempty" json:"source-interface,omitempty"`
}
