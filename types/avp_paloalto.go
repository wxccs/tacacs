// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

// Palo Alto Networks (PAN-OS) vendor-specific TACACS+ AV pairs. PAN-OS
// requests authorization for firewall and Panorama administrators; the
// TACACS+ server returns these attributes in the authorization REPLY to
// assign the administrator role, access domain and user group. The names
// and semantics below are drawn from the PAN-OS Administrator's Guide,
// "Configure TACACS+ Authentication" > "TACACS+ attributes and VSAs" table.
//
// Source: PAN-OS® Administrator's Guide (NGFW Administration),
// https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/pdf/ngfw/ngfw-administration.pdf
//
// Two standard AV pairs carry Palo Alto vendor identification and MUST be
// present in the REPLY: service=PaloAlto and protocol=firewall. The
// PaloAlto-* pairs are returned alongside them. PAN-OS maps them to
// administrator roles, access domains, user groups and virtual systems
// configured on the firewall or Panorama. When predefining dynamic
// administrator roles, use lower-case (e.g. superuser, not SuperUser).

// PaloAltoService is the value of the service AVP that identifies the
// authorization profile as specific to Palo Alto Networks. PAN-OS requires
// the value "PaloAlto".
const PaloAltoService = "PaloAlto"

// PaloAltoProtocol is the value of the protocol AVP that identifies the
// device type. PAN-OS requires the value "firewall".
const PaloAltoProtocol = "firewall"

// Palo Alto-specific AV pair names (PAN-OS TACACS+ VSA table).
const (
	// ArgNamePaloAltoAdminRole is a default (dynamic) administrative role
	// name or a custom administrative role name on the firewall.
	ArgNamePaloAltoAdminRole ArgName = "PaloAlto-Admin-Role"
	// ArgNamePaloAltoAdminAccessDomain is the name of an access domain for
	// firewall administrators (Device > Access Domains). Define it when the
	// firewall has multiple virtual systems.
	ArgNamePaloAltoAdminAccessDomain ArgName = "PaloAlto-Admin-Access-Domain"
	// ArgNamePaloAltoPanoramaAdminRole is a default (dynamic) administrative
	// role name or a custom administrative role name on Panorama.
	ArgNamePaloAltoPanoramaAdminRole ArgName = "PaloAlto-Panorama-Admin-Role"
	// ArgNamePaloAltoPanoramaAdminAccessDomain is the name of an access
	// domain for Device Group and Template administrators on Panorama
	// (Panorama > Access Domains).
	ArgNamePaloAltoPanoramaAdminAccessDomain ArgName = "PaloAlto-Panorama-Admin-Access-Domain"
	// ArgNamePaloAltoUserGroup is the name of a user group in the Allow
	// List of an authentication profile.
	ArgNamePaloAltoUserGroup ArgName = "PaloAlto-User-Group"
)

// PaloAltoServiceArg builds the mandatory service=PaloAlto AV pair that
// identifies the VSAs as specific to Palo Alto Networks. PAN-OS requires
// this attribute to be present in the authorization REPLY.
func PaloAltoServiceArg() Argument {
	return NewMandatoryArg(ArgNameService, PaloAltoService)
}

// PaloAltoProtocolArg builds the mandatory protocol=firewall AV pair that
// identifies the device type. PAN-OS requires this attribute to be present.
func PaloAltoProtocolArg() Argument {
	return NewMandatoryArg(ArgNameProtocol, PaloAltoProtocol)
}

// PaloAltoAdminRoleArg builds the PaloAlto-Admin-Role=<role> AV pair,
// assigning a default (dynamic) or custom administrative role on the
// firewall.
func PaloAltoAdminRoleArg(role string, mandatory bool) Argument {
	return NewArg(ArgNamePaloAltoAdminRole, role, mandatory)
}

// PaloAltoAdminAccessDomainArg builds the
// PaloAlto-Admin-Access-Domain=<domain> AV pair, assigning an access domain
// to a firewall administrator. Define it when the firewall has multiple
// virtual systems.
func PaloAltoAdminAccessDomainArg(domain string, mandatory bool) Argument {
	return NewArg(ArgNamePaloAltoAdminAccessDomain, domain, mandatory)
}

// PaloAltoPanoramaAdminRoleArg builds the
// PaloAlto-Panorama-Admin-Role=<role> AV pair, assigning a default (dynamic)
// or custom administrative role on Panorama.
func PaloAltoPanoramaAdminRoleArg(role string, mandatory bool) Argument {
	return NewArg(ArgNamePaloAltoPanoramaAdminRole, role, mandatory)
}

// PaloAltoPanoramaAdminAccessDomainArg builds the
// PaloAlto-Panorama-Admin-Access-Domain=<domain> AV pair, assigning an
// access domain to a Device Group or Template administrator on Panorama.
func PaloAltoPanoramaAdminAccessDomainArg(domain string, mandatory bool) Argument {
	return NewArg(ArgNamePaloAltoPanoramaAdminAccessDomain, domain, mandatory)
}

// PaloAltoUserGroupArg builds the PaloAlto-User-Group=<group> AV pair,
// naming a user group in the Allow List of an authentication profile.
func PaloAltoUserGroupArg(group string, mandatory bool) Argument {
	return NewArg(ArgNamePaloAltoUserGroup, group, mandatory)
}
