// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPaloAltoArgNames asserts every predefined Palo Alto AVP name constant
// carries the exact wire string PAN-OS expects, so a typo cannot silently
// break interop. Source: PAN-OS Administrator's Guide, "TACACS+ attributes
// and VSAs" table.
func TestPaloAltoArgNames(t *testing.T) {
	cases := []struct {
		name  ArgName
		value string
	}{
		{ArgNamePaloAltoAdminRole, "PaloAlto-Admin-Role"},
		{ArgNamePaloAltoAdminAccessDomain, "PaloAlto-Admin-Access-Domain"},
		{ArgNamePaloAltoPanoramaAdminRole, "PaloAlto-Panorama-Admin-Role"},
		{ArgNamePaloAltoPanoramaAdminAccessDomain, "PaloAlto-Panorama-Admin-Access-Domain"},
		{ArgNamePaloAltoUserGroup, "PaloAlto-User-Group"},
	}
	assert.Equal(t, 5, len(cases), "expected 5 Palo Alto VSA name constants")
	for _, c := range cases {
		assert.Equalf(t, c.value, string(c.name), "constant %q has wrong value", c.value)
	}
}

func TestPaloAltoServiceValue(t *testing.T) {
	assert.Equal(t, "PaloAlto", PaloAltoService)
}

func TestPaloAltoProtocolValue(t *testing.T) {
	assert.Equal(t, "firewall", PaloAltoProtocol)
}

func TestPaloAltoServiceArg(t *testing.T) {
	got := PaloAltoServiceArg()
	assert.True(t, got.Mandatory)
	assert.Equal(t, "service", got.Name)
	assert.Equal(t, "PaloAlto", got.Value)
	assert.Equal(t, "service=PaloAlto", got.String())
}

func TestPaloAltoProtocolArg(t *testing.T) {
	got := PaloAltoProtocolArg()
	assert.True(t, got.Mandatory)
	assert.Equal(t, "protocol", got.Name)
	assert.Equal(t, "firewall", got.Value)
	assert.Equal(t, "protocol=firewall", got.String())
}

func TestPaloAltoVSAWrappers(t *testing.T) {
	got := PaloAltoAdminRoleArg("superuser", true)
	assert.True(t, got.Mandatory)
	assert.Equal(t, "PaloAlto-Admin-Role=superuser", got.String())

	// Optional separator is valid for the supplementary VSAs.
	got = PaloAltoAdminAccessDomainArg("ad1", false)
	assert.False(t, got.Mandatory)
	assert.Equal(t, "PaloAlto-Admin-Access-Domain*ad1", got.String())

	got = PaloAltoPanoramaAdminRoleArg("panorama-admin", true)
	assert.Equal(t, "PaloAlto-Panorama-Admin-Role=panorama-admin", got.String())

	got = PaloAltoPanoramaAdminAccessDomainArg("dg1", true)
	assert.Equal(t, "PaloAlto-Panorama-Admin-Access-Domain=dg1", got.String())

	got = PaloAltoUserGroupArg("netops", false)
	assert.Equal(t, "PaloAlto-User-Group*netops", got.String())
}
