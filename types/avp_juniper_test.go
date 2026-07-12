// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	tacerrs "github.com/wxccs/tacacs/errors"
)

// TestJuniperArgNames asserts every predefined Juniper AVP name constant
// carries the exact wire string Junos expects, so a typo cannot silently
// break interop. Source: "Juniper Networks Vendor-Specific TACACS+
// Attributes", Table 1, plus the refresh-time-interval attribute from the
// periodic-refresh section.
func TestJuniperArgNames(t *testing.T) {
	cases := []struct {
		name  ArgName
		value string
	}{
		{ArgNameLocalUserName, "local-user-name"},
		{ArgNameAllowCommands, "allow-commands"},
		{ArgNameAllowCommandsRegexps, "allow-commands-regexps"},
		{ArgNameAllowConfiguration, "allow-configuration"},
		{ArgNameAllowConfigurationRegexps, "allow-configuration-regexps"},
		{ArgNameDenyCommands, "deny-commands"},
		{ArgNameDenyCommandsRegexps, "deny-commands-regexps"},
		{ArgNameDenyConfiguration, "deny-configuration"},
		{ArgNameDenyConfigurationRegexps, "deny-configuration-regexps"},
		{ArgNameUserPermissions, "user-permissions"},
		{ArgNameAuthenticationType, "authentication-type"},
		{ArgNameSessionPort, "session-port"},
		{ArgNameRefreshTimeInterval, "refresh-time-interval"},
	}
	assert.Equal(t, 13, len(cases), "expected 13 Juniper AVP name constants")
	for _, c := range cases {
		assert.Equalf(t, c.value, string(c.name), "constant %q has wrong value", c.value)
	}
}

func TestJunosExecServiceValue(t *testing.T) {
	assert.Equal(t, "junos-exec", JunosExecService)
}

func TestJuniperAuthTypeValues(t *testing.T) {
	assert.Equal(t, "local", JuniperAuthTypeLocal)
	assert.Equal(t, "remote", JuniperAuthTypeRemote)
}

func TestJunosExecServiceArg(t *testing.T) {
	got := JunosExecServiceArg()
	assert.True(t, got.Mandatory)
	assert.Equal(t, "service", got.Name)
	assert.Equal(t, "junos-exec", got.Value)
	assert.Equal(t, "service=junos-exec", got.String())
}

func TestNewJuniperNumberedArg(t *testing.T) {
	got, err := NewJuniperNumberedArg(ArgNameAllowCommands, 1, "(test)|(ping)", true)
	assert.NoError(t, err)
	assert.Equal(t, "allow-commands1", got.Name)
	assert.Equal(t, "allow-commands1=(test)|(ping)", got.String())

	// Optional separator and non-sequential numbering are both valid per the
	// Junos doc ("numeric values 1 through n must be unique but need not be
	// sequential").
	opt, err := NewJuniperNumberedArg(ArgNameDenyCommands, 3, "(request)", false)
	assert.NoError(t, err)
	assert.Equal(t, "deny-commands3*(request)", opt.String())
}

func TestNewJuniperNumberedArgErrors(t *testing.T) {
	_, err := NewJuniperNumberedArg(ArgNameAllowCommands, 0, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	_, err = NewJuniperNumberedArg(ArgNameAllowCommands, -1, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	// A name already ending in a digit is rejected so the suffix is
	// unambiguous (e.g. "foo2" + 3 -> "foo23").
	_, err = NewJuniperNumberedArg("allow-commands2", 3, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestJuniperNumberedWrappers(t *testing.T) {
	got, err := AllowCommandsNumberedArg(1, "(ping)", true)
	assert.NoError(t, err)
	assert.Equal(t, "allow-commands1=(ping)", got.String())

	got, err = DenyCommandsNumberedArg(2, "(commit)", true)
	assert.NoError(t, err)
	assert.Equal(t, "deny-commands2=(commit)", got.String())

	got, err = AllowConfigurationNumberedArg(1, "(groups re0)", false)
	assert.NoError(t, err)
	assert.Equal(t, "allow-configuration1*(groups re0)", got.String())

	got, err = DenyConfigurationNumberedArg(1, "(system accounting)", true)
	assert.NoError(t, err)
	assert.Equal(t, "deny-configuration1=(system accounting)", got.String())

	got, err = UserPermissionsNumberedArg(1, "interface", true)
	assert.NoError(t, err)
	assert.Equal(t, "user-permissions1=interface", got.String())

	// Wrappers propagate the index validation error.
	_, err = AllowCommandsNumberedArg(0, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestSessionPortArg(t *testing.T) {
	got := SessionPortArg(49152, true)
	assert.Equal(t, "session-port", got.Name)
	assert.Equal(t, "49152", got.Value)
	assert.Equal(t, "session-port=49152", got.String())

	opt := SessionPortArg(0, false)
	assert.Equal(t, "session-port*0", opt.String())
}
