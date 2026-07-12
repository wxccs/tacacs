// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"strconv"

	"github.com/wxccs/tacacs/errors"
)

// Juniper (Junos OS) vendor-specific TACACS+ AV pairs. Junos carries these
// inside a service=junos-exec authorization profile, returned in the
// authorization REPLY after a user is authenticated. The names and semantics
// below are drawn from the Junos "User Access > TACACS+ Authentication"
// documentation, section "Juniper Networks Vendor-Specific TACACS+
// Attributes" (Table 1), plus the refresh-time-interval attribute defined in
// the periodic-refresh section.
//
// Source: https://www.juniper.net/documentation/us/en/software/junos/
// user-access/topics/topic-map/user-access-tacacs-authentication.html
//
// Numbered form: five of these attributes (allow-commands, deny-commands,
// allow-configuration, deny-configuration, user-permissions) may each be
// repeated with a direct numeric suffix, e.g. allow-commands1, allow-commands2.
// Unlike Cisco's indexed form "name#<n>" (see NewIndexedArg), Juniper appends
// the index with no separator, so use NewJuniperNumberedArg to build them. The
// numeric values 1..n must be unique but need not be sequential.

// JunosExecService is the value of the service AVP that selects the Junos
// exec authorization profile (analogous to Cisco's "shell"). Juniper
// attributes such as local-user-name and allow-commands are carried inside
// this profile.
const JunosExecService = "junos-exec"

// Juniper-specific AV pair names (Junos Table 1 + refresh-time-interval).
const (
	ArgNameLocalUserName             ArgName = "local-user-name"
	ArgNameAllowCommands             ArgName = "allow-commands"
	ArgNameAllowCommandsRegexps      ArgName = "allow-commands-regexps"
	ArgNameAllowConfiguration        ArgName = "allow-configuration"
	ArgNameAllowConfigurationRegexps ArgName = "allow-configuration-regexps"
	ArgNameDenyCommands              ArgName = "deny-commands"
	ArgNameDenyCommandsRegexps       ArgName = "deny-commands-regexps"
	ArgNameDenyConfiguration         ArgName = "deny-configuration"
	ArgNameDenyConfigurationRegexps  ArgName = "deny-configuration-regexps"
	ArgNameUserPermissions           ArgName = "user-permissions"
	ArgNameAuthenticationType        ArgName = "authentication-type"
	ArgNameSessionPort               ArgName = "session-port"
	ArgNameRefreshTimeInterval       ArgName = "refresh-time-interval"
)

// Values of the authentication-type AV pair: the method used to authenticate
// the user, as reported back by the device.
const (
	JuniperAuthTypeLocal  = "local"
	JuniperAuthTypeRemote = "remote"
)

// JunosExecServiceArg builds the mandatory service=junos-exec AV pair that
// opens the Junos exec authorization profile. Juniper-specific attributes are
// returned alongside it in the authorization REPLY.
func JunosExecServiceArg() Argument {
	return NewMandatoryArg(ArgNameService, JunosExecService)
}

// NewJuniperNumberedArg builds an Argument whose name carries a numeric suffix
// of the form "name<n>" (e.g. allow-commands1, deny-commands3), the Juniper
// numbered form used to repeat an attribute with distinct values. It returns
// ErrInvalidArgument if n is not positive or if name already ends in a digit,
// which would make the suffix ambiguous (e.g. "foo2" + 3 -> "foo23").
func NewJuniperNumberedArg(name ArgName, n int, value string, mandatory bool) (Argument, error) {
	if n <= 0 {
		return Argument{}, errors.NewValidationError("arg_index", "must be > 0", errors.ErrInvalidArgument)
	}
	ns := string(name)
	if l := len(ns); l > 0 {
		if c := ns[l-1]; c >= '0' && c <= '9' {
			return Argument{}, errors.NewValidationError("arg_name", "ends in digit, index ambiguous", errors.ErrInvalidArgument)
		}
	}
	return Argument{Mandatory: mandatory, Name: ns + strconv.Itoa(n), Value: value}, nil
}

// AllowCommandsNumberedArg builds the numbered allow-commands<n>=<regex> AV
// pair, granting command execution beyond the login class permission bits.
func AllowCommandsNumberedArg(n int, value string, mandatory bool) (Argument, error) {
	return NewJuniperNumberedArg(ArgNameAllowCommands, n, value, mandatory)
}

// DenyCommandsNumberedArg builds the numbered deny-commands<n>=<regex> AV pair,
// denying command execution otherwise allowed by the login class permission
// bits.
func DenyCommandsNumberedArg(n int, value string, mandatory bool) (Argument, error) {
	return NewJuniperNumberedArg(ArgNameDenyCommands, n, value, mandatory)
}

// AllowConfigurationNumberedArg builds the numbered
// allow-configuration<n>=<regex> AV pair, granting view/modify access to
// configuration statements beyond the login class permission bits.
func AllowConfigurationNumberedArg(n int, value string, mandatory bool) (Argument, error) {
	return NewJuniperNumberedArg(ArgNameAllowConfiguration, n, value, mandatory)
}

// DenyConfigurationNumberedArg builds the numbered
// deny-configuration<n>=<regex> AV pair, denying view/modify access to
// configuration statements otherwise allowed by the login class permission
// bits.
func DenyConfigurationNumberedArg(n int, value string, mandatory bool) (Argument, error) {
	return NewJuniperNumberedArg(ArgNameDenyConfiguration, n, value, mandatory)
}

// UserPermissionsNumberedArg builds the numbered
// user-permissions<n>=<flags> AV pair, granting a permission flag set in
// addition to the login class permissions.
func UserPermissionsNumberedArg(n int, value string, mandatory bool) (Argument, error) {
	return NewJuniperNumberedArg(ArgNameUserPermissions, n, value, mandatory)
}

// SessionPortArg builds the session-port=<n> AV pair from a port number.
// session-port carries the source port of the established session (an integer
// value).
func SessionPortArg(port int, mandatory bool) Argument {
	return Argument{Mandatory: mandatory, Name: string(ArgNameSessionPort), Value: strconv.Itoa(port)}
}
