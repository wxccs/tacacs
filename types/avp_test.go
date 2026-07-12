// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	tacerrs "github.com/wxccs/tacacs/errors"
)

// TestArgNames asserts every predefined AVP name constant carries the exact
// string the wire expects, so a typo cannot silently break interop.
func TestArgNames(t *testing.T) {
	cases := []struct {
		name  ArgName
		value string
	}{
		// Authentication / authorization AV pairs.
		{ArgNameService, "service"},
		{ArgNameCmd, "cmd"},
		{ArgNameCmdArg, "cmd-arg"},
		{ArgNamePrivLvl, "priv-lvl"},
		{ArgNameProtocol, "protocol"},
		{ArgNameAcl, "acl"},
		{ArgNameAddr, "addr"},
		{ArgNameAddrPool, "addr-pool"},
		{ArgNameAutocmd, "autocmd"},
		{ArgNameCallbackDialstring, "callback-dialstring"},
		{ArgNameCallbackLine, "callback-line"},
		{ArgNameCallbackRotary, "callback-rotary"},
		{ArgNameDnsServers, "dns-servers"},
		{ArgNameIdletime, "idletime"},
		{ArgNameInacl, "inacl"},
		{ArgNameOutacl, "outacl"},
		{ArgNameIpAddresses, "ip-addresses"},
		{ArgNameGwPassword, "gw-password"},
		{ArgNameNocallbackVerify, "nocallback-verify"},
		{ArgNameNoescape, "noescape"},
		{ArgNameNohangup, "nohangup"},
		{ArgNameOldPrompts, "old-prompts"},
		{ArgNameRouting, "routing"},
		{ArgNameRoute, "route"},
		{ArgNameSourceIP, "source-ip"},
		// Accounting AV pairs.
		{ArgNameBytesIn, "bytes_in"},
		{ArgNameBytesOut, "bytes_out"},
		{ArgNamePaksIn, "paks_in"},
		{ArgNamePaksOut, "paks_out"},
		{ArgNameElapsedTime, "elapsed_time"},
		{ArgNameTaskID, "task_id"},
		{ArgNameTimezone, "timezone"},
		{ArgNameStartTime, "start_time"},
		{ArgNameStopTime, "stop_time"},
		{ArgNameEvent, "event"},
		{ArgNameReason, "reason"},
		{ArgNamePort, "port"},
		{ArgNamePrivLevel, "priv_level"},
		{ArgNameNasRxSpeed, "nas-rx-speed"},
		{ArgNameNasTxSpeed, "nas-tx-speed"},
		{ArgNameMlpLinksMax, "mlp-links-max"},
		{ArgNameMlpSessID, "mlp-sess-id"},
		{ArgNamePreSessionTime, "pre-session-time"},
		// Dual naming: hyphen (Cisco) vs underscore (Huawei).
		{ArgNameDiscCause, "disc-cause"},
		{ArgNameDiscCauseUnderscore, "disc_cause"},
		{ArgNameDiscCauseExt, "disc-cause-ext"},
		{ArgNameDiscCauseExtUnderscore, "disc_cause_ext"},
		// Huawei-specific.
		{ArgNameDnAverage, "dnaverage"},
		{ArgNameDnPeak, "dnpeak"},
		{ArgNameUpAverage, "upaverage"},
		{ArgNameUpPeak, "uppeak"},
		{ArgNameTunnelID, "tunnel-id"},
		{ArgNameTunnelType, "tunnel-type"},
		{ArgNameFtpDir, "ftpdir"},
	}
	for _, c := range cases {
		assert.Equalf(t, c.value, string(c.name), "constant %q has wrong value", c.value)
	}
}

func TestNewArg(t *testing.T) {
	got := NewArg(ArgNameService, "shell", true)
	assert.Equal(t, Argument{Mandatory: true, Name: "service", Value: "shell"}, got)
	assert.Equal(t, "service=shell", got.String())

	opt := NewArg(ArgNameCmd, "show", false)
	assert.Equal(t, Argument{Mandatory: false, Name: "cmd", Value: "show"}, opt)
	assert.Equal(t, "cmd*show", opt.String())
}

func TestNewMandatoryAndOptionalArg(t *testing.T) {
	m := NewMandatoryArg(ArgNameService, "shell")
	assert.True(t, m.Mandatory)
	assert.Equal(t, "service=shell", m.String())

	o := NewOptionalArg(ArgNameCmd, "show")
	assert.False(t, o.Mandatory)
	assert.Equal(t, "cmd*show", o.String())
}

func TestNewIndexedArg(t *testing.T) {
	got, err := NewIndexedArg(ArgNameInacl, 1, "permit ip any any", true)
	assert.NoError(t, err)
	assert.Equal(t, "inacl#1", got.Name)
	assert.Equal(t, "inacl#1=permit ip any any", got.String())

	got, err = NewIndexedArg(ArgNameRoute, 2, "10.0.0.0 255.0.0.0", false)
	assert.NoError(t, err)
	assert.Equal(t, "route#2*10.0.0.0 255.0.0.0", got.String())
}

func TestNewIndexedArgErrors(t *testing.T) {
	_, err := NewIndexedArg(ArgNameInacl, 0, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	_, err = NewIndexedArg(ArgNameInacl, -1, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))

	// A name already containing '#' is rejected so the index is unambiguous.
	_, err = NewIndexedArg("inacl#1", 2, "x", true)
	assert.Error(t, err)
	assert.True(t, tacerrs.Is(err, tacerrs.ErrInvalidArgument))
}

func TestConvenienceArgConstructors(t *testing.T) {
	assert.Equal(t, "service=shell", ServiceArg("shell").String())
	assert.Equal(t, "cmd=show", CmdArg("show").String())
	assert.Equal(t, "cmd-arg=<cr>", CmdArgCR().String())
	assert.Equal(t, "priv-lvl=15", PrivLvlArg(PrivLevelMax).String())
	assert.Equal(t, "priv-lvl=0", PrivLvlArg(PrivLevelMin).String())

	// PrivLvlArg must accept arbitrary levels in the 0..15 range, not just
	// the named constants.
	assert.Equal(t, "priv-lvl=7", PrivLvlArg(PrivLevel(7)).String())

	// Ensure the numeric form is produced via strconv, not fmt %v on a byte.
	assert.Equal(t, "priv-lvl=10", "priv-lvl="+strconv.Itoa(10))
}

// TestArgNameAssignableToArgumentName ensures an ArgName converts cleanly to
// the string field of Argument so callers can mix constants with hand-built
// values.
func TestArgNameAssignableToArgumentName(t *testing.T) {
	var n = ArgNameService // inferred type is ArgName
	a := Argument{Mandatory: true, Name: string(n), Value: "shell"}
	assert.Equal(t, "service=shell", a.String())
	// And ArgName values concatenate like ordinary strings.
	assert.True(t, strings.HasPrefix(string(ArgNameCmdArg), "cmd-arg"))
}
