// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscCauseValues(t *testing.T) {
	cases := []struct {
		v   DiscCause
		s   string
		val uint16
	}{
		{DiscCauseUserRequest, "user-request", 1},
		{DiscCauseDataLost, "data-lost", 2},
		{DiscCauseServiceLost, "service-lost", 3},
		{DiscCauseIdleTimeout, "idle-timeout", 4},
		{DiscCauseSessionTimeout, "session-timeout", 5},
		{DiscCauseAdminRequest, "admin-request", 7},
		{DiscCauseNasError, "nas-error", 9},
		{DiscCauseNasRequest, "nas-request", 10},
		{DiscCausePortDisabled, "port-disabled", 12},
		{DiscCauseUserError, "user-error", 17},
		{DiscCauseHostRequest, "host-request", 18},
	}
	for _, c := range cases {
		assert.Equalf(t, c.val, uint16(c.v), "DiscCause %q wrong value", c.s)
		assert.Equalf(t, c.s, c.v.String(), "DiscCause(%d).String()", c.val)
	}
}

func TestDiscCauseExtValues(t *testing.T) {
	// Covers every Cisco Table 3 code (1000-1068) plus the Huawei-only 1100.
	cases := []struct {
		v   DiscCauseExt
		s   string
		val uint16
	}{
		{DiscCauseExtNoReason, "no-reason", 1000},
		{DiscCauseExtNoDisconnect, "no-disconnect", 1001},
		{DiscCauseExtUnknown, "unknown", 1002},
		{DiscCauseExtCallDisconnect, "call-disconnect", 1003},
		{DiscCauseExtCLIDAuthFail, "clid-auth-fail", 1004},
		{DiscCauseExtNoModemAvailable, "no-modem-available", 1009},
		{DiscCauseExtNoCarrier, "no-carrier", 1010},
		{DiscCauseExtLostCarrier, "lost-carrier", 1011},
		{DiscCauseExtNoModemResults, "no-modem-results", 1012},
		{DiscCauseExtTSUserExit, "ts-user-exit", 1020},
		{DiscCauseExtIdleTimeout, "idle-timeout", 1021},
		{DiscCauseExtTSExitTelnet, "ts-exit-telnet", 1022},
		{DiscCauseExtTSNoIPAddr, "ts-no-ip-addr", 1023},
		{DiscCauseExtTSTCPRawExit, "ts-tcp-raw-exit", 1024},
		{DiscCauseExtTSBadPassword, "ts-bad-password", 1025},
		{DiscCauseExtTSNoTCPRaw, "ts-no-tcp-raw", 1026},
		{DiscCauseExtTSCNTLC, "ts-cntl-c", 1027},
		{DiscCauseExtTSSessionEnd, "ts-session-end", 1028},
		{DiscCauseExtTSCloseVconn, "ts-close-vconn", 1029},
		{DiscCauseExtTSEndVconn, "ts-end-vconn", 1030},
		{DiscCauseExtTSRloginExit, "ts-rlogin-exit", 1031},
		{DiscCauseExtTSRloginOptInvalid, "ts-rlogin-opt-invalid", 1032},
		{DiscCauseExtTSInsuffResources, "ts-insuff-resources", 1033},
		{DiscCauseExtPPPLCPTimeout, "ppp-lcp-timeout", 1040},
		{DiscCauseExtPPPLCPFail, "ppp-lcp-fail", 1041},
		{DiscCauseExtPPPPapFail, "ppp-pap-fail", 1042},
		{DiscCauseExtPPPCHAPFail, "ppp-chap-fail", 1043},
		{DiscCauseExtPPPRemoteFail, "ppp-remote-fail", 1044},
		{DiscCauseExtPPPReceiveTerm, "ppp-receive-term", 1045},
		{DiscCauseExtPPPNoNCP, "ppp-no-ncp", 1047},
		{DiscCauseExtPPPMPError, "ppp-mp-error", 1048},
		{DiscCauseExtPPPMaxChannels, "ppp-max-channels", 1049},
		{DiscCauseExtTSTablesFull, "ts-tables-full", 1050},
		{DiscCauseExtTSResourceFull, "ts-resource-full", 1051},
		{DiscCauseExtTSInvalidIPAddr, "ts-invalid-ip-addr", 1052},
		{DiscCauseExtTSBadHostname, "ts-bad-hostname", 1053},
		{DiscCauseExtTSBadPort, "ts-bad-port", 1054},
		{DiscCauseExtTCPReset, "tcp-reset", 1060},
		{DiscCauseExtTCPConnectionRefused, "tcp-connection-refused", 1061},
		{DiscCauseExtTCPTimeout, "tcp-timeout", 1062},
		{DiscCauseExtTCPForeignHostClose, "tcp-foreign-host-close", 1063},
		{DiscCauseExtTCPNetUnreachable, "tcp-net-unreachable", 1064},
		{DiscCauseExtTCPHostUnreachable, "tcp-host-unreachable", 1065},
		{DiscCauseExtTCPNetAdminUnreachable, "tcp-net-admin-unreachable", 1066},
		{DiscCauseExtTCPHostAdminUnreachable, "tcp-host-admin-unreachable", 1067},
		{DiscCauseExtTCPPortUnreachable, "tcp-port-unreachable", 1068},
		// Huawei-only: Cisco Table 3 has no 1046 or 1100 entry.
		{DiscCauseExtHWPPPAdminClose, "hw-ppp-admin-close", 1046},
		{DiscCauseExtHWSessionTimeout, "hw-session-timeout", 1100},
	}
	assert.Equal(t, 48, len(cases), "expected 48 disconnect-cause-ext codes")
	for _, c := range cases {
		assert.Equalf(t, c.val, uint16(c.v), "DiscCauseExt %q wrong value", c.s)
		assert.Equalf(t, c.s, c.v.String(), "DiscCauseExt(%d).String()", c.val)
	}
}

func TestDiscCauseUnknown(t *testing.T) {
	assert.Equal(t, "unknown(99)", DiscCause(99).String())
	assert.Equal(t, "unknown(9999)", DiscCauseExt(9999).String())
	// The zero value is not a defined code either.
	assert.Equal(t, "unknown(0)", DiscCause(0).String())
	assert.Equal(t, fmt.Sprintf("unknown(%d)", 5000), DiscCauseExt(5000).String())
}

func TestNewDiscCauseArg(t *testing.T) {
	got := NewDiscCauseArg(DiscCauseIdleTimeout, true)
	assert.Equal(t, "disc-cause=4", got.String())
	assert.Equal(t, "disc-cause", got.Name)
	assert.Equal(t, "4", got.Value)

	opt := NewDiscCauseArg(DiscCauseUserRequest, false)
	assert.Equal(t, "disc-cause*1", opt.String())
}

func TestNewDiscCauseExtArg(t *testing.T) {
	got := NewDiscCauseExtArg(DiscCauseExtTCPTimeout, true)
	assert.Equal(t, "disc-cause-ext=1062", got.String())
	assert.Equal(t, "disc-cause-ext", got.Name)

	// Huawei underscore spelling is produced via the generic constructor on the
	// underscore constant, so peers using Huawei naming are also supported.
	hw := NewMandatoryArg(ArgNameDiscCauseExtUnderscore, "1100")
	assert.Equal(t, "disc_cause_ext=1100", hw.String())
}
