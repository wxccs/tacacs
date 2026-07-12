// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"fmt"
	"strconv"
)

// DiscCause is the value of the disc-cause accounting AV pair: the reason a
// connection was taken off-line (RFC 8907 §7, accounting-stop records). The
// numeric codes below are the common base shared by Cisco and Huawei
// implementations (see the Huawei HWTACACS attribute table).
type DiscCause uint16

// Disconnect causes.
const (
	DiscCauseUserRequest    DiscCause = 1
	DiscCauseDataLost       DiscCause = 2
	DiscCauseServiceLost    DiscCause = 3
	DiscCauseIdleTimeout    DiscCause = 4
	DiscCauseSessionTimeout DiscCause = 5
	DiscCauseAdminRequest   DiscCause = 7
	DiscCauseNasError       DiscCause = 9
	DiscCauseNasRequest     DiscCause = 10
	DiscCausePortDisabled   DiscCause = 12
	DiscCauseUserError      DiscCause = 17
	DiscCauseHostRequest    DiscCause = 18
)

// String returns a hyphenated name for the disconnect cause, or
// "unknown(<n>)" for values outside the defined set.
func (d DiscCause) String() string {
	switch d {
	case DiscCauseUserRequest:
		return "user-request"
	case DiscCauseDataLost:
		return "data-lost"
	case DiscCauseServiceLost:
		return "service-lost"
	case DiscCauseIdleTimeout:
		return "idle-timeout"
	case DiscCauseSessionTimeout:
		return "session-timeout"
	case DiscCauseAdminRequest:
		return "admin-request"
	case DiscCauseNasError:
		return "nas-error"
	case DiscCauseNasRequest:
		return "nas-request"
	case DiscCausePortDisabled:
		return "port-disabled"
	case DiscCauseUserError:
		return "user-error"
	case DiscCauseHostRequest:
		return "host-request"
	default:
		return fmt.Sprintf("unknown(%d)", int(d))
	}
}

// DiscCauseExt is the value of the disc-cause-ext accounting AV pair, which
// extends disc-cause with vendor-specific reasons (Cisco Table 3, "Disconnect
// Cause Extensions"). Codes 1000-1068 mirror the Cisco table; the
// Huawei-only 1046 and 1100 are suffixed "HW". Note: Huawei assigns a
// different meaning to 1063 ("PPP handshake failure") than Cisco's
// "tcp-foreign-host-close"; the Cisco meaning is used here.
type DiscCauseExt uint16

// Disconnect cause extensions (Cisco Table 3).
const (
	DiscCauseExtNoReason           DiscCauseExt = 1000
	DiscCauseExtNoDisconnect       DiscCauseExt = 1001
	DiscCauseExtUnknown            DiscCauseExt = 1002
	DiscCauseExtCallDisconnect     DiscCauseExt = 1003
	DiscCauseExtCLIDAuthFail       DiscCauseExt = 1004
	DiscCauseExtNoModemAvailable   DiscCauseExt = 1009
	DiscCauseExtNoCarrier          DiscCauseExt = 1010
	DiscCauseExtLostCarrier        DiscCauseExt = 1011
	DiscCauseExtNoModemResults     DiscCauseExt = 1012
	DiscCauseExtTSUserExit         DiscCauseExt = 1020
	DiscCauseExtIdleTimeout        DiscCauseExt = 1021
	DiscCauseExtTSExitTelnet       DiscCauseExt = 1022
	DiscCauseExtTSNoIPAddr         DiscCauseExt = 1023
	DiscCauseExtTSTCPRawExit       DiscCauseExt = 1024
	DiscCauseExtTSBadPassword      DiscCauseExt = 1025
	DiscCauseExtTSNoTCPRaw         DiscCauseExt = 1026
	DiscCauseExtTSCNTLC            DiscCauseExt = 1027
	DiscCauseExtTSSessionEnd       DiscCauseExt = 1028
	DiscCauseExtTSCloseVconn       DiscCauseExt = 1029
	DiscCauseExtTSEndVconn         DiscCauseExt = 1030
	DiscCauseExtTSRloginExit       DiscCauseExt = 1031
	DiscCauseExtTSRloginOptInvalid DiscCauseExt = 1032
	DiscCauseExtTSInsuffResources  DiscCauseExt = 1033
	DiscCauseExtPPPLCPTimeout      DiscCauseExt = 1040
	DiscCauseExtPPPLCPFail         DiscCauseExt = 1041
	DiscCauseExtPPPPapFail         DiscCauseExt = 1042
	DiscCauseExtPPPCHAPFail        DiscCauseExt = 1043
	DiscCauseExtPPPRemoteFail      DiscCauseExt = 1044
	DiscCauseExtPPPReceiveTerm     DiscCauseExt = 1045
	// DiscCauseExtHWPPPAdminClose (1046) is Huawei-only: the upper layer
	// requested the PPP connection be closed. Cisco Table 3 skips 1046.
	DiscCauseExtHWPPPAdminClose      DiscCauseExt = 1046
	DiscCauseExtPPPNoNCP             DiscCauseExt = 1047
	DiscCauseExtPPPMPError           DiscCauseExt = 1048
	DiscCauseExtPPPMaxChannels       DiscCauseExt = 1049
	DiscCauseExtTSTablesFull         DiscCauseExt = 1050
	DiscCauseExtTSResourceFull       DiscCauseExt = 1051
	DiscCauseExtTSInvalidIPAddr      DiscCauseExt = 1052
	DiscCauseExtTSBadHostname        DiscCauseExt = 1053
	DiscCauseExtTSBadPort            DiscCauseExt = 1054
	DiscCauseExtTCPReset             DiscCauseExt = 1060
	DiscCauseExtTCPConnectionRefused DiscCauseExt = 1061
	DiscCauseExtTCPTimeout           DiscCauseExt = 1062
	// DiscCauseExtTCPForeignHostClose (1063) is "tcp-foreign-host-close" per
	// Cisco Table 3. Huawei documents 1063 as "PPP handshake failure"; the
	// Cisco meaning is used here. Callers interoperating with Huawei should
	// treat 1063 as peer-defined.
	DiscCauseExtTCPForeignHostClose     DiscCauseExt = 1063
	DiscCauseExtTCPNetUnreachable       DiscCauseExt = 1064
	DiscCauseExtTCPHostUnreachable      DiscCauseExt = 1065
	DiscCauseExtTCPNetAdminUnreachable  DiscCauseExt = 1066
	DiscCauseExtTCPHostAdminUnreachable DiscCauseExt = 1067
	DiscCauseExtTCPPortUnreachable      DiscCauseExt = 1068
	// DiscCauseExtHWSessionTimeout (1100) is Huawei-only: session timeout.
	// Cisco Table 3 has no 1100 entry.
	DiscCauseExtHWSessionTimeout DiscCauseExt = 1100
)

// String returns a hyphenated name for the disconnect-cause extension, or
// "unknown(<n>)" for values outside the defined set.
func (d DiscCauseExt) String() string {
	switch d {
	case DiscCauseExtNoReason:
		return "no-reason"
	case DiscCauseExtNoDisconnect:
		return "no-disconnect"
	case DiscCauseExtUnknown:
		return "unknown"
	case DiscCauseExtCallDisconnect:
		return "call-disconnect"
	case DiscCauseExtCLIDAuthFail:
		return "clid-auth-fail"
	case DiscCauseExtNoModemAvailable:
		return "no-modem-available"
	case DiscCauseExtNoCarrier:
		return "no-carrier"
	case DiscCauseExtLostCarrier:
		return "lost-carrier"
	case DiscCauseExtNoModemResults:
		return "no-modem-results"
	case DiscCauseExtTSUserExit:
		return "ts-user-exit"
	case DiscCauseExtIdleTimeout:
		return "idle-timeout"
	case DiscCauseExtTSExitTelnet:
		return "ts-exit-telnet"
	case DiscCauseExtTSNoIPAddr:
		return "ts-no-ip-addr"
	case DiscCauseExtTSTCPRawExit:
		return "ts-tcp-raw-exit"
	case DiscCauseExtTSBadPassword:
		return "ts-bad-password"
	case DiscCauseExtTSNoTCPRaw:
		return "ts-no-tcp-raw"
	case DiscCauseExtTSCNTLC:
		return "ts-cntl-c"
	case DiscCauseExtTSSessionEnd:
		return "ts-session-end"
	case DiscCauseExtTSCloseVconn:
		return "ts-close-vconn"
	case DiscCauseExtTSEndVconn:
		return "ts-end-vconn"
	case DiscCauseExtTSRloginExit:
		return "ts-rlogin-exit"
	case DiscCauseExtTSRloginOptInvalid:
		return "ts-rlogin-opt-invalid"
	case DiscCauseExtTSInsuffResources:
		return "ts-insuff-resources"
	case DiscCauseExtPPPLCPTimeout:
		return "ppp-lcp-timeout"
	case DiscCauseExtPPPLCPFail:
		return "ppp-lcp-fail"
	case DiscCauseExtPPPPapFail:
		return "ppp-pap-fail"
	case DiscCauseExtPPPCHAPFail:
		return "ppp-chap-fail"
	case DiscCauseExtPPPRemoteFail:
		return "ppp-remote-fail"
	case DiscCauseExtPPPReceiveTerm:
		return "ppp-receive-term"
	case DiscCauseExtHWPPPAdminClose:
		return "hw-ppp-admin-close"
	case DiscCauseExtPPPNoNCP:
		return "ppp-no-ncp"
	case DiscCauseExtPPPMPError:
		return "ppp-mp-error"
	case DiscCauseExtPPPMaxChannels:
		return "ppp-max-channels"
	case DiscCauseExtTSTablesFull:
		return "ts-tables-full"
	case DiscCauseExtTSResourceFull:
		return "ts-resource-full"
	case DiscCauseExtTSInvalidIPAddr:
		return "ts-invalid-ip-addr"
	case DiscCauseExtTSBadHostname:
		return "ts-bad-hostname"
	case DiscCauseExtTSBadPort:
		return "ts-bad-port"
	case DiscCauseExtTCPReset:
		return "tcp-reset"
	case DiscCauseExtTCPConnectionRefused:
		return "tcp-connection-refused"
	case DiscCauseExtTCPTimeout:
		return "tcp-timeout"
	case DiscCauseExtTCPForeignHostClose:
		return "tcp-foreign-host-close"
	case DiscCauseExtTCPNetUnreachable:
		return "tcp-net-unreachable"
	case DiscCauseExtTCPHostUnreachable:
		return "tcp-host-unreachable"
	case DiscCauseExtTCPNetAdminUnreachable:
		return "tcp-net-admin-unreachable"
	case DiscCauseExtTCPHostAdminUnreachable:
		return "tcp-host-admin-unreachable"
	case DiscCauseExtTCPPortUnreachable:
		return "tcp-port-unreachable"
	case DiscCauseExtHWSessionTimeout:
		return "hw-session-timeout"
	default:
		return fmt.Sprintf("unknown(%d)", int(d))
	}
}

// NewDiscCauseArg builds a disc-cause=<n> Argument using the Cisco hyphenated
// name. Use NewMandatoryArg(ArgNameDiscCauseUnderscore, ...) for the Huawei
// underscore spelling.
func NewDiscCauseArg(d DiscCause, mandatory bool) Argument {
	return Argument{Mandatory: mandatory, Name: string(ArgNameDiscCause), Value: strconv.Itoa(int(d))}
}

// NewDiscCauseExtArg builds a disc-cause-ext=<n> Argument using the Cisco
// hyphenated name. Use NewMandatoryArg(ArgNameDiscCauseExtUnderscore, ...)
// for the Huawei underscore spelling.
func NewDiscCauseExtArg(d DiscCauseExt, mandatory bool) Argument {
	return Argument{Mandatory: mandatory, Name: string(ArgNameDiscCauseExt), Value: strconv.Itoa(int(d))}
}
