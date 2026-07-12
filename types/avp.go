// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"strconv"
	"strings"

	"github.com/wxccs/tacacs/errors"
)

// ArgName is the name of a predefined TACACS+ argument-value pair. It is a
// named string so that predefined AVP names are distinct from ad-hoc strings
// at compile time, while remaining zero-cost to use in an Argument. The
// predefined names below are drawn from the Cisco IOS XE "TACACS Attribute-
// Value Pairs" reference and the Huawei HWTACACS attribute table. Where Cisco
// and Huawei disagree on the separator (hyphen vs underscore, e.g. disc-cause
// / disc_cause), both spellings are provided and the Huawei variant is
// suffixed "Underscore".
type ArgName string

// Authentication and authorization AV pairs (service=shell, cmd, cmd-arg,
// priv-lvl, ...). Used in authorization REQUEST and REPLY argument lists.
const (
	ArgNameService            ArgName = "service"
	ArgNameCmd                ArgName = "cmd"
	ArgNameCmdArg             ArgName = "cmd-arg"
	ArgNamePrivLvl            ArgName = "priv-lvl" // authorization uses a hyphen
	ArgNameProtocol           ArgName = "protocol"
	ArgNameAcl                ArgName = "acl"
	ArgNameAddr               ArgName = "addr"
	ArgNameAddrPool           ArgName = "addr-pool"
	ArgNameAutocmd            ArgName = "autocmd"
	ArgNameCallbackDialstring ArgName = "callback-dialstring"
	ArgNameCallbackLine       ArgName = "callback-line"
	ArgNameCallbackRotary     ArgName = "callback-rotary"
	ArgNameDnsServers         ArgName = "dns-servers"
	ArgNameIdletime           ArgName = "idletime"
	ArgNameInacl              ArgName = "inacl"  // indexed: inacl#<n>
	ArgNameOutacl             ArgName = "outacl" // indexed: outacl#<n>
	ArgNameIpAddresses        ArgName = "ip-addresses"
	ArgNameGwPassword         ArgName = "gw-password" // secret-bearing
	ArgNameNocallbackVerify   ArgName = "nocallback-verify"
	ArgNameNoescape           ArgName = "noescape"
	ArgNameNohangup           ArgName = "nohangup"
	ArgNameOldPrompts         ArgName = "old-prompts"
	ArgNameRouting            ArgName = "routing"
	ArgNameRoute              ArgName = "route" // indexed: route#<n>
	ArgNameSourceIP           ArgName = "source-ip"
)

// Accounting AV pairs (bytes_in, task_id, elapsed_time, ...). Used in
// accounting REQUEST argument lists.
const (
	ArgNameBytesIn        ArgName = "bytes_in"
	ArgNameBytesOut       ArgName = "bytes_out"
	ArgNamePaksIn         ArgName = "paks_in"
	ArgNamePaksOut        ArgName = "paks_out"
	ArgNameElapsedTime    ArgName = "elapsed_time"
	ArgNameTaskID         ArgName = "task_id"
	ArgNameTimezone       ArgName = "timezone"
	ArgNameStartTime      ArgName = "start_time"
	ArgNameStopTime       ArgName = "stop_time"
	ArgNameEvent          ArgName = "event"
	ArgNameReason         ArgName = "reason"
	ArgNamePort           ArgName = "port"
	ArgNamePrivLevel      ArgName = "priv_level" // accounting uses an underscore
	ArgNameNasRxSpeed     ArgName = "nas-rx-speed"
	ArgNameNasTxSpeed     ArgName = "nas-tx-speed"
	ArgNameMlpLinksMax    ArgName = "mlp-links-max"
	ArgNameMlpSessID      ArgName = "mlp-sess-id"
	ArgNamePreSessionTime ArgName = "pre-session-time"
)

// Disconnect-cause AV pairs. Cisco uses the hyphenated spelling (disc-cause,
// disc-cause-ext); Huawei uses the underscore spelling (disc_cause,
// disc_cause_ext). Both are provided; callers pick the one that matches the
// peer they interoperate with.
const (
	ArgNameDiscCause              ArgName = "disc-cause"
	ArgNameDiscCauseUnderscore    ArgName = "disc_cause"
	ArgNameDiscCauseExt           ArgName = "disc-cause-ext"
	ArgNameDiscCauseExtUnderscore ArgName = "disc_cause_ext"
)

// Huawei-specific AV pairs. dnaverage/dnpeak/upaverage/uppeak report link
// rates in bit/s; tunnel-id/tunnel-type describe VPDN tunnels; ftpdir sets the
// FTP user's initial directory. These are not part of the Cisco set.
const (
	ArgNameDnAverage  ArgName = "dnaverage"
	ArgNameDnPeak     ArgName = "dnpeak"
	ArgNameUpAverage  ArgName = "upaverage"
	ArgNameUpPeak     ArgName = "uppeak"
	ArgNameTunnelID   ArgName = "tunnel-id"
	ArgNameTunnelType ArgName = "tunnel-type"
	ArgNameFtpDir     ArgName = "ftpdir"
)

// NewArg builds an Argument with the given name, value and mandatory flag.
// It is the generic constructor for predefined AV pairs.
func NewArg(name ArgName, value string, mandatory bool) Argument {
	return Argument{Mandatory: mandatory, Name: string(name), Value: value}
}

// NewMandatoryArg builds a mandatory Argument ("name=value").
func NewMandatoryArg(name ArgName, value string) Argument {
	return NewArg(name, value, true)
}

// NewOptionalArg builds an optional Argument ("name*value").
func NewOptionalArg(name ArgName, value string) Argument {
	return NewArg(name, value, false)
}

// NewIndexedArg builds an Argument whose name carries a numeric index suffix
// of the form "name#<n>", used by AV pairs such as inacl#1, outacl#2 and
// route#3. It returns ErrInvalidArgument if n is not positive or if name
// already contains a '#', which would make the index ambiguous.
func NewIndexedArg(name ArgName, n int, value string, mandatory bool) (Argument, error) {
	if n <= 0 {
		return Argument{}, errors.NewValidationError("arg_index", "must be > 0", errors.ErrInvalidArgument)
	}
	ns := string(name)
	if strings.Contains(ns, "#") {
		return Argument{}, errors.NewValidationError("arg_name", "already indexed", errors.ErrInvalidArgument)
	}
	return Argument{Mandatory: mandatory, Name: ns + "#" + strconv.Itoa(n), Value: value}, nil
}

// ServiceArg builds a mandatory service=<value> AV pair. "service" MUST always
// be present in an authorization or accounting request (RFC 8907 §5.1).
func ServiceArg(value string) Argument {
	return NewMandatoryArg(ArgNameService, value)
}

// CmdArg builds a mandatory cmd=<value> AV pair, the shell command being
// authorized or accounted. The value is the command's first keyword during
// command authorization, or the full command line during accounting.
func CmdArg(value string) Argument {
	return NewMandatoryArg(ArgNameCmd, value)
}

// CmdArgCR builds the mandatory cmd-arg=<cr> AV pair that terminates the
// cmd-arg list during command authorization.
func CmdArgCR() Argument {
	return NewMandatoryArg(ArgNameCmdArg, "<cr>")
}

// PrivLvlArg builds a mandatory priv-lvl=<n> AV pair from a PrivLevel. The
// numeric form is used because PrivLevel has no String method of its own.
func PrivLvlArg(lvl PrivLevel) Argument {
	return Argument{Mandatory: true, Name: string(ArgNamePrivLvl), Value: strconv.Itoa(int(lvl))}
}
