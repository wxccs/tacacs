// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"strconv"
	"strings"
)

// Cisco IOS TACACS+ vendor-specific AV pairs. These are the AV pairs defined
// only by the Cisco IOS TACACS+ reference and not shared with Huawei (shared
// pairs live in avp.go). Each constant is the AV pair name exactly as it
// appears on the wire.
//
// Source: "Cisco IOS Security Configuration Guide: Securing User Services,
// Release 12.4 - TACACS+ Attribute-Value Pairs"
// (https://www.cisco.com/c/en/us/td/docs/ios/sec_user_services/configuration/
// guide/12_4/sec_securing_user_services_12-4_book/sec_tacacs_attr_vp.html)
//
// Tables: "TACACS+ Authentication and Authorization AV Pairs" and
// "TACACS+ Accounting AV Pairs". Indexed pairs (inacl, outacl, route,
// interface-config, pool-def, proxyacl, rte-fltr-in/out, sap, sap-fltr-in/out)
// use the name#<n> form built by NewIndexedArg.
//
// Security: gw-password/nas-password/l2tp-tunnel-password/send-secret carry
// shared secrets; never log or echo their values. priv-lvl/acl/cmd/service are
// authorization-decision attributes validated server-side.

// Authentication and authorization AV pairs specific to Cisco. Already
// implemented (shared with prior releases) plus the remaining pairs from the
// Cisco doc, ordered as in the reference table.
const (
	// Already implemented, moved from avp.go.
	ArgNameCallbackDialstring ArgName = "callback-dialstring" // service=shell/arap/slip/ppp
	ArgNameCallbackRotary     ArgName = "callback-rotary"     // rotary group 0-100
	ArgNameInacl              ArgName = "inacl"               // indexed: inacl#<n>, also inacl=x
	ArgNameOutacl             ArgName = "outacl"              // indexed: outacl#<n>, also outacl=x
	ArgNameNoescape           ArgName = "noescape"            // service=shell
	ArgNameOldPrompts         ArgName = "old-prompts"
	ArgNameRouting            ArgName = "routing"
	ArgNameRoute              ArgName = "route" // indexed: route#<n>

	// Completed from the Cisco doc (Authentication and Authorization table).
	ArgNameDataService           ArgName = "data-service"              // service=outbound, protocol=ip
	ArgNameDialNumber            ArgName = "dial-number"               // service=outbound, protocol=ip
	ArgNameForce56               ArgName = "force-56"                  // service=outbound, protocol=ip
	ArgNameInterfaceConfig       ArgName = "interface-config"          // indexed: interface-config#<n>, service=ppp
	ArgNameL2tpBusyDisconnect    ArgName = "l2tp-busy-disconnect"      // service=ppp, protocol=vpdn
	ArgNameL2tpCmLocalWindowSize ArgName = "l2tp-cm-local-window-size" // service=ppp, protocol=vpdn
	ArgNameL2tpDropOutOfOrder    ArgName = "l2tp-drop-out-of-order"    // service=ppp, protocol=vpdn
	ArgNameL2tpHelloInterval     ArgName = "l2tp-hello-interval"       // service=ppp, protocol=vpdn
	ArgNameL2tpHiddenAvp         ArgName = "l2tp-hidden-avp"           // service=ppp, protocol=vpdn
	ArgNameL2tpNosessionTimeout  ArgName = "l2tp-nosession-timeout"    // service=ppp, protocol=vpdn
	ArgNameL2tpTosReflect        ArgName = "l2tp-tos-reflect"          // service=ppp, protocol=vpdn
	ArgNameL2tpTunnelAuthen      ArgName = "l2tp-tunnel-authen"        // service=ppp, protocol=vpdn
	ArgNameL2tpTunnelPassword    ArgName = "l2tp-tunnel-password"      // key-bearing, service=ppp protocol=vpdn
	ArgNameL2tpUdpChecksum       ArgName = "l2tp-udp-checksum"         // service=ppp, protocol=vpdn
	ArgNameLinkCompression       ArgName = "link-compression"          // numeric 0-3, service=ppp
	ArgNameLoadThreshold         ArgName = "load-threshold"            // <n> 1-255, service=ppp protocol=multilink
	ArgNameMapClass              ArgName = "map-class"                 // service=outbound, protocol=ip
	ArgNameMaxLinks              ArgName = "max-links"                 // <n> 1-255, service=ppp protocol=multilink
	ArgNameMinLinks              ArgName = "min-links"                 // service=ppp protocol=multilink/vpdn
	ArgNameNasPassword           ArgName = "nas-password"              // key-bearing, service=ppp protocol=vpdn (L2F)
	ArgNamePoolDef               ArgName = "pool-def"                  // indexed: pool-def#<n>, service=ppp protocol=ip
	ArgNamePoolTimeout           ArgName = "pool-timeout"              // service=ppp protocol=ip
	ArgNamePortType              ArgName = "port-type"                 // physical port type
	ArgNamePppVjSlotCompression  ArgName = "ppp-vj-slot-compression"   // service=ppp
	ArgNameProxyacl              ArgName = "proxyacl"                  // indexed: proxyacl#<n>, downloadable ACL
	ArgNameRteFltrIn             ArgName = "rte-fltr-in"               // indexed: rte-fltr-in#<n>, routing-update input filter
	ArgNameRteFltrOut            ArgName = "rte-fltr-out"              // indexed: rte-fltr-out#<n>, routing-update output filter
	ArgNameSap                   ArgName = "sap"                       // indexed: sap#<n>, static SAP entries
	ArgNameSapFltrIn             ArgName = "sap-fltr-in"               // indexed: sap-fltr-in#<n>, input SAP filter
	ArgNameSapFltrOut            ArgName = "sap-fltr-out"              // indexed: sap-fltr-out#<n>, output SAP filter
	ArgNameSendAuth              ArgName = "send-auth"                 // PAP or CHAP after callback
	ArgNameSendSecret            ArgName = "send-secret"               // key-bearing, CHAP/PAP response secret
	ArgNameSpi                   ArgName = "spi"                       // mobile-IP auth info
	ArgNameTimeout               ArgName = "timeout"                   // minutes, EXEC/ARA disconnect
	ArgNameWinsServers           ArgName = "wins-servers"              // service=ppp protocol=ip
	ArgNameZonelist              ArgName = "zonelist"                  // numeric, service=arap (AppleTalk)
)

// Accounting AV pairs specific to Cisco. Already implemented plus the remaining
// pairs from the Cisco Accounting AV Pairs table. The Fax-*, Email-*,
// Abort-Cause, Call-Type, Gateway-Id and Port-Used pairs belong to the Cisco
// IOS Store-and-Forward Fax feature (legacy); they are retained for completeness.
const (
	// Already implemented, moved from avp.go.
	ArgNameNasRxSpeed     ArgName = "nas-rx-speed"
	ArgNameNasTxSpeed     ArgName = "nas-tx-speed"
	ArgNameMlpLinksMax    ArgName = "mlp-links-max"
	ArgNameMlpSessID      ArgName = "mlp-sess-id"
	ArgNamePreSessionTime ArgName = "pre-session-time"

	// Completed from the Cisco doc (Accounting AV Pairs table).
	ArgNameAbortCause          ArgName = "Abort-Cause"
	ArgNameCallType            ArgName = "Call-Type"
	ArgNameEmailServerAddress  ArgName = "Email-Server-Address"
	ArgNameEmailServerAckFlag  ArgName = "Email-Server-Ack-Flag"
	ArgNameFaxAccountIdOrigin  ArgName = "Fax-Account-Id-Origin"
	ArgNameFaxAuthStatus       ArgName = "Fax-Auth-Status"
	ArgNameFaxConnectSpeed     ArgName = "Fax-Connect-Speed"
	ArgNameFaxCoverpageFlag    ArgName = "Fax-Coverpage-Flag"
	ArgNameFaxDsnAddress       ArgName = "Fax-Dsn-Address"
	ArgNameFaxDsnFlag          ArgName = "Fax-Dsn-Flag"
	ArgNameFaxMdnAddress       ArgName = "Fax-Mdn-Address"
	ArgNameFaxMdnFlag          ArgName = "Fax-Mdn-Flag"
	ArgNameFaxModemTime        ArgName = "Fax-Modem-Time"
	ArgNameFaxMsgId            ArgName = "Fax-Msg-Id"
	ArgNameFaxPages            ArgName = "Fax-Pages"
	ArgNameFaxProcessAbortFlag ArgName = "Fax-Process-Abort-Flag"
	ArgNameFaxRecipientCount   ArgName = "Fax-Recipient-Count"
	ArgNameGatewayId           ArgName = "Gateway-Id"
	ArgNamePortUsed            ArgName = "Port-Used"
	ArgNamePreBytesIn          ArgName = "pre-bytes-in"
	ArgNamePreBytesOut         ArgName = "pre-bytes-out"
	ArgNamePrePaksIn           ArgName = "pre-paks-in"
	ArgNamePrePaksOut          ArgName = "pre-paks-out"
)

// Deprecated aliases. The Cisco doc notes data-rate was renamed to nas-rx-speed
// and xmit-rate to nas-tx-speed. These constants alias to the current names so
// legacy code emits the modern wire string rather than the obsolete one.
const (
	ArgNameDataRate ArgName = ArgNameNasRxSpeed // deprecated alias for nas-rx-speed
	ArgNameXmitRate ArgName = ArgNameNasTxSpeed // deprecated alias for nas-tx-speed
)

// cisco-av-pair VSAs as used by Cisco NX-OS (and the same format on other Cisco
// platforms that honor the shell VSA). The NX-OS VSA format is
// "protocol:attribute separator value", where separator is '=' (mandatory) or
// '*' (optional). The shell protocol carries user-profile attributes in the
// authorization REPLY; the accounting protocol carries accountinginfo in
// accounting-request packets.
//
// Source: Cisco Nexus 9000 Series NX-OS Security Configuration Guide,
// Release 10.6(x), "VSA Format" and "Specifying Cisco NX-OS User Roles and
// SNMPv3 Parameters on AAA Servers".
//
// Security: shell:roles and shell:priv-lvl are authorization-decision
// attributes (roles such as network-admin grant high privilege); they are
// validated server-side and must not be accepted from untrusted input.
const (
	// ArgNameShellRoles lists the user roles assigned to the user. The value
	// is a white-space-delimited list of group names, e.g.
	// "network-operator network-admin". Shell protocol only (access-accept).
	// When the optional separator '*' is used, NX-OS flags the VSA as optional
	// and other Cisco devices ignore it.
	ArgNameShellRoles ArgName = "shell:roles"
	// ArgNameShellPrivLvl is the privilege level under the shell protocol
	// namespace (the shell-namespaced counterpart of priv-lvl), used together
	// with SNMPv3 attributes. Shell protocol only.
	ArgNameShellPrivLvl ArgName = "shell:priv-lvl"
	// ArgNameAccountingInfo stores accounting information beyond the standard
	// TACACS+/RADIUS accounting attributes. Accounting protocol only
	// (accounting-request); it does not carry the "shell:" prefix.
	ArgNameAccountingInfo ArgName = "accountinginfo"
)

// ShellRolesArg builds the shell:roles=<roles> AV pair from a list of role
// names. The roles are joined by a single space, matching the NX-OS value
// format ("network-operator network-admin"). Set mandatory to false to emit
// the optional "shell:roles*<roles>" form (NX-OS then treats the pair as
// optional and other Cisco devices ignore it).
func ShellRolesArg(roles []string, mandatory bool) Argument {
	return NewArg(ArgNameShellRoles, strings.Join(roles, " "), mandatory)
}

// ShellPrivLvlArg builds the shell:priv-lvl=<n> AV pair from a PrivLevel, the
// shell-namespaced counterpart of priv-lvl used by NX-OS together with SNMPv3
// attributes.
func ShellPrivLvlArg(lvl PrivLevel, mandatory bool) Argument {
	return Argument{Mandatory: mandatory, Name: string(ArgNameShellPrivLvl), Value: strconv.Itoa(int(lvl))}
}
