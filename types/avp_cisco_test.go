// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCiscoArgNames asserts every Cisco-specific AVP name constant carries the
// exact wire string the Cisco IOS TACACS+ AV pair reference expects, so a typo
// cannot silently break interop. Source: "Cisco IOS Security Configuration
// Guide: Securing User Services, Release 12.4 - TACACS+ Attribute-Value Pairs"
// (Authentication and Authorization AV Pairs table, and Accounting AV Pairs
// table). Attributes shared with Huawei live in avp.go, not here.
func TestCiscoArgNames(t *testing.T) {
	cases := []struct {
		name  ArgName
		value string
	}{
		// Authentication / authorization AV pairs (already implemented).
		{ArgNameCallbackDialstring, "callback-dialstring"},
		{ArgNameCallbackRotary, "callback-rotary"},
		{ArgNameInacl, "inacl"},
		{ArgNameOutacl, "outacl"},
		{ArgNameNoescape, "noescape"},
		{ArgNameOldPrompts, "old-prompts"},
		{ArgNameRouting, "routing"},
		{ArgNameRoute, "route"},
		// Accounting AV pairs (already implemented).
		{ArgNameNasRxSpeed, "nas-rx-speed"},
		{ArgNameNasTxSpeed, "nas-tx-speed"},
		{ArgNameMlpLinksMax, "mlp-links-max"},
		{ArgNameMlpSessID, "mlp-sess-id"},
		{ArgNamePreSessionTime, "pre-session-time"},

		// Authentication / authorization AV pairs (completed from the Cisco doc).
		{ArgNameDataService, "data-service"},
		{ArgNameDialNumber, "dial-number"},
		{ArgNameForce56, "force-56"},
		{ArgNameInterfaceConfig, "interface-config"},
		{ArgNameL2tpBusyDisconnect, "l2tp-busy-disconnect"},
		{ArgNameL2tpCmLocalWindowSize, "l2tp-cm-local-window-size"},
		{ArgNameL2tpDropOutOfOrder, "l2tp-drop-out-of-order"},
		{ArgNameL2tpHelloInterval, "l2tp-hello-interval"},
		{ArgNameL2tpHiddenAvp, "l2tp-hidden-avp"},
		{ArgNameL2tpNosessionTimeout, "l2tp-nosession-timeout"},
		{ArgNameL2tpTosReflect, "l2tp-tos-reflect"},
		{ArgNameL2tpTunnelAuthen, "l2tp-tunnel-authen"},
		{ArgNameL2tpTunnelPassword, "l2tp-tunnel-password"},
		{ArgNameL2tpUdpChecksum, "l2tp-udp-checksum"},
		{ArgNameLinkCompression, "link-compression"},
		{ArgNameLoadThreshold, "load-threshold"},
		{ArgNameMapClass, "map-class"},
		{ArgNameMaxLinks, "max-links"},
		{ArgNameMinLinks, "min-links"},
		{ArgNameNasPassword, "nas-password"},
		{ArgNamePoolDef, "pool-def"},
		{ArgNamePoolTimeout, "pool-timeout"},
		{ArgNamePortType, "port-type"},
		{ArgNamePppVjSlotCompression, "ppp-vj-slot-compression"},
		{ArgNameProxyacl, "proxyacl"},
		{ArgNameRteFltrIn, "rte-fltr-in"},
		{ArgNameRteFltrOut, "rte-fltr-out"},
		{ArgNameSap, "sap"},
		{ArgNameSapFltrIn, "sap-fltr-in"},
		{ArgNameSapFltrOut, "sap-fltr-out"},
		{ArgNameSendAuth, "send-auth"},
		{ArgNameSendSecret, "send-secret"},
		{ArgNameSpi, "spi"},
		{ArgNameTimeout, "timeout"},
		{ArgNameWinsServers, "wins-servers"},
		{ArgNameZonelist, "zonelist"},

		// Accounting AV pairs (completed from the Cisco doc).
		{ArgNameAbortCause, "Abort-Cause"},
		{ArgNameCallType, "Call-Type"},
		{ArgNameEmailServerAddress, "Email-Server-Address"},
		{ArgNameEmailServerAckFlag, "Email-Server-Ack-Flag"},
		{ArgNameFaxAccountIdOrigin, "Fax-Account-Id-Origin"},
		{ArgNameFaxAuthStatus, "Fax-Auth-Status"},
		{ArgNameFaxConnectSpeed, "Fax-Connect-Speed"},
		{ArgNameFaxCoverpageFlag, "Fax-Coverpage-Flag"},
		{ArgNameFaxDsnAddress, "Fax-Dsn-Address"},
		{ArgNameFaxDsnFlag, "Fax-Dsn-Flag"},
		{ArgNameFaxMdnAddress, "Fax-Mdn-Address"},
		{ArgNameFaxMdnFlag, "Fax-Mdn-Flag"},
		{ArgNameFaxModemTime, "Fax-Modem-Time"},
		{ArgNameFaxMsgId, "Fax-Msg-Id"},
		{ArgNameFaxPages, "Fax-Pages"},
		{ArgNameFaxProcessAbortFlag, "Fax-Process-Abort-Flag"},
		{ArgNameFaxRecipientCount, "Fax-Recipient-Count"},
		{ArgNameGatewayId, "Gateway-Id"},
		{ArgNamePortUsed, "Port-Used"},
		{ArgNamePreBytesIn, "pre-bytes-in"},
		{ArgNamePreBytesOut, "pre-bytes-out"},
		{ArgNamePrePaksIn, "pre-paks-in"},
		{ArgNamePrePaksOut, "pre-paks-out"},

		// cisco-av-pair shell/accounting VSAs (NX-OS, from the Security
		// Configuration Guide, Release 10.6(x), "VSA Format").
		{ArgNameShellRoles, "shell:roles"},
		{ArgNameShellPrivLvl, "shell:priv-lvl"},
		{ArgNameAccountingInfo, "accountinginfo"},
	}
	assert.Equal(t, 75, len(cases), "expected 75 Cisco-only AVP name constants (excluding aliases)")
	for _, c := range cases {
		assert.Equalf(t, c.value, string(c.name), "constant %q has wrong value", c.value)
	}
}

// TestCiscoDeprecatedAliases asserts the renamed AV pairs alias to their
// current names. The Cisco doc notes data-rate was renamed to nas-rx-speed and
// xmit-rate to nas-tx-speed; the alias constants resolve to the current names
// so legacy code never emits the obsolete wire string.
func TestCiscoDeprecatedAliases(t *testing.T) {
	assert.Equal(t, string(ArgNameNasRxSpeed), string(ArgNameDataRate))
	assert.Equal(t, string(ArgNameNasTxSpeed), string(ArgNameXmitRate))
	assert.Equal(t, "nas-rx-speed", string(ArgNameDataRate))
	assert.Equal(t, "nas-tx-speed", string(ArgNameXmitRate))
}

// TestCiscoShellAVPairs covers the cisco-av-pair VSAs defined by NX-OS. The
// roles attribute value is a white-space-delimited list of group names; the
// optional separator '*' marks the pair as optional (other Cisco devices then
// ignore it). Source: NX-OS Security Configuration Guide, Release 10.6(x),
// "VSA Format" and "Specifying Cisco NX-OS User Roles ... on AAA Servers".
func TestCiscoShellAVPairs(t *testing.T) {
	// roles: multiple roles joined by a single space, mandatory.
	got := ShellRolesArg([]string{"network-operator", "network-admin"}, true)
	assert.True(t, got.Mandatory)
	assert.Equal(t, "shell:roles", got.Name)
	assert.Equal(t, "network-operator network-admin", got.Value)
	assert.Equal(t, "shell:roles=network-operator network-admin", got.String())

	// roles: optional (separator '*') is valid but NX-OS flags it as optional
	// and other Cisco devices ignore it.
	opt := ShellRolesArg([]string{"network-admin"}, false)
	assert.False(t, opt.Mandatory)
	assert.Equal(t, "shell:roles*network-admin", opt.String())

	// priv-lvl: numeric privilege level under the shell protocol namespace.
	p := ShellPrivLvlArg(PrivLevelMax, true)
	assert.True(t, p.Mandatory)
	assert.Equal(t, "shell:priv-lvl", p.Name)
	assert.Equal(t, "15", p.Value)
	assert.Equal(t, "shell:priv-lvl=15", p.String())

	// accountinginfo: accounting-protocol VSA, no shell: prefix.
	ai := NewMandatoryArg(ArgNameAccountingInfo, "custom-accounting-data")
	assert.Equal(t, "accountinginfo=custom-accounting-data", ai.String())
}
