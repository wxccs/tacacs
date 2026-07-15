// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package types holds the protocol constants and shared primitive types for
// the tacacs library: protocol versions, packet types, header flags, the
// authentication/authorization/accounting enumerations, privilege levels, the
// Argument codec, the predefined AVP name constants and constructors, the
// disconnect-cause enumerations, packet size limits, and the Logger
// interface used by the core library.
//
// Constant values follow RFC 8907 ("TACACS+ Protocol"). Each enumeration is a
// named type so that distinct value spaces cannot be mixed at compile time.
//
// The predefined AVP name constants are organized by vendor. avp.go holds the
// pairs shared by all vendors: the RFC 8907 base set (§6 authorization and §8.3
// accounting arguments, including err_msg, bytes and paks) plus the Cisco &
// Huawei common traditional pairs (acl, addr, addr-pool, autocmd, callback-line,
// dns-servers, gw-password, idletime, ip-addresses, nocallback-verify, nohangup,
// source-ip, tunnel-id), and the disconnect-cause dual naming (disc-cause vs
// disc_cause). Vendor-specific pairs live in avp_cisco.go (the full Cisco IOS
// TACACS+ AV pair reference, including the L2TP/VPDN, SAP, fax and accounting
// pairs), avp_huawei.go (HWTACACS rate/tunnel/ftp pairs), avp_juniper.go (Junos
// exec attributes) and avp_paloalto.go (PAN-OS administrator VSAs).
// Disconnect-cause codes are enumerated by DiscCause and DiscCauseExt.
package types
