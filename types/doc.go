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
// The predefined AVP name constants (ArgNameService, ArgNameCmd, ...) cover
// the attribute-value pairs defined by RFC 8907 (§6 authorization and §8.3
// accounting arguments, including err_msg), the Cisco IOS XE TACACS+
// reference, the Huawei HWTACACS attribute table and the vendor-specific
// attributes of Juniper Junos and Palo Alto Networks PAN-OS; where Cisco
// and Huawei disagree on the spelling (e.g. disc-cause vs disc_cause) both
// forms are provided. Disconnect-cause codes are enumerated by DiscCause
// and DiscCauseExt.
package types
