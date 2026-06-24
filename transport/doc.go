// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package transport implements the TCP and TLS 1.3 transports for TACACS+
// (RFC 8907 §4.3 and RFC 9887).
//
// The framing layer reads and writes whole packets: a 12-byte header followed
// by the body length declared in the header. The TCP transport (port 49) uses
// the legacy MD5 obfuscation. The TLS 1.3 transport (port 300, "tacacss")
// obsoletes obfuscation: every packet MUST have TAC_PLUS_UNENCRYPTED_FLAG set
// in both directions, and 0-RTT is forbidden.
package transport
