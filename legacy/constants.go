// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package legacy

// UDP/TCP ports (RFC 1492 §2/§3).
const (
	UDPPort = 49 // historical TACACS UDP port
	// TCPPort has no reserved value; it is configurable.
)

// UDP version byte values (RFC 1492 §2.2.1). The version discriminates the
// simple (6-byte header) and extended (26-byte header) forms.
const (
	UDPVersionSimple     byte = 0   // simple form
	UDPVersionExtended   byte = 128 // extended form (0x80)
	UDPHeaderLenSimple   int  = 6
	UDPHeaderLenExtended int  = 26
)

// UDP TYPE values (RFC 1492 §2.2.1).
const (
	UDPTypeLogin     byte = 1
	UDPTypeResponse  byte = 2 // server -> client only
	UDPTypeChange    byte = 3
	UDPTypeFollow    byte = 4
	UDPTypeConnect   byte = 5
	UDPTypeSuperuser byte = 6
	UDPTypeLogout    byte = 7
	UDPTypeReload    byte = 8
	UDPTypeSlipOn    byte = 9
	UDPTypeSlipOff   byte = 10
	UDPTypeSlipAddr  byte = 11
)

// UDP RESPONSE values (server sets; client sets to 0) (RFC 1492 §2.2.1).
const (
	UDPResponseAccepted byte = 1
	UDPResponseRejected byte = 2
)

// UDP REASON values (RFC 1492 §2.2.1).
const (
	UDPReasonNone     byte = 0
	UDPReasonExpiring byte = 1
	UDPReasonPassword byte = 2
	UDPReasonDenied   byte = 3
	UDPReasonQuit     byte = 4
	UDPReasonIdle     byte = 5
	UDPReasonDrop     byte = 6
	UDPReasonBad      byte = 7
)

// TCP encoding constants (RFC 1492 §3).
const (
	TCPVersion byte = 1 // TCP encoding version (unrelated to UDP versions)
	// CRLF is the TCP line separator.
	CRLF = "\r\n"
)

// TCP reply codes (RFC 1492 §3.2). The first digit classifies the reply:
// 2xx positive completion, 4xx transient negative, 5xx permanent negative.
const (
	TCPReplyAccepted        = "201"
	TCPReplyAcceptedExpire  = "202"
	TCPReplyNoResponseRetry = "401"
	TCPReplyInvalidFormat   = "501"
	TCPReplyAccessDenied    = "502"
)
