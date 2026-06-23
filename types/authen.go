// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package types

// AuthenAction is the authentication action (START byte 0).
type AuthenAction byte

// Authentication actions (RFC 8907 §5.2.1).
const (
	AuthenLogin    AuthenAction = 0x01
	AuthenChpass   AuthenAction = 0x02
	AuthenSendauth AuthenAction = 0x04
)

// AuthenType is the authentication type (START byte 2).
type AuthenType byte

// Authentication types (RFC 8907 §5.2.2). AuthenTypeNotSet is only valid in
// authorization and accounting requests.
const (
	AuthenTypeNotSet   AuthenType = 0x00
	AuthenTypeASCII    AuthenType = 0x01
	AuthenTypePAP      AuthenType = 0x02
	AuthenTypeCHAP     AuthenType = 0x03
	AuthenTypeMSCHAP   AuthenType = 0x05
	AuthenTypeMSCHAPv2 AuthenType = 0x06
)

// AuthenService is the authentication service (START byte 3).
type AuthenService byte

// Authentication services (RFC 8907 §5.2.3).
const (
	AuthenServiceNone    AuthenService = 0x00
	AuthenServiceLogin   AuthenService = 0x01
	AuthenServiceEnable  AuthenService = 0x02
	AuthenServicePPP     AuthenService = 0x03
	AuthenServicePT      AuthenService = 0x05
	AuthenServiceRCMD    AuthenService = 0x06
	AuthenServiceX25     AuthenService = 0x07
	AuthenServiceNASI    AuthenService = 0x08
	AuthenServiceFWProxy AuthenService = 0x09
)

// AuthenStatus is the authentication REPLY status (REPLY byte 0).
type AuthenStatus byte

// Authentication statuses (RFC 8907 §5.4.1). AuthenStatusFollow is deprecated
// and MUST be treated as Fail by clients.
const (
	AuthenStatusPass    AuthenStatus = 0x01
	AuthenStatusFail    AuthenStatus = 0x02
	AuthenStatusGetData AuthenStatus = 0x03
	AuthenStatusGetUser AuthenStatus = 0x04
	AuthenStatusGetPass AuthenStatus = 0x05
	AuthenStatusRestart AuthenStatus = 0x06
	AuthenStatusError   AuthenStatus = 0x07
	AuthenStatusFollow  AuthenStatus = 0x21
)

// ReplyFlagNoEcho is the authentication REPLY flag indicating that the data
// echoed back to the server (in a subsequent CONTINUE) should not be echoed
// locally (REPLY byte 1, RFC 8907 §5.4.1).
const ReplyFlagNoEcho byte = 0x01

// ContinueFlagAbort is the authentication CONTINUE flag indicating that the
// session is being aborted by the client (CONTINUE byte 4, RFC 8907 §5.3.2).
const ContinueFlagAbort byte = 0x01
