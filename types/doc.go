// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
// Package types holds the protocol constants and shared primitive types for
// the tacacs library: protocol versions, packet types, header flags, the
// authentication/authorization/accounting enumerations, privilege levels, the
// Argument codec, packet size limits, and the Logger interface used by the
// core library.
//
// Constant values follow RFC 8907 ("TACACS+ Protocol"). Each enumeration is a
// named type so that distinct value spaces cannot be mixed at compile time.
package types
