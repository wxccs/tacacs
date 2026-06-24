// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package client provides a high-level TACACS+ client that drives complete
// authentication, authorization and accounting exchanges over a transport.Conn.
//
// The Client composes the packet, protocol and transport layers: it builds the
// correct minor version for each authen_type, manages the session id and
// sequence numbers, obfuscates bodies (legacy) or leaves them cleartext (TLS),
// and follows interactive CONTINUE/REPLY loops until a terminal status is
// reached.
package client
