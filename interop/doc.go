// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package interop contains cross-implementation tests that validate wire
// compatibility between this tacacs library and github.com/facebookincubator/tacquito
// (tacquito). It is a test-only package: it exports no symbols.
//
// The suite covers both directions of the TACACS+ exchange over the legacy
// obfuscated transport (RFC 8907) and over TLS 1.3 (RFC 9887):
//
//   - Local client → tacquito server (PAP, ASCII, Authorize, Accounting, TLS-PAP)
//   - tacquito client → local server (PAP, ASCII, Authorize, Accounting, TLS-PAP)
//
// Each test stands up an in-process peer using the opposite implementation,
// drives a full AAA exchange, and asserts the protocol-level status. This
// catches silent protocol drift that same-implementation unit tests cannot.
package interop
