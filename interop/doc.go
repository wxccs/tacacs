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
// It also covers cross-cutting properties that are security-critical:
//
//   - Multi-session: a single connection carrying a PAP auth → authorize →
//     accounting sequence, exercising seq_no incrementing and per-packet
//     session state across implementations.
//   - Bad-secret rejection: when client and server hold different shared
//     secrets the exchange must NOT pass (a silent pass would let an attacker
//     strip obfuscation). Both directions are verified.
//
// Each test stands up an in-process peer using the opposite implementation,
// drives a full AAA exchange, and asserts the protocol-level status. This
// catches silent protocol drift that same-implementation unit tests cannot.
package interop
