// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
// Package legacy implements the original TACACS protocol (RFC 1492), distinct
// from TACACS+ (RFC 8907). RFC 1492 defines two wire-incompatible encodings:
//
//   - a binary UDP encoding on port 49, in a "simple" (6-byte header) form and
//     an "extended" (26-byte header) form, discriminated by the version byte
//     (0 = simple, 128 = extended);
//   - an ASCII TCP encoding on a configurable port, using a four-line request
//     and a three-digit reply code.
//
// Original TACACS has no dedicated authorization phase: CONNECT, SUPERUSER and
// SLIPON request/response pairs serve as authorization-equivalent exchanges.
package legacy
