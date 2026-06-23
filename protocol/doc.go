// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
// Package protocol implements the TACACS+ authentication, authorization and
// accounting logic on top of the packet and crypto layers (RFC 8907 §5-8, §11).
//
// It provides:
//   - session management (cryptographically random session id, sequence-number
//     bookkeeping with client-odd/server-even parity and no-wrap semantics,
//     single-connection negotiation);
//   - parsing of the challenge/response data field for CHAP, MS-CHAP and
//     MS-CHAPv2 authentications, including the challenge-length validation the
//     server MUST enforce;
//   - helpers to build the various REPLY and error packets.
//
// The package is transport-agnostic: it operates on in-memory packet bodies and
// leaves connection handling to the transport layer.
package protocol
