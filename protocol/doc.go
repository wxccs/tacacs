// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
//
// This library is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library. If not, see <https://www.gnu.org/licenses/>.

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
