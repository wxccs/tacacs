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

// Package crypto implements the TACACS+ body obfuscation defined by
// RFC 8907 §4.5.
//
// The obfuscation is NOT encryption: it provides no integrity, privacy or
// replay protection (RFC 8907 §10.5.2). New deployments SHOULD use TLS 1.3
// (RFC 9887), which obsoletes this mechanism. This package exists for
// compatibility with legacy non-TLS peers.
//
// The body of a packet (everything after the 12-byte header) is XORed
// bytewise with a pseudo-random pad built from MD5 hashes of the session id,
// the shared secret, the header version byte and the sequence number, each
// subsequent hash appending the previous digest. The header itself is never
// obfuscated.
package crypto
