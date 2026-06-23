// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Daniel Wu.
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

// Package transport implements the TCP and TLS 1.3 transports for TACACS+
// (RFC 8907 §4.3 and RFC 9887).
//
// The framing layer reads and writes whole packets: a 12-byte header followed
// by the body length declared in the header. The TCP transport (port 49) uses
// the legacy MD5 obfuscation. The TLS 1.3 transport (port 300, "tacacss")
// obsoletes obfuscation: every packet MUST have TAC_PLUS_UNENCRYPTED_FLAG set
// in both directions, and 0-RTT is forbidden.
package transport
