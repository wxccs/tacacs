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

// Package client provides a high-level TACACS+ client that drives complete
// authentication, authorization and accounting exchanges over a transport.Conn.
//
// The Client composes the packet, protocol and transport layers: it builds the
// correct minor version for each authen_type, manages the session id and
// sequence numbers, obfuscates bodies (legacy) or leaves them cleartext (TLS),
// and follows interactive CONTINUE/REPLY loops until a terminal status is
// reached.
package client
