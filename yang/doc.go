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

// Package yang mirrors the ietf-system-tacacs-plus YANG data model (RFC 9950)
// as Go configuration structs and loads them from YAML or JSON via viper.
//
// The model augments /system with a "tacacs-plus" container holding a single
// unified list of servers. Each server advertises which AAA services it
// provides (server-type bits), a security choice (TLS or shared-secret
// obfuscation), and optional source/VRF selection. The shared-secret is
// cleartext and deprecated in favor of TLS.
//
// Choice nodes map to tagged Go unions (Security, AuthType, RefOrExplicit).
// After loading, Validate enforces the model's "must" and "unique" constraints:
// unique (address, port) pairs, a server-auth configuration when TLS is used,
// sni-enabled requires domain-name, and TLS 1.2 is forbidden as a min or max
// version.
package yang
