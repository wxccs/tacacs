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

package yang

import "strings"

// Redact returns a copy of the Config with sensitive material replaced by a
// placeholder, safe for logging. Shared secrets and private keys are redacted
// per RFC 9950 §6 (shared-secret is nacm:default-deny-all; private keys are
// sensitive).
func (c *Config) Redact() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Servers = make([]Server, len(c.Servers))
	for i, s := range c.Servers {
		rs := s
		if rs.Security.SharedSecret != nil {
			hidden := strings.Repeat("*", len(*rs.Security.SharedSecret))
			rs.Security.SharedSecret = &hidden
		}
		if rs.Security.TLS != nil {
			if rs.Security.TLS.ClientIdentity.Certificate != nil &&
				rs.Security.TLS.ClientIdentity.Certificate.InlineDefinition != nil {
				ind := *rs.Security.TLS.ClientIdentity.Certificate.InlineDefinition
				ind.CleartextPrivateKey = redactIfSet(ind.CleartextPrivateKey)
				rs.Security.TLS.ClientIdentity.Certificate.InlineDefinition = &ind
			}
		}
		out.Servers[i] = rs
	}
	return &out
}

// redactIfSet replaces a non-empty sensitive string with a fixed placeholder.
func redactIfSet(s string) string {
	if s == "" {
		return s
	}
	return "<redacted>"
}
