// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
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
