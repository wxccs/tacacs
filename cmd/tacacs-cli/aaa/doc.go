// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package aaa provides production-grade AAA backend components for the
// tacacs-cli server: a bcrypt-backed Authenticator, a regex-based Authorizer,
// and durable Accounters (file and syslog). Each component is composable via
// CompositeHandler, which adapts them to the server.Handler interface.
package aaa
