// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package errors provides the sentinel and typed errors used throughout the
// tacacs library, together with thin wrappers around the standard library
// error helpers (New, Is, As, Unwrap, Join) so that callers can import a
// single errors package.
//
// Sentinel errors such as ErrSecretMismatch and ErrInvalidPacket describe
// well-known failure conditions. ValidationError wraps a sentinel with
// field-level context to aid packet diagnostics. All typed errors implement
// Unwrap so they participate in errors.Is / errors.As chains.
package errors
