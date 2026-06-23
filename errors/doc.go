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
