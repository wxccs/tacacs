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

// Package server implements a TACACS+ server: it accepts connections, decodes
// packets, drives the authentication/authorization/accounting state machines
// via a caller-supplied Handler, and encodes the responses.
//
// The Handler interface is the integration point: an application implements
// Authenticate, Authorize and Account to make policy decisions. The Server
// takes care of framing, obfuscation/TLS, sequence-number bookkeeping and the
// protocol invariants (the deprecated FOLLOW status, generic ERROR packets,
// the UNENCRYPTED flag policy).
package server
