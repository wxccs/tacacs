// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

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
