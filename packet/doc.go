// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package packet implements the TACACS+ packet header and body marshalling
// defined by RFC 8907.
//
// The Header is a fixed 12-byte structure: a packed version byte (major in the
// high nibble, minor in the low nibble), the packet type, the sequence number,
// the header flags, a 4-byte session id and a 4-byte body length, all in network
// (big-endian) byte order. The length field counts only the body, not the
// header itself.
//
// Each packet body type (Authentication START/CONTINUE/REPLY, Authorization
// REQUEST/REPLY, Accounting REQUEST/REPLY) implements the Body interface with a
// Marshal and Unmarshal method that reads and writes the exact field layout and
// length-prefix scheme specified by RFC 8907 §5-8.
package packet
