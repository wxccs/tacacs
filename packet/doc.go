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
