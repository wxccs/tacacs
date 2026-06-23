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

// Package legacy implements the original TACACS protocol (RFC 1492), distinct
// from TACACS+ (RFC 8907). RFC 1492 defines two wire-incompatible encodings:
//
//   - a binary UDP encoding on port 49, in a "simple" (6-byte header) form and
//     an "extended" (26-byte header) form, discriminated by the version byte
//     (0 = simple, 128 = extended);
//   - an ASCII TCP encoding on a configurable port, using a four-line request
//     and a three-digit reply code.
//
// Original TACACS has no dedicated authorization phase: CONNECT, SUPERUSER and
// SLIPON request/response pairs serve as authorization-equivalent exchanges.
package legacy
