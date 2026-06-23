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

// Package types holds the protocol constants and shared primitive types for
// the tacacs library: protocol versions, packet types, header flags, the
// authentication/authorization/accounting enumerations, privilege levels, the
// Argument codec, packet size limits, and the Logger interface used by the
// core library.
//
// Constant values follow RFC 8907 ("TACACS+ Protocol"). Each enumeration is a
// named type so that distinct value spaces cannot be mixed at compile time.
package types
