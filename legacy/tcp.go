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

package legacy

import (
	"strings"

	"github.com/wxccs/tacacs/errors"
)

// TCPRequest is an original-TACACS ASCII request over TCP (RFC 1492 §3).
// The first line is "<version> <type> [parameters]"; the following three lines
// are the username, password and line.
type TCPRequest struct {
	Type     string // upper-case keyword: AUTH, LOGIN, CONNECT, SUPERUSER, LOGOUT, SLIPON, SLIPOFF, SLIPADDR
	Style    string // AUTH style (optional)
	DestHost string // CONNECT/SLIPON/SLIPOFF IP in dotted decimal (optional)
	DestPort string // CONNECT port in decimal (optional)
	Username string
	Password string
	Line     string // decimal line number
}

// validateFields ensures no field contains a bare CR, LF or NUL (RFC 1492 §3).
func validateFields(fields ...string) error {
	for _, f := range fields {
		if strings.ContainsAny(f, "\r\n\x00") {
			return errors.NewValidationError("tcp_request", "field contains CR/LF/NUL", errors.ErrInvalidArgument)
		}
	}
	return nil
}

// MarshalText encodes the request to its four-line ASCII form.
func (r TCPRequest) MarshalText() ([]byte, error) {
	if err := validateFields(r.Type, r.Style, r.DestHost, r.DestPort, r.Username, r.Password, r.Line); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteByte(byte('0' + TCPVersion))
	b.WriteByte(' ')
	b.WriteString(strings.ToUpper(r.Type))
	if r.Type == "AUTH" && r.Style != "" {
		b.WriteByte(' ')
		b.WriteString(r.Style)
	}
	if (r.Type == "CONNECT" || r.Type == "SLIPON" || r.Type == "SLIPOFF") && r.DestHost != "" {
		b.WriteByte(' ')
		b.WriteString(r.DestHost)
	}
	if r.Type == "CONNECT" && r.DestPort != "" {
		b.WriteByte(' ')
		b.WriteString(r.DestPort)
	}
	b.WriteString(CRLF)
	b.WriteString(r.Username)
	b.WriteString(CRLF)
	b.WriteString(r.Password)
	b.WriteString(CRLF)
	b.WriteString(r.Line)
	b.WriteString(CRLF)
	return []byte(b.String()), nil
}

// UnmarshalText decodes a four-line ASCII request.
func (r *TCPRequest) UnmarshalText(data []byte) error {
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\r\n")
	if len(lines) < 4 {
		return errors.NewValidationError("tcp_request", "expected 4 lines", errors.ErrInvalidPacket)
	}
	if err := validateFields(lines...); err != nil {
		return err
	}
	first := strings.Fields(lines[0])
	if len(first) < 2 {
		return errors.NewValidationError("tcp_request", "first line malformed", errors.ErrInvalidPacket)
	}
	// first[0] is the version "1".
	r.Type = strings.ToUpper(first[1])
	rest := first[2:]
	// Assign remaining parameters per type.
	switch r.Type {
	case "AUTH":
		if len(rest) > 0 {
			r.Style = rest[0]
		}
	case "CONNECT":
		if len(rest) > 0 {
			r.DestHost = rest[0]
		}
		if len(rest) > 1 {
			r.DestPort = rest[1]
		}
	case "SLIPON", "SLIPOFF":
		if len(rest) > 0 {
			r.DestHost = rest[0]
		}
	}
	r.Username = lines[1]
	r.Password = lines[2]
	r.Line = lines[3]
	return nil
}

// TCPReply is an original-TACACS ASCII reply over TCP (RFC 1492 §3.2):
// "<3-digit-code> [text]\r\n". The code completely determines the result; the
// text is human commentary.
type TCPReply struct {
	Code string // exactly three decimal digits
	Text string // optional, printable
}

// MarshalText encodes the reply.
func (r TCPReply) MarshalText() ([]byte, error) {
	if len(r.Code) != 3 {
		return nil, errors.NewValidationError("tcp_reply", "code must be 3 digits", errors.ErrInvalidArgument)
	}
	if err := validateFields(r.Code, r.Text); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(r.Code)
	if r.Text != "" {
		b.WriteByte(' ')
		b.WriteString(r.Text)
	}
	b.WriteString(CRLF)
	return []byte(b.String()), nil
}

// UnmarshalText decodes a reply line.
func (r *TCPReply) UnmarshalText(data []byte) error {
	line := strings.TrimRight(string(data), "\r\n")
	if len(line) < 3 {
		return errors.NewValidationError("tcp_reply", "short line", errors.ErrInvalidPacket)
	}
	r.Code = line[:3]
	if len(line) > 3 {
		// Skip the single separating space if present.
		rest := line[3:]
		rest = strings.TrimPrefix(rest, " ")
		r.Text = rest
	}
	return nil
}

// Accepted reports whether the reply is a positive completion (2xx).
func (r TCPReply) Accepted() bool { return len(r.Code) == 3 && r.Code[0] == '2' }

// Transient reports whether the reply is a transient negative (4xx).
func (r TCPReply) Transient() bool { return len(r.Code) == 3 && r.Code[0] == '4' }

// Permanent reports whether the reply is a permanent negative (5xx).
func (r TCPReply) Permanent() bool { return len(r.Code) == 3 && r.Code[0] == '5' }
