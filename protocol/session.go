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

package protocol

import (
	"crypto/rand"

	"github.com/wxccs/tacacs/errors"
)

// maxSeqNo is the largest sequence number before the session must terminate
// and restart (RFC 8907 §11: the sequence number must never wrap).
const maxSeqNo byte = 255

// Role indicates which side of a TACACS+ session a peer is acting as. It
// determines the parity of sequence numbers it sends: clients send odd values,
// servers send even values (RFC 8907 §11).
type Role int

// Client and Server roles.
const (
	RoleClient Role = iota
	RoleServer
)

// Session tracks the per-session state of a single TACACS+ exchange: the
// session id (constant for the session) and the next sequence number to send.
// It is not safe for concurrent use by multiple goroutines; callers must
// serialize access (one session per request/response exchange).
type Session struct {
	// SessionID is the cryptographically random session id, constant for the
	// duration of the session (RFC 8907 §11).
	SessionID uint32
	// Role is the peer role (client or server).
	Role Role
	// nextSeq is the next sequence number the local peer will send. It is an int
	// (not a byte) so that exceeding 255 can be detected instead of wrapping:
	// per RFC 8907 §11 the sequence number must never wrap.
	nextSeq int
}

// NewSession creates a session for the given role with a fresh, cryptographically
// random session id and the initial sequence number for that role: clients start
// at 1 (odd), servers start at 2 (even) — the server's first packet is always
// a response to the client's START, so it begins one step ahead.
func NewSession(role Role) (*Session, error) {
	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	s := &Session{SessionID: id, Role: role}
	s.nextSeq = s.initialSeq()
	return s, nil
}

// NewSessionWithID creates a session adopting an existing session id (for
// example, a server responding within a session a client opened). The initial
// sequence number is set for the given role.
func NewSessionWithID(role Role, sessionID uint32) *Session {
	s := &Session{SessionID: sessionID, Role: role}
	s.nextSeq = s.initialSeq()
	return s
}

// initialSeq returns the first sequence number for the role: clients start at
// 1, servers start at 2 (their first packet is the reply to seq_no 1).
func (s *Session) initialSeq() int {
	if s.Role == RoleClient {
		return 1
	}
	return 2
}

// NextSeq returns the sequence number the local peer should use for its next
// outbound packet, and advances the internal counter by 2 (preserving the
// client-odd/server-even parity, since the peer sends the in-between value).
//
// It returns ErrInvalidSeqNo if the counter would exceed 255; per RFC 8907 §11
// the sequence number must never wrap, so the session must terminate and restart.
func (s *Session) NextSeq() (byte, error) {
	if s.nextSeq > int(maxSeqNo) {
		return 0, errors.NewValidationError("seq_no", "session must restart (reached 255)", errors.ErrInvalidSeqNo)
	}
	cur := s.nextSeq
	s.nextSeq += 2
	return byte(cur), nil
}

// PeekSeq returns the next sequence number without advancing the counter.
func (s *Session) PeekSeq() byte { return byte(s.nextSeq) }

// ExpectSeq reports whether an incoming sequence number is valid for the peer
// role: a client expects even (server) values; a server expects odd (client)
// values, and the value must be the one it is waiting for.
func (s *Session) ExpectSeq(in byte) bool {
	if s.Role == RoleClient {
		return in%2 == 0
	}
	return in%2 == 1
}

// randomSessionID returns a cryptographically random 32-bit session id per RFC
// 8907 §11 (see RFC 4086).
func randomSessionID() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}
