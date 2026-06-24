// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package packet

import (
	"encoding/binary"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/types"
)

// HeaderLength is the fixed TACACS+ header size in bytes.
const HeaderLength = types.HeaderLength

// Header is the 12-byte TACACS+ packet header (RFC 8907 §4.4).
//
//	1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
//
// +----------------+----------------+----------------+----------------+
// |major  | minor  |      type      |     seq_no     |     flags      |
// +----------------+----------------+----------------+----------------+
// |                            session_id                             |
// +----------------+----------------+----------------+----------------+
// |                              length                               |
// +----------------+----------------+----------------+----------------+
//
// The version byte packs the major version in the high nibble and the minor
// version in the low nibble. session_id and length are big-endian. length is
// the body length, excluding the 12-byte header.
type Header struct {
	Version   types.Version
	Type      types.PacketType
	SeqNo     byte
	Flags     types.HeaderFlags
	SessionID uint32
	Length    uint32
}

// MarshalBinary encodes the header to its 12-byte wire form.
func (h Header) MarshalBinary() ([]byte, error) {
	b := make([]byte, HeaderLength)
	b[0] = byte(h.Version)
	b[1] = byte(h.Type)
	b[2] = h.SeqNo
	b[3] = byte(h.Flags)
	binary.BigEndian.PutUint32(b[4:8], h.SessionID)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
	return b, nil
}

// UnmarshalBinary parses a 12-byte header. It returns a wrapped
// ErrInvalidHeader error if the buffer is too short or the version byte is not
// a supported TACACS+ version.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderLength {
		return errors.NewValidationError("header", "short buffer", errors.ErrInvalidHeader)
	}
	h.Version = types.Version(data[0])
	if !h.Version.Valid() {
		return errors.NewValidationError("version", "unsupported version byte", errors.ErrUnsupportedVersion)
	}
	h.Type = types.PacketType(data[1])
	h.SeqNo = data[2]
	h.Flags = types.HeaderFlags(data[3])
	h.SessionID = binary.BigEndian.Uint32(data[4:8])
	h.Length = binary.BigEndian.Uint32(data[8:12])
	return nil
}

// Validate checks header invariants:
//   - the version byte is a supported TACACS+ version;
//   - the packet type is one of authentication, authorization or accounting;
//   - the body length does not exceed the recommended maximum packet size;
//   - only defined flag bits are set (undefined bits are ignored on read but
//     SHOULD be zero on write).
//
// It does not enforce the seq_no parity rules or the TAC_PLUS_UNENCRYPTED_FLAG
// policy; those are enforced by the protocol and transport layers.
func (h Header) Validate() error {
	if !h.Version.Valid() {
		return errors.NewValidationError("version", "unsupported", errors.ErrUnsupportedVersion)
	}
	if !h.Type.Valid() {
		return errors.NewValidationError("type", "unsupported", errors.ErrUnsupportedType)
	}
	if h.Length > types.MaxPacketSize {
		return errors.NewValidationError("length", "exceeds max packet size", errors.ErrInvalidLength)
	}
	if !h.Flags.Valid() {
		return errors.NewValidationError("flags", "undefined bits set", errors.ErrInvalidHeader)
	}
	return nil
}

// ErrorHeader builds the generic error packet header for a received header
// (RFC 8907 §3.6): the cleartext header is echoed back with the sequence
// number incremented by one and the length set to zero.
func ErrorHeader(in Header) Header {
	return Header{
		Version:   in.Version,
		Type:      in.Type,
		SeqNo:     in.SeqNo + 1,
		Flags:     in.Flags,
		SessionID: in.SessionID,
		Length:    0,
	}
}

// IsClient reports whether a sequence number is a client-originated (odd)
// value per RFC 8907 §11.
func IsClient(seqNo byte) bool { return seqNo%2 == 1 }

// IsServer reports whether a sequence number is a server-originated (even)
// value per RFC 8907 §11.
func IsServer(seqNo byte) bool { return seqNo%2 == 0 }
