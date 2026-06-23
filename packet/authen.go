// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import "github.com/wxccs/tacacs/errors"

// AuthenStart is the Authentication START body (client -> server, seq_no 1).
// Fixed part is 8 bytes; the four length fields are single bytes.
//
//	action | priv_lvl | authen_type | authen_service
//	user_len | port_len | rem_addr_len | data_len
//	user | port | rem_addr | data
type AuthenStart struct {
	Action  typesAuthenAction
	PrivLvl typesPrivLevel
	Type    typesAuthenType
	Service typesAuthenService
	User    string
	Port    string
	RemAddr string
	Data    string
}

// MarshalBinary encodes the START body.
func (a AuthenStart) MarshalBinary() ([]byte, error) {
	if err := checkByteLen(len(a.User)); err != nil {
		return nil, err
	}
	if err := checkByteLen(len(a.Port)); err != nil {
		return nil, err
	}
	if err := checkByteLen(len(a.RemAddr)); err != nil {
		return nil, err
	}
	if err := checkByteLen(len(a.Data)); err != nil {
		return nil, err
	}
	b := make([]byte, 8+len(a.User)+len(a.Port)+len(a.RemAddr)+len(a.Data))
	b[0] = byte(a.Action)
	b[1] = byte(a.PrivLvl)
	b[2] = byte(a.Type)
	b[3] = byte(a.Service)
	b[4] = byte(len(a.User))
	b[5] = byte(len(a.Port))
	b[6] = byte(len(a.RemAddr))
	b[7] = byte(len(a.Data))
	pos := 8
	pos += copy(b[pos:], a.User)
	pos += copy(b[pos:], a.Port)
	pos += copy(b[pos:], a.RemAddr)
	copy(b[pos:], a.Data)
	return b, nil
}

// UnmarshalBinary decodes the START body.
func (a *AuthenStart) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.NewValidationError("authen_start", "short buffer", errors.ErrInvalidPacket)
	}
	a.Action = typesAuthenAction(data[0])
	a.PrivLvl = typesPrivLevel(data[1])
	a.Type = typesAuthenType(data[2])
	a.Service = typesAuthenService(data[3])
	ul, pl, rl, dl := int(data[4]), int(data[5]), int(data[6]), int(data[7])
	if 8+ul+pl+rl+dl != len(data) {
		return errors.NewValidationError("authen_start", "length mismatch", errors.ErrInvalidLength)
	}
	pos := 8
	a.User = string(data[pos : pos+ul])
	pos += ul
	a.Port = string(data[pos : pos+pl])
	pos += pl
	a.RemAddr = string(data[pos : pos+rl])
	pos += rl
	a.Data = string(data[pos : pos+dl])
	return nil
}

// AuthenContinue is the Authentication CONTINUE body (client -> server).
// Fixed part is 5 bytes; user_msg_len and data_len are 2-byte big-endian.
//
//	user_msg_len(2) | data_len(2) | flags(1)
//	user_msg | data
type AuthenContinue struct {
	UserMsg string
	Data    string
	Flags   byte
}

// MarshalBinary encodes the CONTINUE body.
func (a AuthenContinue) MarshalBinary() ([]byte, error) {
	if err := checkU16Len(len(a.UserMsg)); err != nil {
		return nil, err
	}
	if err := checkU16Len(len(a.Data)); err != nil {
		return nil, err
	}
	b := make([]byte, 5+len(a.UserMsg)+len(a.Data))
	b[0] = byte(len(a.UserMsg) >> 8)
	b[1] = byte(len(a.UserMsg))
	b[2] = byte(len(a.Data) >> 8)
	b[3] = byte(len(a.Data))
	b[4] = a.Flags
	pos := 5
	pos += copy(b[pos:], a.UserMsg)
	copy(b[pos:], a.Data)
	return b, nil
}

// UnmarshalBinary decodes the CONTINUE body.
func (a *AuthenContinue) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return errors.NewValidationError("authen_continue", "short buffer", errors.ErrInvalidPacket)
	}
	ul := int(data[0])<<8 | int(data[1])
	dl := int(data[2])<<8 | int(data[3])
	if 5+ul+dl != len(data) {
		return errors.NewValidationError("authen_continue", "length mismatch", errors.ErrInvalidLength)
	}
	a.Flags = data[4]
	pos := 5
	a.UserMsg = string(data[pos : pos+ul])
	pos += ul
	a.Data = string(data[pos : pos+dl])
	return nil
}

// AuthenReply is the Authentication REPLY body (server -> client).
// Fixed part is 6 bytes; server_msg_len and data_len are 2-byte big-endian.
//
//	status(1) | flags(1) | server_msg_len(2) | data_len(2)
//	server_msg | data
type AuthenReply struct {
	Status    typesAuthenStatus
	Flags     byte
	ServerMsg string
	Data      string
}

// MarshalBinary encodes the REPLY body.
func (a AuthenReply) MarshalBinary() ([]byte, error) {
	if err := checkU16Len(len(a.ServerMsg)); err != nil {
		return nil, err
	}
	if err := checkU16Len(len(a.Data)); err != nil {
		return nil, err
	}
	b := make([]byte, 6+len(a.ServerMsg)+len(a.Data))
	b[0] = byte(a.Status)
	b[1] = a.Flags
	b[2] = byte(len(a.ServerMsg) >> 8)
	b[3] = byte(len(a.ServerMsg))
	b[4] = byte(len(a.Data) >> 8)
	b[5] = byte(len(a.Data))
	pos := 6
	pos += copy(b[pos:], a.ServerMsg)
	copy(b[pos:], a.Data)
	return b, nil
}

// UnmarshalBinary decodes the REPLY body.
func (a *AuthenReply) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return errors.NewValidationError("authen_reply", "short buffer", errors.ErrInvalidPacket)
	}
	a.Status = typesAuthenStatus(data[0])
	a.Flags = data[1]
	ml := int(data[2])<<8 | int(data[3])
	dl := int(data[4])<<8 | int(data[5])
	if 6+ml+dl != len(data) {
		return errors.NewValidationError("authen_reply", "length mismatch", errors.ErrInvalidLength)
	}
	pos := 6
	a.ServerMsg = string(data[pos : pos+ml])
	pos += ml
	a.Data = string(data[pos : pos+dl])
	return nil
}
