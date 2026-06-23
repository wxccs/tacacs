// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.
package packet

import "github.com/wxccs/tacacs/errors"

// AuthorRequest is the Authorization REQUEST body (client -> server, seq_no 1).
// Minor version is always 0 for authorization. Fixed part is 8 bytes followed by
// arg_cnt one-byte argument lengths, then user/port/rem_addr, then the args.
//
//	authen_method | priv_lvl | authen_type | authen_service
//	user_len | port_len | rem_addr_len | arg_cnt
//	arg_1_len .. arg_N_len
//	user | port | rem_addr | arg_1 .. arg_N
type AuthorRequest struct {
	Method  typesAuthenMethod
	PrivLvl typesPrivLevel
	Type    typesAuthenType
	Service typesAuthenService
	User    string
	Port    string
	RemAddr string
	Args    []string
}

// MarshalBinary encodes the authorization REQUEST body.
func (a AuthorRequest) MarshalBinary() ([]byte, error) {
	if err := checkByteLen(len(a.User)); err != nil {
		return nil, err
	}
	if err := checkByteLen(len(a.Port)); err != nil {
		return nil, err
	}
	if err := checkByteLen(len(a.RemAddr)); err != nil {
		return nil, err
	}
	for _, arg := range a.Args {
		if err := checkByteLen(len(arg)); err != nil {
			return nil, err
		}
	}
	if len(a.Args) > 0xff {
		return nil, errors.NewValidationError("arg_cnt", "exceeds 255", errors.ErrTooManyArguments)
	}
	// Fixed part is 8 bytes; offset 7 holds arg_cnt, and the arg length bytes
	// follow at offset 8..8+len(Args).
	fixed := 8 + len(a.Args)
	total := fixed + len(a.User) + len(a.Port) + len(a.RemAddr)
	for _, arg := range a.Args {
		total += len(arg)
	}
	b := make([]byte, total)
	b[0] = byte(a.Method)
	b[1] = byte(a.PrivLvl)
	b[2] = byte(a.Type)
	b[3] = byte(a.Service)
	b[4] = byte(len(a.User))
	b[5] = byte(len(a.Port))
	b[6] = byte(len(a.RemAddr))
	pos, err := encodeArgLengths(b, 7, a.Args)
	if err != nil {
		return nil, err
	}
	pos += copy(b[pos:], a.User)
	pos += copy(b[pos:], a.Port)
	pos += copy(b[pos:], a.RemAddr)
	for _, arg := range a.Args {
		pos += copy(b[pos:], arg)
	}
	return b, nil
}

// UnmarshalBinary decodes the authorization REQUEST body.
func (a *AuthorRequest) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.NewValidationError("author_request", "short buffer", errors.ErrInvalidPacket)
	}
	a.Method = typesAuthenMethod(data[0])
	a.PrivLvl = typesPrivLevel(data[1])
	a.Type = typesAuthenType(data[2])
	a.Service = typesAuthenService(data[3])
	ul := int(data[4])
	pl := int(data[5])
	rl := int(data[6])
	lengths, pos, err := decodeArgLengths(data, 7)
	if err != nil {
		return err
	}
	argTotal := 0
	for _, l := range lengths {
		argTotal += l
	}
	want := pos + ul + pl + rl + argTotal
	if want != len(data) {
		return errors.NewValidationError("author_request", "length mismatch", errors.ErrInvalidLength)
	}
	a.User = string(data[pos : pos+ul])
	pos += ul
	a.Port = string(data[pos : pos+pl])
	pos += pl
	a.RemAddr = string(data[pos : pos+rl])
	pos += rl
	a.Args = make([]string, len(lengths))
	for i, l := range lengths {
		a.Args[i] = string(data[pos : pos+l])
		pos += l
	}
	return nil
}

// AuthorReply is the Authorization REPLY body (server -> client).
// Fixed part is 6 bytes (status, arg_cnt, server_msg_len(2), data_len(2)),
// then arg_cnt one-byte argument lengths, then server_msg, data, args.
type AuthorReply struct {
	Status    typesAuthorStatus
	ServerMsg string
	Data      string
	Args      []string
}

// MarshalBinary encodes the authorization REPLY body.
func (a AuthorReply) MarshalBinary() ([]byte, error) {
	if err := checkU16Len(len(a.ServerMsg)); err != nil {
		return nil, err
	}
	if err := checkU16Len(len(a.Data)); err != nil {
		return nil, err
	}
	for _, arg := range a.Args {
		if err := checkByteLen(len(arg)); err != nil {
			return nil, err
		}
	}
	if len(a.Args) > 0xff {
		return nil, errors.NewValidationError("arg_cnt", "exceeds 255", errors.ErrTooManyArguments)
	}
	fixed := 6 + len(a.Args)
	total := fixed + len(a.ServerMsg) + len(a.Data)
	for _, arg := range a.Args {
		total += len(arg)
	}
	b := make([]byte, total)
	b[0] = byte(a.Status)
	b[1] = byte(len(a.Args))
	b[2] = byte(len(a.ServerMsg) >> 8)
	b[3] = byte(len(a.ServerMsg))
	b[4] = byte(len(a.Data) >> 8)
	b[5] = byte(len(a.Data))
	pos := 6
	for _, arg := range a.Args {
		b[pos] = byte(len(arg))
		pos++
	}
	pos += copy(b[pos:], a.ServerMsg)
	pos += copy(b[pos:], a.Data)
	for _, arg := range a.Args {
		pos += copy(b[pos:], arg)
	}
	return b, nil
}

// UnmarshalBinary decodes the authorization REPLY body.
func (a *AuthorReply) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return errors.NewValidationError("author_reply", "short buffer", errors.ErrInvalidPacket)
	}
	a.Status = typesAuthorStatus(data[0])
	n := int(data[1])
	ml := int(data[2])<<8 | int(data[3])
	dl := int(data[4])<<8 | int(data[5])
	pos := 6
	if pos+n > len(data) {
		return errors.NewValidationError("author_reply", "arg lengths short", errors.ErrInvalidPacket)
	}
	lengths := make([]int, n)
	for i := 0; i < n; i++ {
		lengths[i] = int(data[pos])
		pos++
	}
	argTotal := 0
	for _, l := range lengths {
		argTotal += l
	}
	if pos+ml+dl+argTotal != len(data) {
		return errors.NewValidationError("author_reply", "length mismatch", errors.ErrInvalidLength)
	}
	a.ServerMsg = string(data[pos : pos+ml])
	pos += ml
	a.Data = string(data[pos : pos+dl])
	pos += dl
	a.Args = make([]string, n)
	for i, l := range lengths {
		a.Args[i] = string(data[pos : pos+l])
		pos += l
	}
	return nil
}
