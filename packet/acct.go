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

package packet

import "github.com/wxccs/tacacs/errors"

// AcctRequest is the Accounting REQUEST body (client -> server, seq_no 1).
// Minor version is always 0 for accounting. Fixed part is 8 bytes (flags,
// authen_method, priv_lvl, authen_type, authen_service, user_len, port_len,
// rem_addr_len), then arg_cnt and argument lengths, then user/port/rem_addr/args.
type AcctRequest struct {
	Flags   typesAcctFlags
	Method  typesAuthenMethod
	PrivLvl typesPrivLevel
	Type    typesAuthenType
	Service typesAuthenService
	User    string
	Port    string
	RemAddr string
	Args    []string
}

// MarshalBinary encodes the accounting REQUEST body.
func (a AcctRequest) MarshalBinary() ([]byte, error) {
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
	fixed := 8 + 1 + len(a.Args)
	total := fixed + len(a.User) + len(a.Port) + len(a.RemAddr)
	for _, arg := range a.Args {
		total += len(arg)
	}
	b := make([]byte, total)
	b[0] = byte(a.Flags)
	b[1] = byte(a.Method)
	b[2] = byte(a.PrivLvl)
	b[3] = byte(a.Type)
	b[4] = byte(a.Service)
	b[5] = byte(len(a.User))
	b[6] = byte(len(a.Port))
	b[7] = byte(len(a.RemAddr))
	pos, err := encodeArgLengths(b, 8, a.Args)
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

// UnmarshalBinary decodes the accounting REQUEST body.
func (a *AcctRequest) UnmarshalBinary(data []byte) error {
	if len(data) < 9 {
		return errors.NewValidationError("acct_request", "short buffer", errors.ErrInvalidPacket)
	}
	a.Flags = typesAcctFlags(data[0])
	a.Method = typesAuthenMethod(data[1])
	a.PrivLvl = typesPrivLevel(data[2])
	a.Type = typesAuthenType(data[3])
	a.Service = typesAuthenService(data[4])
	ul := int(data[5])
	pl := int(data[6])
	rl := int(data[7])
	lengths, pos, err := decodeArgLengths(data, 8)
	if err != nil {
		return err
	}
	argTotal := 0
	for _, l := range lengths {
		argTotal += l
	}
	want := pos + ul + pl + rl + argTotal
	if want != len(data) {
		return errors.NewValidationError("acct_request", "length mismatch", errors.ErrInvalidLength)
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

// AcctReply is the Accounting REPLY body (server -> client).
// Fixed part is 5 bytes: server_msg_len(2), data_len(2), status(1), then
// server_msg and data.
type AcctReply struct {
	Status    typesAcctStatus
	ServerMsg string
	Data      string
}

// MarshalBinary encodes the accounting REPLY body.
func (a AcctReply) MarshalBinary() ([]byte, error) {
	if err := checkU16Len(len(a.ServerMsg)); err != nil {
		return nil, err
	}
	if err := checkU16Len(len(a.Data)); err != nil {
		return nil, err
	}
	b := make([]byte, 5+len(a.ServerMsg)+len(a.Data))
	b[0] = byte(len(a.ServerMsg) >> 8)
	b[1] = byte(len(a.ServerMsg))
	b[2] = byte(len(a.Data) >> 8)
	b[3] = byte(len(a.Data))
	b[4] = byte(a.Status)
	pos := 5
	pos += copy(b[pos:], a.ServerMsg)
	copy(b[pos:], a.Data)
	return b, nil
}

// UnmarshalBinary decodes the accounting REPLY body.
func (a *AcctReply) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return errors.NewValidationError("acct_reply", "short buffer", errors.ErrInvalidPacket)
	}
	ml := int(data[0])<<8 | int(data[1])
	dl := int(data[2])<<8 | int(data[3])
	if 5+ml+dl != len(data) {
		return errors.NewValidationError("acct_reply", "length mismatch", errors.ErrInvalidLength)
	}
	a.Status = typesAcctStatus(data[4])
	pos := 5
	a.ServerMsg = string(data[pos : pos+ml])
	pos += ml
	a.Data = string(data[pos : pos+dl])
	return nil
}
