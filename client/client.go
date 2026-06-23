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

package client

import (
	"context"
	"fmt"

	"github.com/wxccs/tacacs/errors"
	"github.com/wxccs/tacacs/packet"
	"github.com/wxccs/tacacs/protocol"
	"github.com/wxccs/tacacs/transport"
	"github.com/wxccs/tacacs/types"
)

// Client is a high-level TACACS+ client bound to an established transport.Conn.
type Client struct {
	conn *transport.Conn
	sess *protocol.Session
}

// New creates a Client over an established connection, starting a fresh
// client session (odd sequence numbers from 1).
func New(c *transport.Conn) (*Client, error) {
	sess, err := protocol.NewSession(protocol.RoleClient)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c, sess: sess}, nil
}

// Conn returns the underlying transport connection.
func (c *Client) Conn() *transport.Conn { return c.conn }

// Authenticate performs a single authentication exchange. For ASCII it follows
// the interactive CONTINUE/REPLY loop driven by contFn, which is called with
// each non-terminal REPLY to produce the next CONTINUE's user message. For
// PAP/CHAP/MSCHAP/MSCHAPv2 the exchange is a single START+REPLY and contFn is
// not called.
func (c *Client) Authenticate(ctx context.Context, req AuthenRequest, contFn func(reply AuthenReply) (string, error)) (AuthenReply, error) {
	minor := types.MinorVersionFor(req.Type)
	version := types.Version(types.MajorVersion<<4 | minor)

	start := packet.AuthenStart{
		Action: req.Action, PrivLvl: req.PrivLvl, Type: req.Type, Service: req.Service,
		User: req.User, Port: req.Port, RemAddr: req.RemAddr, Data: string(req.Data),
	}
	sb, err := start.MarshalBinary()
	if err != nil {
		return AuthenReply{}, err
	}

	// Send START.
	if err := c.send(ctx, version, types.PacketAuthentication, sb); err != nil {
		return AuthenReply{}, err
	}

	for {
		hdr, body, err := c.conn.ReadPacket()
		if err != nil {
			return AuthenReply{}, err
		}
		if int(hdr.Length) == 0 {
			// Generic header-only error packet.
			return AuthenReply{}, errors.NewValidationError("authen", "server returned error packet", errors.ErrInvalidPacket)
		}
		var reply packet.AuthenReply
		if err := reply.UnmarshalBinary(body); err != nil {
			return AuthenReply{}, err
		}
		status := protocol.NormalizeAuthenStatus(types.AuthenStatus(reply.Status))
		r := AuthenReply{
			Status: status, Flags: reply.Flags, ServerMsg: reply.ServerMsg, Data: []byte(reply.Data),
		}
		if protocol.IsTerminal(status) {
			return r, nil
		}
		if status == types.AuthenStatusRestart {
			return r, errors.NewValidationError("authen", "server requested RESTART", errors.ErrInvalidPacket)
		}
		// Non-terminal: GETUSER/GETPASS/GETDATA -> send a CONTINUE.
		if contFn == nil {
			return r, fmt.Errorf("tacacs: authentication requires a CONTINUE but no contFn was provided (status %d)", status)
		}
		msg, err := contFn(r)
		if err != nil {
			return r, err
		}
		cont := packet.AuthenContinue{UserMsg: msg}
		cb, err := cont.MarshalBinary()
		if err != nil {
			return r, err
		}
		if err := c.send(ctx, version, types.PacketAuthentication, cb); err != nil {
			return r, err
		}
	}
}

// Authorize performs a single authorization request/reply.
func (c *Client) Authorize(ctx context.Context, req AuthorRequest) (AuthorResult, error) {
	args := make([]string, 0, len(req.Args))
	for _, a := range req.Args {
		args = append(args, a.String())
	}
	pktReq := packet.AuthorRequest{
		Method: req.Method, PrivLvl: req.PrivLvl, Type: req.Type, Service: req.Service,
		User: req.User, Port: req.Port, RemAddr: req.RemAddr, Args: args,
	}
	sb, err := pktReq.MarshalBinary()
	if err != nil {
		return AuthorResult{}, err
	}
	version := types.VersionDefault // authorization always uses minor version 0
	if err := c.send(ctx, version, types.PacketAuthorization, sb); err != nil {
		return AuthorResult{}, err
	}
	hdr, body, err := c.conn.ReadPacket()
	if err != nil {
		return AuthorResult{}, err
	}
	if int(hdr.Length) == 0 {
		return AuthorResult{}, errors.NewValidationError("author", "server returned error packet", errors.ErrInvalidPacket)
	}
	var reply packet.AuthorReply
	if err := reply.UnmarshalBinary(body); err != nil {
		return AuthorResult{}, err
	}
	status := protocol.NormalizeAuthorStatus(types.AuthorStatus(reply.Status))
	result := AuthorResult{Status: status, ServerMsg: reply.ServerMsg}
	for _, a := range reply.Args {
		parsed, perr := types.ParseArgument(a)
		if perr != nil {
			return result, perr
		}
		result.Args = append(result.Args, parsed)
	}
	return result, nil
}

// Account performs a single accounting request/reply.
func (c *Client) Account(ctx context.Context, req AcctRequest) (AcctResult, error) {
	args := make([]string, 0, len(req.Args))
	for _, a := range req.Args {
		args = append(args, a.String())
	}
	pktReq := packet.AcctRequest{
		Flags: req.Flags, Method: req.Method, PrivLvl: req.PrivLvl, Type: req.Type, Service: req.Service,
		User: req.User, Port: req.Port, RemAddr: req.RemAddr, Args: args,
	}
	sb, err := pktReq.MarshalBinary()
	if err != nil {
		return AcctResult{}, err
	}
	version := types.VersionDefault // accounting always uses minor version 0
	if err := c.send(ctx, version, types.PacketAccounting, sb); err != nil {
		return AcctResult{}, err
	}
	hdr, body, err := c.conn.ReadPacket()
	if err != nil {
		return AcctResult{}, err
	}
	if int(hdr.Length) == 0 {
		return AcctResult{}, errors.NewValidationError("acct", "server returned error packet", errors.ErrInvalidPacket)
	}
	var reply packet.AcctReply
	if err := reply.UnmarshalBinary(body); err != nil {
		return AcctResult{}, err
	}
	status := protocol.NormalizeAcctStatus(types.AcctStatus(reply.Status))
	return AcctResult{Status: status, ServerMsg: reply.ServerMsg}, nil
}

// send marshals the header with the next client sequence number and writes the
// packet. For legacy mode the Conn obfuscates the body; for TLS it forces the
// unencrypted flag.
func (c *Client) send(ctx context.Context, version types.Version, ptype types.PacketType, body []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	seq, err := c.sess.NextSeq()
	if err != nil {
		return err
	}
	hdr := packet.Header{
		Version: version, Type: ptype, SeqNo: seq, Flags: 0,
		SessionID: c.sess.SessionID,
	}
	return c.conn.WritePacket(hdr, body)
}

// AuthenRequest is the high-level authentication request for a client.
type AuthenRequest struct {
	Action  types.AuthenAction
	PrivLvl types.PrivLevel
	Type    types.AuthenType
	Service types.AuthenService
	User    string
	Port    string
	RemAddr string
	Data    []byte
}

// AuthenReply is the high-level authentication reply.
type AuthenReply struct {
	Status    types.AuthenStatus
	Flags     byte
	ServerMsg string
	Data      []byte
}

// AuthorRequest is the high-level authorization request.
type AuthorRequest struct {
	Method  types.AuthenMethod
	PrivLvl types.PrivLevel
	Type    types.AuthenType
	Service types.AuthenService
	User    string
	Port    string
	RemAddr string
	Args    []types.Argument
}

// AuthorResult is the high-level authorization result.
type AuthorResult struct {
	Status    types.AuthorStatus
	Args      []types.Argument
	ServerMsg string
}

// AcctRequest is the high-level accounting request.
type AcctRequest struct {
	Flags   types.AcctFlags
	Method  types.AuthenMethod
	PrivLvl types.PrivLevel
	Type    types.AuthenType
	Service types.AuthenService
	User    string
	Port    string
	RemAddr string
	Args    []types.Argument
}

// AcctResult is the high-level accounting result.
type AcctResult struct {
	Status    types.AcctStatus
	ServerMsg string
}
