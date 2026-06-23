// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 The tacacs authors.
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

import "github.com/wxccs/tacacs/errors"

// Challenge-response data field layouts (RFC 8907 §5.4.2.3-5.4.2.5). The data
// field of an authentication START for these authen_types is a concatenation of
// a PPP id (1 octet), a challenge and a response of fixed length per type.
const (
	chapResponseLen   = 16 // CHAP response is always 16 octets
	mschapResponseLen = 49 // MS-CHAP v1/v2 response is always 49 octets
	mschapV1Challenge = 8  // MS-CHAP v1 challenge MUST be 8 bytes
	mschapV2Challenge = 16 // MS-CHAP v2 challenge MUST be 16 bytes
	minCHAPChallenge  = 8  // recommended minimum CHAP challenge length
)

// CHAPData is the parsed CHAP challenge-response data field.
//
//	data = ppp_id(1) || challenge(var) || response(16)
type CHAPData struct {
	PPPID     byte
	Challenge []byte
	Response  []byte
}

// ParseCHAPData parses a CHAP data field (RFC 8907 §5.4.2.3). The challenge
// length is data_len - 1 - 16. The server SHOULD reject challenges shorter
// than 8 bytes; ParseCHAPData returns ErrInvalidArgument in that case.
func ParseCHAPData(data []byte) (CHAPData, error) {
	if len(data) < 1+minCHAPChallenge+chapResponseLen {
		return CHAPData{}, errors.NewValidationError("chap_data", "too short", errors.ErrInvalidArgument)
	}
	pppID := data[0]
	challengeLen := len(data) - 1 - chapResponseLen
	if challengeLen < minCHAPChallenge {
		return CHAPData{}, errors.NewValidationError("chap_data", "challenge below minimum 8 bytes", errors.ErrInvalidArgument)
	}
	challenge := data[1 : 1+challengeLen]
	response := data[1+challengeLen:]
	return CHAPData{PPPID: pppID, Challenge: challenge, Response: response}, nil
}

// MSCHAPData is the parsed MS-CHAP v1 challenge-response data field.
//
//	data = ppp_id(1) || challenge(8) || response(49)
type MSCHAPData struct {
	PPPID     byte
	Challenge []byte
	Response  []byte
}

// ParseMSCHAPData parses an MS-CHAP v1 data field (RFC 8907 §5.4.2.4). The
// challenge MUST be exactly 8 bytes; the server MUST reject deviations.
func ParseMSCHAPData(data []byte) (MSCHAPData, error) {
	if len(data) != 1+mschapV1Challenge+mschapResponseLen {
		return MSCHAPData{}, errors.NewValidationError("mschap_data", "challenge must be 8 bytes", errors.ErrInvalidArgument)
	}
	return MSCHAPData{
		PPPID:     data[0],
		Challenge: data[1 : 1+mschapV1Challenge],
		Response:  data[1+mschapV1Challenge:],
	}, nil
}

// MSCHAPv2Data is the parsed MS-CHAP v2 challenge-response data field.
//
//	data = ppp_id(1) || challenge(16) || response(49)
type MSCHAPv2Data struct {
	PPPID     byte
	Challenge []byte
	Response  []byte
}

// ParseMSCHAPv2Data parses an MS-CHAP v2 data field (RFC 8907 §5.4.2.5). The
// challenge MUST be exactly 16 bytes; the server MUST reject deviations.
func ParseMSCHAPv2Data(data []byte) (MSCHAPv2Data, error) {
	if len(data) != 1+mschapV2Challenge+mschapResponseLen {
		return MSCHAPv2Data{}, errors.NewValidationError("mschapv2_data", "challenge must be 16 bytes", errors.ErrInvalidArgument)
	}
	return MSCHAPv2Data{
		PPPID:     data[0],
		Challenge: data[1 : 1+mschapV2Challenge],
		Response:  data[1+mschapV2Challenge:],
	}, nil
}

// IsTerminal reports whether an authentication REPLY status terminates the
// session (PASS, FAIL, ERROR). Non-terminal statuses (GETUSER, GETPASS,
// GETDATA, RESTART) expect further exchange. FOLLOW is deprecated and treated
// as terminal FAIL by the client (see NormalizeAuthenStatus).
func IsTerminal(status AuthenStatusAlias) bool {
	switch status {
	case authenPass, authenFail, authenError:
		return true
	default:
		return false
	}
}

// NormalizeAuthenStatus applies the deprecation rules of RFC 8907 §5.4.1:
// TAC_PLUS_AUTHEN_STATUS_FOLLOW (0x21) MUST be treated as FAIL by clients.
func NormalizeAuthenStatus(status AuthenStatusAlias) AuthenStatusAlias {
	if status == authenFollow {
		return authenFail
	}
	return status
}
