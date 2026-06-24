// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionConstants(t *testing.T) {
	assert.Equal(t, byte(0x0c), MajorVersion)
	assert.Equal(t, Version(0xc0), VersionDefault)
	assert.Equal(t, Version(0xc1), VersionOne)
	assert.Equal(t, MajorVersion, VersionDefault.Major())
	assert.Equal(t, MinorVersionNone, VersionDefault.Minor())
	assert.Equal(t, MinorVersionOne, VersionOne.Minor())
	assert.True(t, VersionDefault.Valid())
	assert.True(t, VersionOne.Valid())
	assert.False(t, Version(0xc2).Valid())
	assert.False(t, Version(0x00).Valid())
}

func TestMinorVersionFor(t *testing.T) {
	assert.Equal(t, MinorVersionNone, MinorVersionFor(AuthenTypeASCII))
	assert.Equal(t, MinorVersionOne, MinorVersionFor(AuthenTypePAP))
	assert.Equal(t, MinorVersionOne, MinorVersionFor(AuthenTypeCHAP))
	assert.Equal(t, MinorVersionOne, MinorVersionFor(AuthenTypeMSCHAP))
	assert.Equal(t, MinorVersionOne, MinorVersionFor(AuthenTypeMSCHAPv2))
	assert.Equal(t, MinorVersionNone, MinorVersionFor(AuthenTypeNotSet))
}

func TestPacketTypeGoldenValues(t *testing.T) {
	assert.Equal(t, PacketType(0x01), PacketAuthentication)
	assert.Equal(t, PacketType(0x02), PacketAuthorization)
	assert.Equal(t, PacketType(0x03), PacketAccounting)
	assert.True(t, PacketAuthentication.Valid())
	assert.True(t, PacketAuthorization.Valid())
	assert.True(t, PacketAccounting.Valid())
	assert.False(t, PacketType(0x09).Valid())
	assert.Equal(t, "authentication", PacketAuthentication.String())
	assert.Equal(t, "authorization", PacketAuthorization.String())
	assert.Equal(t, "accounting", PacketAccounting.String())
	assert.Equal(t, "unknown", PacketType(0xff).String())
}

func TestHeaderFlagsGoldenValues(t *testing.T) {
	assert.Equal(t, HeaderFlags(0x01), FlagUnencrypted)
	assert.Equal(t, HeaderFlags(0x04), FlagSingleConnect)
	f := FlagUnencrypted | FlagSingleConnect
	assert.True(t, f.Has(FlagUnencrypted))
	assert.True(t, f.Has(FlagSingleConnect))
	assert.False(t, HeaderFlags(0).Has(FlagUnencrypted))
	assert.True(t, f.Valid())
	assert.True(t, HeaderFlags(0).Valid())
	assert.False(t, HeaderFlags(0x02).Valid()) // unassigned bit 0x02
	assert.False(t, HeaderFlags(0x08).Valid()) // unassigned bit 0x08
}

func TestAuthenGoldenValues(t *testing.T) {
	// actions
	assert.Equal(t, AuthenAction(0x01), AuthenLogin)
	assert.Equal(t, AuthenAction(0x02), AuthenChpass)
	assert.Equal(t, AuthenAction(0x04), AuthenSendauth)
	// types
	assert.Equal(t, AuthenType(0x01), AuthenTypeASCII)
	assert.Equal(t, AuthenType(0x02), AuthenTypePAP)
	assert.Equal(t, AuthenType(0x03), AuthenTypeCHAP)
	assert.Equal(t, AuthenType(0x05), AuthenTypeMSCHAP)
	assert.Equal(t, AuthenType(0x06), AuthenTypeMSCHAPv2)
	// services
	assert.Equal(t, AuthenService(0x01), AuthenServiceLogin)
	assert.Equal(t, AuthenService(0x02), AuthenServiceEnable)
	assert.Equal(t, AuthenService(0x03), AuthenServicePPP)
	assert.Equal(t, AuthenService(0x05), AuthenServicePT)
	assert.Equal(t, AuthenService(0x09), AuthenServiceFWProxy)
	// statuses
	assert.Equal(t, AuthenStatus(0x01), AuthenStatusPass)
	assert.Equal(t, AuthenStatus(0x02), AuthenStatusFail)
	assert.Equal(t, AuthenStatus(0x03), AuthenStatusGetData)
	assert.Equal(t, AuthenStatus(0x04), AuthenStatusGetUser)
	assert.Equal(t, AuthenStatus(0x05), AuthenStatusGetPass)
	assert.Equal(t, AuthenStatus(0x06), AuthenStatusRestart)
	assert.Equal(t, AuthenStatus(0x07), AuthenStatusError)
	assert.Equal(t, AuthenStatus(0x21), AuthenStatusFollow)
	// reply/continue flags
	assert.Equal(t, byte(0x01), ReplyFlagNoEcho)
	assert.Equal(t, byte(0x01), ContinueFlagAbort)
}

func TestPrivGoldenValues(t *testing.T) {
	assert.Equal(t, PrivLevel(0x00), PrivLevelMin)
	assert.Equal(t, PrivLevel(0x01), PrivLevelUser)
	assert.Equal(t, PrivLevel(0x0f), PrivLevelRoot)
	assert.Equal(t, PrivLevel(0x0f), PrivLevelMax)
	assert.Equal(t, PrivLevelRoot, PrivLevelMax)
}

func TestAuthorGoldenValues(t *testing.T) {
	assert.Equal(t, AuthorStatus(0x01), AuthorStatusPassAdd)
	assert.Equal(t, AuthorStatus(0x02), AuthorStatusPassRepl)
	assert.Equal(t, AuthorStatus(0x10), AuthorStatusFail)
	assert.Equal(t, AuthorStatus(0x11), AuthorStatusError)
	assert.Equal(t, AuthorStatus(0x21), AuthorStatusFollow)
	assert.Equal(t, AuthenMethod(0x06), AuthenMethodTacacsPlus)
	assert.Equal(t, AuthenMethod(0x10), AuthenMethodRadius)
	assert.Equal(t, AuthenMethod(0x20), AuthenMethodRcmd)
}

func TestAcctGoldenValues(t *testing.T) {
	assert.Equal(t, AcctFlags(0x02), AcctFlagStart)
	assert.Equal(t, AcctFlags(0x04), AcctFlagStop)
	assert.Equal(t, AcctFlags(0x08), AcctFlagWatchdog)
	assert.Equal(t, AcctFlags(0x0e), AcctFlagMask)
	assert.Equal(t, AcctStatus(0x01), AcctStatusSuccess)
	assert.Equal(t, AcctStatus(0x02), AcctStatusError)
	assert.Equal(t, AcctStatus(0x21), AcctStatusFollow)
}

func TestAcctRecordClassification(t *testing.T) {
	cases := []struct {
		flags AcctFlags
		want  AcctRecord
	}{
		{AcctFlagStart, AcctRecordStart},
		{AcctFlagStop, AcctRecordStop},
		{AcctFlagWatchdog, AcctRecordWatchdogNoUpdate},
		{AcctFlagWatchdog | AcctFlagStart, AcctRecordWatchdogWithUpdate},
		{0, AcctRecordInvalid},
		{AcctFlagStart | AcctFlagStop, AcctRecordInvalid},                    // 0x06
		{AcctFlagStop | AcctFlagWatchdog, AcctRecordInvalid},                 // 0x0c
		{AcctFlagStart | AcctFlagStop | AcctFlagWatchdog, AcctRecordInvalid}, // 0x0e
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.flags.Record(), "flags=%#02x", byte(c.flags))
	}
}

func TestSizes(t *testing.T) {
	assert.Equal(t, 12, HeaderLength)
	assert.Equal(t, 1<<16, MaxPacketSize)
	assert.Equal(t, 255, MaxArgCount)
	assert.Equal(t, 255, MaxArgLength)
	assert.Equal(t, 2, MinArgLength)
}
