// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHuaweiArgNames asserts every Huawei-specific AVP name constant carries
// the exact wire string the HWTACACS attribute table expects. Source: Huawei
// HWTACACS attribute table (S-series V600R025 product documentation). Note:
// tunnel-id is NOT here - it is shared with Cisco and lives in avp.go.
func TestHuaweiArgNames(t *testing.T) {
	cases := []struct {
		name  ArgName
		value string
	}{
		{ArgNameDnAverage, "dnaverage"},
		{ArgNameDnPeak, "dnpeak"},
		{ArgNameUpAverage, "upaverage"},
		{ArgNameUpPeak, "uppeak"},
		{ArgNameTunnelType, "tunnel-type"},
		{ArgNameFtpDir, "ftpdir"},
	}
	assert.Equal(t, 6, len(cases), "expected 6 Huawei-only AVP name constants")
	for _, c := range cases {
		assert.Equalf(t, c.value, string(c.name), "constant %q has wrong value", c.value)
	}
}
