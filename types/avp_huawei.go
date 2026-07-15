// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package types

// Huawei HWTACACS vendor-specific AV pairs. These attributes are listed in the
// Huawei HWTACACS attribute table and are specific to Huawei VRP devices; they
// are not part of the Cisco TACACS+ AV pair set. Attributes shared between
// Cisco and Huawei (acl, addr, addr-pool, autocmd, callback-line, dns-servers,
// gw-password, idletime, ip-addresses, nocallback-verify, nohangup, source-ip,
// tunnel-id) are defined in avp.go as common pairs, not here.
//
// Source: S1700/S5700/S6700 V600R025C00 产品文档 - HWTACACS属性
// (galaxy_aaa_cfg_0042.html, attribute-definition table).
//
// Huawei also uses the underscore spelling for the disconnect-cause accounting
// pairs (disc_cause, disc_cause_ext); those name constants live in avp.go as
// the Huawei side of the dual-naming pair.

// Huawei-specific AV pair names. dnaverage/dnpeak/upaverage/uppeak report link
// rates in bit/s; tunnel-type describes the VPDN tunnel type; ftpdir sets the
// FTP user's initial directory.
const (
	ArgNameDnAverage  ArgName = "dnaverage"
	ArgNameDnPeak     ArgName = "dnpeak"
	ArgNameUpAverage  ArgName = "upaverage"
	ArgNameUpPeak     ArgName = "uppeak"
	ArgNameTunnelType ArgName = "tunnel-type"
	ArgNameFtpDir     ArgName = "ftpdir"
)
