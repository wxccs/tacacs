// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package proxy implements parsing of the HAProxy PROXY protocol v1
// (ASCII), used to convey the real client address through a TCP load
// balancer. Only v1 is supported, matching the scope of tacquito's proxy
// package.
//
// Reference: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
package proxy
