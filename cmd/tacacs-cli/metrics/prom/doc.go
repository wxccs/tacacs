// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

// Package prom implements the server.Metrics interface using Prometheus
// counters, gauges and histograms. It is kept out of the library core so
// the server package has zero external metrics dependencies; CLI binaries
// that want Prometheus export import this package and inject via
// server.Config.Metrics.
package prom
