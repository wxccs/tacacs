// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package prom

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/wxccs/tacacs/server"
	"github.com/wxccs/tacacs/types"
)

const namespace = "tacacs"

// Metrics is a Prometheus-backed implementation of server.Metrics. A nil
// Metrics is never produced; use server.NopMetrics for a silent default.
type Metrics struct {
	packetReceived  *prometheus.CounterVec
	packetInvalid   *prometheus.CounterVec
	authenStatus    *prometheus.CounterVec
	authorStatus    *prometheus.CounterVec
	acctStatus      *prometheus.CounterVec
	secretLookup    *prometheus.CounterVec
	sessionDuration prometheus.Histogram
	sessionActive   prometheus.Gauge
}

// New registers a fresh set of Prometheus collectors on the default
// registry and returns a Metrics. Calling New twice panics (duplicate
// registration); use a single instance per process.
func New() *Metrics {
	m := &Metrics{
		packetReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_received_total",
			Help:      "Total number of TACACS+ packets received by type.",
		}, []string{"type"}),
		packetInvalid: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_invalid_total",
			Help:      "Total number of invalid packets by reason.",
		}, []string{"reason"}),
		authenStatus: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "authen_status_total",
			Help:      "Total authentication replies by status.",
		}, []string{"status"}),
		authorStatus: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "author_status_total",
			Help:      "Total authorization replies by status.",
		}, []string{"status"}),
		acctStatus: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "acct_status_total",
			Help:      "Total accounting replies by status.",
		}, []string{"status"}),
		secretLookup: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "secret_lookup_total",
			Help:      "Total SecretProvider lookups by hit (true/false).",
		}, []string{"hit"}),
		sessionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "session_duration_seconds",
			Help:      "Wall-clock duration of expired TACACS+ sessions.",
			Buckets:   prometheus.DefBuckets,
		}),
		sessionActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "sessions_active",
			Help:      "Number of currently active sessions.",
		}),
	}
	prometheus.MustRegister(
		m.packetReceived, m.packetInvalid, m.authenStatus, m.authorStatus,
		m.acctStatus, m.secretLookup, m.sessionDuration, m.sessionActive,
	)
	return m
}

// IncPacketReceived implements server.Metrics.
func (m *Metrics) IncPacketReceived(pt types.PacketType) {
	m.packetReceived.WithLabelValues(pt.String()).Inc()
}

// IncPacketInvalid implements server.Metrics.
func (m *Metrics) IncPacketInvalid(reason string) {
	m.packetInvalid.WithLabelValues(reason).Inc()
}

// IncAuthenStatus implements server.Metrics.
func (m *Metrics) IncAuthenStatus(s types.AuthenStatus) {
	m.authenStatus.WithLabelValues(s.String()).Inc()
}

// IncAuthorStatus implements server.Metrics.
func (m *Metrics) IncAuthorStatus(s types.AuthorStatus) {
	m.authorStatus.WithLabelValues(s.String()).Inc()
}

// IncAcctStatus implements server.Metrics.
func (m *Metrics) IncAcctStatus(s types.AcctStatus) {
	m.acctStatus.WithLabelValues(s.String()).Inc()
}

// IncSecretLookup implements server.Metrics.
func (m *Metrics) IncSecretLookup(hit bool) {
	m.secretLookup.WithLabelValues(boolStr(hit)).Inc()
}

// ObserveSessionDuration implements server.Metrics.
func (m *Metrics) ObserveSessionDuration(d time.Duration) {
	m.sessionDuration.Observe(d.Seconds())
}

// IncSessionActive implements server.Metrics.
func (m *Metrics) IncSessionActive() { m.sessionActive.Inc() }

// DecSessionActive implements server.Metrics.
func (m *Metrics) DecSessionActive() { m.sessionActive.Dec() }

// Handler returns an http.Handler that exposes the registered Prometheus
// metrics on /metrics. Mount it in your HTTP server.
func Handler() http.Handler {
	return promhttp.Handler()
}

// boolStr returns "true" or "false" for use as a Prometheus label value.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Compile-time assertion that Metrics implements server.Metrics.
var _ server.Metrics = (*Metrics)(nil)
