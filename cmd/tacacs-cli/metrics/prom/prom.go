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
	connAccepted    prometheus.Counter
	connRejected    *prometheus.CounterVec
	acceptError     prometheus.Counter
	aaaLatency      *prometheus.HistogramVec
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
			Help:      "Total authentication replies by authentication type and status.",
		}, []string{"authen_type", "status"}),
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
		connAccepted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_accepted_total",
			Help:      "Total connections accepted and dispatched for service.",
		}),
		connRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_rejected_total",
			Help:      "Total connections rejected before service, by reason.",
		}, []string{"reason"}),
		acceptError: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "accept_errors_total",
			Help:      "Total transient listener Accept errors that triggered backoff.",
		}),
		aaaLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "aaa_handler_latency_seconds",
			Help:      "Wall-clock latency of AAA handler invocations by phase (authen/author/acct).",
			Buckets:   prometheus.DefBuckets,
		}, []string{"phase"}),
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
		m.acctStatus, m.secretLookup, m.connAccepted, m.connRejected,
		m.acceptError, m.aaaLatency, m.sessionDuration, m.sessionActive,
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
func (m *Metrics) IncAuthenStatus(at types.AuthenType, s types.AuthenStatus) {
	m.authenStatus.WithLabelValues(at.String(), s.String()).Inc()
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

// IncConnAccepted implements server.Metrics.
func (m *Metrics) IncConnAccepted() { m.connAccepted.Inc() }

// IncConnRejected implements server.Metrics.
func (m *Metrics) IncConnRejected(reason string) {
	m.connRejected.WithLabelValues(reason).Inc()
}

// IncAcceptError implements server.Metrics.
func (m *Metrics) IncAcceptError() { m.acceptError.Inc() }

// ObserveAuthenLatency implements server.Metrics.
func (m *Metrics) ObserveAuthenLatency(d time.Duration) {
	m.aaaLatency.WithLabelValues("authen").Observe(d.Seconds())
}

// ObserveAuthorLatency implements server.Metrics.
func (m *Metrics) ObserveAuthorLatency(d time.Duration) {
	m.aaaLatency.WithLabelValues("author").Observe(d.Seconds())
}

// ObserveAcctLatency implements server.Metrics.
func (m *Metrics) ObserveAcctLatency(d time.Duration) {
	m.aaaLatency.WithLabelValues("acct").Observe(d.Seconds())
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
