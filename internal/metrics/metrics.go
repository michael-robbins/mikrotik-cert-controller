// Package metrics defines Prometheus metrics for the cert-controller.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// SyncsTotal counts certificate sync operations per router.
	SyncsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certsync_syncs_total",
			Help: "Total number of certificate sync operations",
		},
		[]string{"router", "status"},
	)

	// SyncDuration tracks how long sync operations take.
	SyncDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "certsync_sync_duration_seconds",
			Help:    "Duration of certificate sync operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"router"},
	)

	// CertExpiry tracks certificate expiry time as a Unix timestamp.
	CertExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certsync_cert_expiry_seconds",
			Help: "Certificate expiry time as Unix timestamp",
		},
		[]string{"cert_name", "router"},
	)

	// ErrorsTotal counts errors during sync operations.
	ErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certsync_errors_total",
			Help: "Total number of sync errors",
		},
		[]string{"router", "operation"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		SyncsTotal,
		SyncDuration,
		CertExpiry,
		ErrorsTotal,
	)
}
