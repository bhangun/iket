package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Define Prometheus metrics
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"code", "method", "path"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code", "method", "path"},
	)

	httpResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "Size of HTTP responses in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"code", "method", "path"},
	)

	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_active_connections",
			Help: "Number of active HTTP connections",
		},
	)
)

func init() {
	// Register the metrics with Prometheus
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(httpResponseSize)
	prometheus.MustRegister(activeConnections)
}

// Metrics collects and exposes gateway metrics
type Metrics struct {
	requestCount    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
	activeRequests  *prometheus.GaugeVec

	graphqlQueriesTotal  *prometheus.CounterVec
	graphqlQueryDuration *prometheus.HistogramVec
	graphqlErrorsTotal   prometheus.Counter
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	m := &Metrics{
		requestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_requests_total",
				Help: "Total number of requests processed by the gateway",
			},
			[]string{"method", "path", "status"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "gateway_request_duration_seconds",
				Help: "Duration of requests processed by the gateway",
			},
			[]string{"method", "path"},
		),
		responseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "gateway_response_size_bytes",
				Help: "Size of responses returned by the gateway",
			},
			[]string{"method", "path"},
		),
		activeRequests: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_active_requests",
				Help: "Number of active requests being processed by the gateway",
			},
			[]string{"method"},
		),

		graphqlQueriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "graphql_queries_total",
				Help: "Total GraphQL queries processed",
			},
			[]string{"operation"},
		),
		graphqlQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "graphql_query_duration_seconds",
				Help:    "GraphQL query processing time",
				Buckets: []float64{0.1, 0.5, 1, 5, 10},
			},
			[]string{"operation"},
		),
		graphqlErrorsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "graphql_errors_total",
				Help: "Total GraphQL errors encountered",
			},
		),
	}

	// Register all metrics
	prometheus.MustRegister(m.requestCount)
	prometheus.MustRegister(m.requestDuration)
	prometheus.MustRegister(m.responseSize)
	prometheus.MustRegister(m.activeRequests)

	prometheus.MustRegister(
		m.graphqlQueriesTotal,
		m.graphqlQueryDuration,
		m.graphqlErrorsTotal,
	)

	return m
}

func (m *Metrics) ObserveGraphQLQuery(duration time.Duration, hasErrors bool) {
	// This would be enhanced to track specific operations
	m.graphqlQueryDuration.WithLabelValues("query").Observe(duration.Seconds())
	m.graphqlQueriesTotal.WithLabelValues("query").Inc()
	if hasErrors {
		m.graphqlErrorsTotal.Inc()
	}
}
