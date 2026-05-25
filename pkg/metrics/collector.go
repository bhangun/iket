package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector handles metrics collection for the gateway
type Collector struct {
	registry *prometheus.Registry

	// HTTP metrics
	httpRequestsTotal    *prometheus.CounterVec
	httpRequestDuration  *prometheus.HistogramVec
	httpRequestsInFlight *prometheus.GaugeVec

	// BFF metrics
	bffStepRequestsTotal *prometheus.CounterVec
	bffStepDuration      *prometheus.HistogramVec

	// Gateway metrics
	activeConnections prometheus.Gauge
	configReloads     prometheus.Counter
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	registry := prometheus.NewRegistry()

	collector := &Collector{
		registry: registry,
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		httpRequestsInFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_http_requests_in_flight",
				Help: "Current number of HTTP requests being processed",
			},
			[]string{"method", "path"},
		),
		bffStepRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_bff_step_requests_total",
				Help: "Total number of BFF upstream step requests",
			},
			[]string{"route", "step", "status", "required", "outcome"},
		),
		bffStepDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_bff_step_duration_seconds",
				Help:    "BFF upstream step request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"route", "step", "status", "required", "outcome"},
		),
		activeConnections: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_active_connections",
				Help: "Current number of active connections",
			},
		),
		configReloads: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "gateway_config_reloads_total",
				Help: "Total number of configuration reloads",
			},
		),
	}

	// Register metrics
	registry.MustRegister(
		collector.httpRequestsTotal,
		collector.httpRequestDuration,
		collector.httpRequestsInFlight,
		collector.bffStepRequestsTotal,
		collector.bffStepDuration,
		collector.activeConnections,
		collector.configReloads,
	)

	return collector
}

// ServeHTTP implements http.Handler for metrics endpoint
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// RecordRequest records an HTTP request
func (c *Collector) RecordRequest(method, path string, status int, duration float64) {
	c.httpRequestsTotal.WithLabelValues(method, path, strconv.Itoa(status)).Inc()
	c.httpRequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordBFFStep records a BFF upstream step execution.
func (c *Collector) RecordBFFStep(route, step string, status int, required bool, outcome string, duration float64) {
	if c == nil {
		return
	}
	c.bffStepRequestsTotal.WithLabelValues(route, step, strconv.Itoa(status), strconv.FormatBool(required), outcome).Inc()
	c.bffStepDuration.WithLabelValues(route, step, strconv.Itoa(status), strconv.FormatBool(required), outcome).Observe(duration)
}

// TrackRequestInFlight tracks a request in flight
func (c *Collector) TrackRequestInFlight(method, path string, inFlight bool) {
	if inFlight {
		c.httpRequestsInFlight.WithLabelValues(method, path).Inc()
	} else {
		c.httpRequestsInFlight.WithLabelValues(method, path).Dec()
	}
}

// SetActiveConnections sets the number of active connections
func (c *Collector) SetActiveConnections(count float64) {
	c.activeConnections.Set(count)
}

// IncrementConfigReloads increments the config reload counter
func (c *Collector) IncrementConfigReloads() {
	c.configReloads.Inc()
}
