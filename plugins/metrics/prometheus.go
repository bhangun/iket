package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusPlugin implements a metrics collection plugin using Prometheus
type PrometheusPlugin struct {
	name            string
	metricsPath     string
	metricsPort     int
	server          *http.Server
	requestCounter  *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.SummaryVec
}

// Plugin is the exported symbol for the plugin system to load
var Plugin PrometheusPlugin

// Name returns the plugin name
func (p PrometheusPlugin) Name() string {
	return p.name
}

// Initialize sets up the Prometheus metrics with the provided configuration
func (p *PrometheusPlugin) Initialize(config map[string]interface{}) error {
	p.name = "prometheus-metrics"

	// Set default values
	p.metricsPath = "/metrics"
	p.metricsPort = 9090

	// Override with provided configuration
	if path, ok := config["metricsPath"].(string); ok {
		p.metricsPath = path
	}

	if port, ok := config["metricsPort"].(float64); ok {
		p.metricsPort = int(port)
	}

	// Initialize metrics
	p.requestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	p.requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	p.responseSize = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "gateway_http_response_size_bytes",
			Help:       "HTTP response size in bytes",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method", "path"},
	)

	// Start metrics server
	go p.startMetricsServer()

	log.Printf("Prometheus metrics plugin initialized: serving metrics at :%d%s",
		p.metricsPort, p.metricsPath)
	return nil
}

// startMetricsServer starts a separate HTTP server for exposing Prometheus metrics
func (p *PrometheusPlugin) startMetricsServer() {
	mux := http.NewServeMux()
	mux.Handle(p.metricsPath, promhttp.Handler())

	p.server = &http.Server{
		Addr:    ":" + strconv.Itoa(p.metricsPort),
		Handler: mux,
	}

	if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Failed to start metrics server: %v", err)
	}
}

// Middleware returns a middleware function that collects metrics
func (p *PrometheusPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture metrics
			mw := newMetricsResponseWriter(w)

			// Process the request
			next.ServeHTTP(mw, r)

			// Record metrics
			duration := time.Since(start).Seconds()
			statusCode := strconv.Itoa(mw.statusCode)

			p.requestCounter.WithLabelValues(r.Method, r.URL.Path, statusCode).Inc()
			p.requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
			p.responseSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(mw.bytesWritten))
		})
	}
}

// metricsResponseWriter is a custom ResponseWriter that captures metrics
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func newMetricsResponseWriter(w http.ResponseWriter) *metricsResponseWriter {
	return &metricsResponseWriter{w, http.StatusOK, 0}
}

func (mw *metricsResponseWriter) WriteHeader(code int) {
	mw.statusCode = code
	mw.ResponseWriter.WriteHeader(code)
}

func (mw *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := mw.ResponseWriter.Write(b)
	mw.bytesWritten += n
	return n, err
}

// Shutdown stops the metrics server
func (p *PrometheusPlugin) Shutdown() error {
	log.Println("Shutting down Prometheus metrics plugin")
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}
