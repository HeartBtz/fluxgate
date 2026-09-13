// Package metrics définit l'instrumentation Prometheus de FluxGate.
//
// Métriques exposées :
//   - fluxgate_http_requests_total     : compteur de requêtes HTTP (method, path, status)
//   - fluxgate_http_request_duration_seconds : histogramme de latence
//   - fluxgate_uploads_total / upload_bytes_total / upload_errors_total
//   - fluxgate_downloads_total / download_bytes_total / active_downloads
//   - fluxgate_storage_used_bytes / files_total
//   - fluxgate_auth_failures_total     : par type (jwt, apikey, password)
//   - fluxgate_links_created_total / links_expired_total
package metrics

import (
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fluxgate_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fluxgate_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// Upload metrics
	UploadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_uploads_total",
		Help: "Total number of file uploads",
	})

	UploadBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_upload_bytes_total",
		Help: "Total bytes uploaded",
	})

	UploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_upload_errors_total",
		Help: "Total upload errors",
	})

	// Download metrics
	DownloadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_downloads_total",
		Help: "Total number of file downloads",
	})

	DownloadBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_download_bytes_total",
		Help: "Total bytes downloaded",
	})

	ActiveDownloads = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fluxgate_active_downloads",
		Help: "Currently active downloads",
	})

	DownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_download_errors_total",
		Help: "Total download errors",
	})

	// Storage metrics
	StorageUsedBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fluxgate_storage_used_bytes",
		Help: "Total storage used in bytes",
	})

	FilesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fluxgate_files_total",
		Help: "Total number of files stored",
	})

	// Auth metrics
	AuthFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fluxgate_auth_failures_total",
			Help: "Total authentication failures",
		},
		[]string{"type"},
	)

	// Link metrics
	LinksCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_links_created_total",
		Help: "Total download links created",
	})

	LinksExpired = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fluxgate_links_expired_total",
		Help: "Total download links expired",
	})
)

// InstrumentHandler wraps an HTTP handler with Prometheus metrics
func InstrumentHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &metricsResponseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(wrapped.statusCode)

		// Normalize path to avoid high cardinality
		path, method := metricLabels(r)

		HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
		HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
	})
}

// Handler returns the Prometheus HTTP handler
func Handler() http.Handler {
	return promhttp.Handler()
}

type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *metricsResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *metricsResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom implements io.ReaderFrom so that io.Copy can use sendfile(2)
// for zero-copy streaming when the underlying ResponseWriter supports it.
func (w *metricsResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(w.ResponseWriter, src)
}

// Unwrap returns the underlying ResponseWriter, enabling Go 1.20+
// http.ResponseController to discover capabilities (Flush, sendfile, etc.)
func (w *metricsResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func metricLabels(r *http.Request) (string, string) {
	path := "unmatched"
	if route := chi.RouteContext(r.Context()); route != nil && route.RoutePattern() != "" {
		path = route.RoutePattern()
	}
	method := r.Method
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
	default:
		method = "OTHER"
	}
	return path, method
}
