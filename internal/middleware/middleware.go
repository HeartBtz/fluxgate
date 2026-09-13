// Package middleware fournit les middlewares HTTP de FluxGate :
//   - Recovery     : récupération des panics avec stack trace
//   - Logger       : logging structuré des requêtes (slog)
//   - SecurityHeaders : en-têtes de sécurité (CSP, X-Frame-Options, etc.)
//   - CORS         : gestion des requêtes cross-origin
//   - AuthMiddleware: vérification JWT et clés API
//   - RateLimiter  : limitation par IP (token bucket)
//   - CSRF         : protection contre les attaques CSRF
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	mu             sync.RWMutex
	visitors       map[string]*visitor
	limit          int
	window         time.Duration
	stopCh         chan struct{}
	stopOnce       sync.Once
	trustedProxies []string
}

type visitor struct {
	count       int
	windowStart time.Time
	lastSeen    time.Time
}

func NewRateLimiter(limit int, window time.Duration, trustedProxies []string) *RateLimiter {
	rl := &RateLimiter{
		visitors:       make(map[string]*visitor),
		limit:          limit,
		window:         window,
		stopCh:         make(chan struct{}),
		trustedProxies: trustedProxies,
	}

	// Cleanup goroutine with stop support
	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stopCh:
				return
			case <-ticker.C:
				rl.mu.Lock()
				for ip, v := range rl.visitors {
					if time.Since(v.lastSeen) > window {
						delete(rl.visitors, ip)
					}
				}
				rl.mu.Unlock()
			}
		}
	}()

	return rl
}

// Stop signals the rate limiter cleanup goroutine to exit
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stopCh) })
}

func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := RealIP(r, rl.trustedProxies)
		now := time.Now()

		rl.mu.Lock()
		v, exists := rl.visitors[ip]
		if !exists {
			if len(rl.visitors) >= 10000 {
				rl.mu.Unlock()
				w.Header().Set("Retry-After", "60")
				writeJSONError(w, http.StatusTooManyRequests, "rate limiter capacity reached")
				return
			}
			rl.visitors[ip] = &visitor{count: 1, windowStart: now, lastSeen: now}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		// A window is anchored to its first request. Using lastSeen here
		// permanently blocks low, steady traffic (such as a health check)
		// once its lifetime request count reaches the limit.
		if now.Sub(v.windowStart) >= rl.window {
			v.count = 1
			v.windowStart = now
			v.lastSeen = now
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		v.count++
		v.lastSeen = now

		if v.count > rl.limit {
			rl.mu.Unlock()
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rl.window.Seconds())))
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		rl.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// Logger creates structured logging middleware
func Logger(logger *slog.Logger, trustedProxies []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			logger.Info("request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", wrapped.statusCode),
				slog.Duration("duration", duration),
				slog.String("ip", RealIP(r, trustedProxies)),
				slog.String("user_agent", r.UserAgent()),
				slog.Int64("bytes", wrapped.bytesWritten),
			)
		})
	}
}

// Recovery recovers from panics
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						slog.String("stack", string(debug.Stack())),
						slog.String("request_id", GetRequestID(r.Context())),
					)
					writeJSONError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// CORS adds CORS headers with a specific allowed origin
func CORS(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestOrigin := r.Header.Get("Origin")
			if requestOrigin != "" {
				w.Header().Add("Vary", "Origin")
			}
			if allowedOrigin != "" && requestOrigin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, X-CSRF-Token, X-Filename, Upload-Offset")
				w.Header().Set("Access-Control-Expose-Headers", "Upload-Offset, Upload-Length")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security headers
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "security initialization failed", http.StatusInternalServerError)
			return
		}
		nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'", nonce))
		ctx := context.WithValue(r.Context(), contextKey("csp_nonce"), nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetCSPNonce returns the per-request script nonce generated by SecurityHeaders.
func GetCSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(contextKey("csp_nonce")).(string)
	return nonce
}

// RequestID generates or propagates a unique request ID for log correlation
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			id = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), contextKey("request_id"), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	id, _ := ctx.Value(contextKey("request_id")).(string)
	return id
}

// RealIP extracts the real client IP from request
// trustedProxies is a list of CIDR ranges or IPs that are trusted reverse proxies
func RealIP(r *http.Request, trustedProxies []string) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Only trust proxy headers if the request comes from a trusted proxy
	if len(trustedProxies) > 0 && isTrustedProxy(remoteIP, trustedProxies) {
		// Check X-Forwarded-For — take the rightmost non-trusted IP
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Walk backwards to find the first non-trusted IP
			for i := len(parts) - 1; i >= 0; i-- {
				parsed := net.ParseIP(strings.TrimSpace(parts[i]))
				if parsed == nil {
					continue
				}
				ip := parsed.String()
				if !isTrustedProxy(ip, trustedProxies) {
					return ip
				}
			}
		}

		// Check X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if parsed := net.ParseIP(strings.TrimSpace(xri)); parsed != nil {
				return parsed.String()
			}
		}
	}

	return remoteIP
}

// isTrustedProxy checks if the given IP is in the trusted proxies list
func isTrustedProxy(ip string, trusted []string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, t := range trusted {
		// Try CIDR
		if strings.Contains(t, "/") {
			_, cidr, err := net.ParseCIDR(t)
			if err == nil && cidr.Contains(parsedIP) {
				return true
			}
		} else {
			// Exact IP match
			if t == ip {
				return true
			}
		}
	}
	return false
}

// CSRFMiddleware implements double-submit cookie CSRF protection for web routes
func CSRFMiddleware(secureCookie bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Generate or read CSRF token from cookie
			cookie, err := r.Cookie("_csrf")
			var csrfToken string
			if err != nil || cookie.Value == "" {
				// Generate new token
				b := make([]byte, 32)
				if _, err := rand.Read(b); err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				csrfToken = base64.RawURLEncoding.EncodeToString(b)
				http.SetCookie(w, &http.Cookie{ // #nosec G124 -- readable double-submit token; Secure is configured from the public HTTPS URL
					Name:     "_csrf",
					Value:    csrfToken,
					Path:     "/",
					HttpOnly: true,
					Secure:   secureCookie,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   86400,
				})
			} else {
				csrfToken = cookie.Value
			}

			// Store token in context for templates
			ctx := context.WithValue(r.Context(), contextKey("csrf_token"), csrfToken)

			// For state-changing methods, validate the token
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE" {
				// Check header first to avoid triggering ParseMultipartForm on large uploads
				submitted := r.Header.Get("X-CSRF-Token")
				if submitted == "" {
					// Only parse form body if it's NOT a multipart request to avoid memory/disk exhaustion
					contentType := r.Header.Get("Content-Type")
					if !strings.HasPrefix(strings.ToLower(contentType), "multipart/form-data") {
						r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
						if err := r.ParseForm(); err != nil {
							http.Error(w, "invalid form", http.StatusBadRequest)
							return
						}
						submitted = r.PostForm.Get("_csrf_token")
					}
				}
				if submitted == "" || subtle.ConstantTimeCompare([]byte(submitted), []byte(csrfToken)) != 1 {
					http.Error(w, "CSRF token mismatch", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimitBasicAuth applies an additional limiter only when a client presents
// HTTP Basic credentials. Public downloads keep their normal throughput while
// password guessing receives the stricter budget.
func RateLimitBasicAuth(limiter func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limiter(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := r.BasicAuth(); ok {
				limited.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WebOrigin supplements CSRF tokens against sibling-domain cookie injection.
func WebOrigin(baseURL string) func(http.Handler) http.Handler {
	u, _ := url.Parse(baseURL) // Config.Validate rejects invalid public URLs.
	origin := u.Scheme + "://" + u.Host
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				if value := r.Header.Get("Origin"); (value != "" && value != origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ConcurrentRequests rejects overload without a waiting goroutine or writer wrapper.
func ConcurrentRequests(limit int) func(http.Handler) http.Handler {
	slots := make(chan struct{}, limit)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				next.ServeHTTP(w, r)
			default:
				w.Header().Set("Retry-After", "1")
				http.Error(w, "transfer capacity reached", http.StatusServiceUnavailable)
			}
		})
	}
}

// GetCSRFToken extracts the CSRF token from context
func GetCSRFToken(ctx context.Context) string {
	token, _ := ctx.Value(contextKey("csrf_token")).(string)
	return token
}

// responseWriter wraps http.ResponseWriter to capture status and bytes
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom implements io.ReaderFrom so that io.Copy can use sendfile(2)
// for zero-copy streaming when the underlying ResponseWriter supports it.
func (rw *responseWriter) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := rw.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		rw.bytesWritten += n
		return n, err
	}
	// Fallback to standard copy via Write
	n, err := io.Copy(rw.ResponseWriter, src)
	rw.bytesWritten += n
	return n, err
}

// Unwrap returns the underlying ResponseWriter, enabling Go 1.20+
// http.ResponseController to discover capabilities (Flush, sendfile, etc.)
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(domain.ErrorResponse{
		Error: message,
	}); err != nil {
		return
	}
}
