package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRateLimiterResetsAnActiveClientAtWindowBoundary(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, nil)
	defer rl.Stop()

	h := rl.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "192.0.2.10:1234"

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("request %d status = %d", i+1, rr.Code)
		}
	}

	rl.mu.Lock()
	rl.visitors["192.0.2.10"].windowStart = time.Now().Add(-time.Minute)
	rl.visitors["192.0.2.10"].lastSeen = time.Now()
	rl.mu.Unlock()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("first request in new window status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestAPIKeyScopesAndCredentialBoundaries(t *testing.T) {
	m := &AuthMiddleware{}
	for _, tc := range []struct {
		auth   string
		scopes []string
		want   int
	}{
		{"apikey", []string{"download"}, 403},
		{"apikey", []string{"upload"}, 204},
		{"apikey", nil, 403},
		{"jwt", nil, 204},
	} {
		ctx := context.WithValue(context.Background(), ContextAuthType, tc.auth)
		ctx = context.WithValue(ctx, ContextScopes, tc.scopes)
		r := httptest.NewRequest("POST", "/api/v1/files/upload", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		m.RequireScope("upload")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s scopes %v: %d", tc.auth, tc.scopes, w.Code)
		}
		if tc.auth == "apikey" {
			w = httptest.NewRecorder()
			m.JWTOnly(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("API key could mint credentials") })).ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("JWTOnly: %d", w.Code)
			}
		}
	}
	if extractAPIKey(httptest.NewRequest("GET", "/api/v1/files?api_key=test-key", nil)) != "" {
		t.Fatal("query API key accepted")
	}
}

func TestBasicAuthCaseAndHeadSharePasswordBudget(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute, nil)
	defer rl.Stop()
	h := RateLimitBasicAuth(rl.Handler)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for i, method := range []string{"HEAD", "GET"} {
		r := httptest.NewRequest(method, "/d/test", nil)
		r.SetBasicAuth("", "test-password")
		r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "Basic", "bAsIc", 1))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i == 0 && w.Code != 204 || i == 1 && w.Code != 429 {
			t.Fatalf("%s: %d", method, w.Code)
		}
	}
}

func TestConcurrentRequestsRejectsAndReleases(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := ConcurrentRequests(1)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { close(entered); <-release; w.WriteHeader(204) }))
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)) }()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Errorf("overload: %d", w.Code)
	}
	close(release)
	<-done
}

func TestRateLimiterBoundsNewVisitors(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute, nil)
	defer rl.Stop()
	rl.mu.Lock()
	for i := 0; i < 10000; i++ {
		rl.visitors[fmt.Sprint(i)] = &visitor{lastSeen: time.Now()}
	}
	rl.mu.Unlock()
	w := httptest.NewRecorder()
	rl.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("overload admitted") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 429 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestWebOriginAndCSRFRejectURLToken(t *testing.T) {
	h := WebOrigin("https://example.test")(CSRFMiddleware(true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })))
	for _, tc := range []struct {
		origin, query, body string
		want                int
	}{
		{"https://evil.example.test", "", "_csrf_token=test", 403},
		{"null", "", "_csrf_token=test", 403},
		{"https://example.test", "?_csrf_token=test", "", 403},
		{"https://example.test", "", "_csrf_token=test", 204},
	} {
		r := httptest.NewRequest("POST", "/web/link"+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "_csrf", Value: "test"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("origin %s query %s: %d", tc.origin, tc.query, w.Code)
		}
	}
}

func TestRealIPOnlyTrustsConfiguredProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.2")
	if got := RealIP(req, []string{"192.168.1.1"}); got != "203.0.113.10" {
		t.Fatalf("untrusted proxy spoofed IP: %q", got)
	}
	req.RemoteAddr = "192.168.1.1:1234"
	if got := RealIP(req, []string{"192.168.1.1"}); got != "198.51.100.2" {
		t.Fatalf("trusted proxy IP = %q", got)
	}
}

func TestRealIPIgnoresMalformedForwardedValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("X-Forwarded-For", "garbage, 198.51.100.2, 192.168.1.2")
	if got := RealIP(req, []string{"192.168.1.0/24"}); got != "198.51.100.2" {
		t.Fatalf("RealIP() = %q", got)
	}
}

func TestRequestIDRejectsUnsafeValues(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, unsafe := range []string{"with spaces", "line\nbreak", strings.Repeat("x", 129)} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Request-ID", unsafe)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if got := rr.Header().Get("X-Request-ID"); got == unsafe || got == "" {
			t.Fatalf("unsafe ID was not replaced: %q", got)
		}
	}
}

func TestCSRFSecureCookie(t *testing.T) {
	h := CSRFMiddleware(true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if cookie := rr.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatalf("CSRF cookie is not secure: %q", cookie)
	}
}

func TestCORSDoesNotGrantUntrustedOrigin(t *testing.T) {
	h := CORS("https://fluxgate.example")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("untrusted origin received CORS permission %q", got)
	}
}

func TestRateLimitBasicAuthOnlyLimitsCredentialRequests(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute, nil)
	defer rl.Stop()
	h := RateLimitBasicAuth(rl.Handler)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/d/token", nil))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("public request %d status = %d", i, rr.Code)
		}
	}
	for i, want := range []int{http.StatusNoContent, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodGet, "/d/token", nil)
		req.SetBasicAuth("", "password")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Fatalf("credential request %d status = %d, want %d", i, rr.Code, want)
		}
	}
}

func TestSecurityHeadersDoNotAllowThirdPartyScripts(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy is missing")
	}
	if strings.Contains(csp, "http://") || strings.Contains(csp, "https://") {
		t.Fatalf("CSP unexpectedly allows a third-party origin: %q", csp)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
}
