package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// URLSigner handles creation and verification of signed URLs
// Uses HMAC-SHA256 for CDN-compatible signatures
type URLSigner struct {
	secret []byte
	keyID  string
}

// NewURLSigner creates a new URL signer
func NewURLSigner(secret string, keyID string) *URLSigner {
	return &URLSigner{
		secret: []byte(secret),
		keyID:  keyID,
	}
}

// SignedURLParams contains parameters for signed URL generation
type SignedURLParams struct {
	Token     string
	ExpiresAt time.Time
	MaxDL     int    // 0 = unlimited
	IP        string // empty = no restriction
	Password  bool   // whether password protected
}

// Sign generates a signed URL
func (s *URLSigner) Sign(baseURL string, params SignedURLParams) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	q := u.Query()
	q.Set("token", params.Token)
	q.Set("expires", strconv.FormatInt(params.ExpiresAt.Unix(), 10))
	q.Set("kid", s.keyID)

	if params.MaxDL > 0 {
		q.Set("max_dl", strconv.Itoa(params.MaxDL))
	}
	if params.IP != "" {
		q.Set("ip", params.IP)
	}

	// Build the string to sign (canonical form)
	signString := s.buildSignString(params.Token, params.ExpiresAt.Unix(), params.IP)

	// Generate HMAC signature
	sig := s.computeHMAC(signString)
	q.Set("sig", sig)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Verify validates a signed URL
func (s *URLSigner) Verify(rawURL string, clientIP string) (*SignedURLParams, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	q := u.Query()
	token := q.Get("token")
	expiresStr := q.Get("expires")
	sig := q.Get("sig")
	ip := q.Get("ip")

	if token == "" || expiresStr == "" || sig == "" {
		return nil, fmt.Errorf("missing required signed URL parameters")
	}

	// Parse expiration
	expiresUnix, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration: %w", err)
	}

	// Check expiration FIRST
	if time.Now().Unix() >= expiresUnix {
		return nil, fmt.Errorf("signed URL has expired")
	}

	// Verify signature using constant-time comparison (anti timing attack)
	expectedSigStr := s.buildSignString(token, expiresUnix, ip)
	expectedSig := s.computeHMAC(expectedSigStr)

	if !constantTimeEqual(sig, expectedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Verify IP restriction
	if ip != "" {
		// Extract just the IP (no port)
		cleanClientIP := normalizeIP(clientIP)
		parsedExpected, parsedClient := net.ParseIP(ip), net.ParseIP(cleanClientIP)
		if parsedExpected == nil || parsedClient == nil || !parsedExpected.Equal(parsedClient) {
			return nil, fmt.Errorf("IP mismatch")
		}
	}

	maxDL := 0
	if mdl := q.Get("max_dl"); mdl != "" {
		maxDL, _ = strconv.Atoi(mdl)
	}

	return &SignedURLParams{
		Token:     token,
		ExpiresAt: time.Unix(expiresUnix, 0),
		MaxDL:     maxDL,
		IP:        ip,
	}, nil
}

func normalizeIP(addr string) string {
	if net.ParseIP(addr) != nil {
		return addr
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// buildSignString creates the canonical string for signing
func (s *URLSigner) buildSignString(token string, expires int64, ip string) string {
	parts := []string{
		token,
		strconv.FormatInt(expires, 10),
		s.keyID,
	}
	if ip != "" {
		parts = append(parts, ip)
	}
	return strings.Join(parts, "\n")
}

// computeHMAC generates the HMAC-SHA256 signature
func (s *URLSigner) computeHMAC(data string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// constantTimeEqual performs constant-time string comparison
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateToken generates a cryptographically random token
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
