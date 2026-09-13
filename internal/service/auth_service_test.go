package service

import (
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"

	"github.com/HeartBtz/fluxgate/internal/config"
)

func TestAuthTagChangesWithPasswordHash(t *testing.T) {
	svc := &AuthService{cfg: &config.Config{Auth: config.AuthConfig{JWTSecret: strings.Repeat("s", 32)}}}
	first := svc.authTag("bcrypt-hash-one")
	if first == "" || first != svc.authTag("bcrypt-hash-one") {
		t.Fatal("auth tag is empty or unstable")
	}
	if first == svc.authTag("bcrypt-hash-two") {
		t.Fatal("password hash change did not change auth tag")
	}
}

func TestJWTRequiresExpiryAndIssuer(t *testing.T) {
	svc := &AuthService{cfg: &config.Config{Auth: config.AuthConfig{JWTSecret: strings.Repeat("s", 32)}}}
	for _, tc := range []struct {
		issuer string
		expiry *jwt.NumericDate
		valid  bool
	}{
		{"fluxgate", nil, false},
		{"other", jwt.NewNumericDate(time.Now().Add(time.Hour)), false},
		{"fluxgate", jwt.NewNumericDate(time.Now().Add(-time.Hour)), false},
		{"fluxgate", jwt.NewNumericDate(time.Now().Add(time.Hour)), true},
	} {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: tc.issuer, ExpiresAt: tc.expiry}}).SignedString([]byte(svc.cfg.Auth.JWTSecret))
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ValidateJWT(token)
		if (err == nil) != tc.valid {
			t.Fatalf("issuer %s expiry %v: %v", tc.issuer, tc.expiry, err)
		}
	}
}
