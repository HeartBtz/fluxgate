package config

import (
	"math"
	"strings"
	"testing"
)

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	t.Setenv("FLUXGATE_JWT_SECRET", strings.Repeat("j", 32))
	t.Setenv("FLUXGATE_HMAC_SECRET", strings.Repeat("h", 32))
	t.Setenv("FLUXGATE_DB_PASSWORD", "test-only")
	for name, mutate := range map[string]func(*Config){
		"URL credentials": func(c *Config) { c.Server.BaseURL = "https://user:secret@example.test" },
		"URL path":        func(c *Config) { c.Server.BaseURL = "https://example.test/subpath" },
		"URL query":       func(c *Config) { c.Server.BaseURL = "https://example.test?secret=value" },
		"invalid proxy":   func(c *Config) { c.Security.TrustedProxies = []string{"typo"} },
		"wildcard CORS":   func(c *Config) { c.Security.CORSAllowedOrigin = "*" },
		"overflow upload": func(c *Config) { c.Limits.MaxUploadSize = math.MaxInt64 },
		"cleanup ticker":  func(c *Config) { c.Worker.CleanupInterval = 0 },
		"cleanup batch":   func(c *Config) { c.Worker.BatchSize = -1 },
		"concurrency":     func(c *Config) { c.Limits.MaxConcurrentDL = 0 },
		"TLS pair":        func(c *Config) { c.Server.TLSCert = "test.crt" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Load()
			mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	cfg := Load()
	cfg.Server.BaseURL = "https://example.test/"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.BaseURL != "https://example.test" || cfg.Security.CORSAllowedOrigin != cfg.Server.BaseURL {
		t.Fatal("public origin not normalized")
	}
}
