// Package config gère le chargement et la validation de la configuration
// de FluxGate à partir des variables d'environnement.
//
// Toutes les variables sont préfixées FLUXGATE_ et organisées en groupes :
// serveur, base de données, stockage, authentification, signature, limites,
// workers, métriques, logs et sécurité.
//
// Utilisation :
//
//	cfg := config.Load()
//	if err := cfg.Validate(); err != nil { ... }
package config

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config centralise toute la configuration de l'application.
// Chaque sous-structure correspond à un groupe de variables d'environnement.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Storage  StorageConfig
	Auth     AuthConfig
	Signing  SigningConfig
	Limits   LimitsConfig
	Worker   WorkerConfig
	Metrics  MetricsConfig
	Log      LogConfig
	Security SecurityConfig
}

type ServerConfig struct {
	Host              string
	Port              int
	BaseURL           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	ShutdownTimeout   time.Duration
	TLSCert           string
	TLSKey            string
}

type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	MigrationsPath  string
}

func (d DatabaseConfig) DSN() string {
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(d.User, d.Password),
		Host:     fmt.Sprintf("%s:%d", d.Host, d.Port),
		Path:     d.Name,
		RawQuery: fmt.Sprintf("sslmode=%s", url.QueryEscape(d.SSLMode)),
	}
	return u.String()
}

type StorageConfig struct {
	Backend          string // "local", "s3"
	LocalPath        string
	S3Endpoint       string
	S3Region         string
	S3Bucket         string
	S3AccessKey      string
	S3SecretKey      string
	S3UseSSL         bool
	S3ForcePathStyle bool
	MinFreeBytes     int64 // safety floor kept free on local storage
}

type AuthConfig struct {
	JWTSecret        string
	JWTExpiry        time.Duration
	JWTRefreshExpiry time.Duration
	BcryptCost       int
	AdminUsername    string
	AdminPassword    string
	AdminEmail       string
}

type SigningConfig struct {
	DefaultKeyID  string
	HMACSecret    string
	DefaultExpiry time.Duration
	MaxExpiry     time.Duration
}

type LimitsConfig struct {
	MaxUploadSize        int64
	MaxConcurrentDL      int
	MaxConcurrentUploads int
	DefaultQuota         int64
	MaxFileNameLength    int
	RateLimitRequests    int
	RateLimitWindow      time.Duration
	AllowedExtensions    []string
	BlockedExtensions    []string
	AllowedMIMETypes     []string
}

type SecurityConfig struct {
	TrustedProxies    []string // CIDR or IPs of trusted reverse proxies
	CORSAllowedOrigin string   // Allowed origin for CORS, empty = same as BaseURL
}

type WorkerConfig struct {
	CleanupInterval   time.Duration
	SessionExpiry     time.Duration
	StaleUploadExpiry time.Duration
	BatchSize         int
}

type MetricsConfig struct {
	Enabled bool
	Port    int
}

type LogConfig struct {
	Level  string // "debug", "info", "warn", "error"
	Format string // "json", "text"
}

// Load charge la configuration depuis les variables d'environnement.
// Chaque variable a une valeur par défaut raisonnable sauf les secrets
// (JWT_SECRET, HMAC_SECRET, ADMIN_PASSWORD) qui doivent être définis.
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:              envStr("FLUXGATE_HOST", "0.0.0.0"),
			Port:              envInt("FLUXGATE_PORT", 8080),
			BaseURL:           envStr("FLUXGATE_BASE_URL", "http://localhost:8080"),
			ReadHeaderTimeout: envDuration("FLUXGATE_READ_HEADER_TIMEOUT", 10*time.Second),
			ReadTimeout:       envDuration("FLUXGATE_READ_TIMEOUT", 0),  // 0 for streaming request bodies
			WriteTimeout:      envDuration("FLUXGATE_WRITE_TIMEOUT", 0), // 0 for streaming
			IdleTimeout:       envDuration("FLUXGATE_IDLE_TIMEOUT", 120*time.Second),
			MaxHeaderBytes:    envInt("FLUXGATE_MAX_HEADER_BYTES", 1<<20), // 1 MB
			ShutdownTimeout:   envDuration("FLUXGATE_SHUTDOWN_TIMEOUT", 30*time.Second),
			TLSCert:           envStr("FLUXGATE_TLS_CERT", ""),
			TLSKey:            envStr("FLUXGATE_TLS_KEY", ""),
		},
		Database: DatabaseConfig{
			Host:            envStr("FLUXGATE_DB_HOST", "localhost"),
			Port:            envInt("FLUXGATE_DB_PORT", 5432),
			User:            envStr("FLUXGATE_DB_USER", "fluxgate"),
			Password:        envStr("FLUXGATE_DB_PASSWORD", ""),
			Name:            envStr("FLUXGATE_DB_NAME", "fluxgate"),
			SSLMode:         envStr("FLUXGATE_DB_SSLMODE", "disable"),
			MaxOpenConns:    envInt("FLUXGATE_DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    envInt("FLUXGATE_DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: envDuration("FLUXGATE_DB_CONN_MAX_LIFETIME", 5*time.Minute),
			MigrationsPath:  envStr("FLUXGATE_MIGRATIONS_PATH", "migrations"),
		},
		Storage: StorageConfig{
			Backend:          envStr("FLUXGATE_STORAGE_BACKEND", "local"),
			LocalPath:        envStr("FLUXGATE_STORAGE_LOCAL_PATH", "/data/fluxgate/files"),
			S3Endpoint:       envStr("FLUXGATE_S3_ENDPOINT", ""),
			S3Region:         envStr("FLUXGATE_S3_REGION", "us-east-1"),
			S3Bucket:         envStr("FLUXGATE_S3_BUCKET", "fluxgate"),
			S3AccessKey:      envStr("FLUXGATE_S3_ACCESS_KEY", ""),
			S3SecretKey:      envStr("FLUXGATE_S3_SECRET_KEY", ""),
			S3UseSSL:         envBool("FLUXGATE_S3_USE_SSL", true),
			S3ForcePathStyle: envBool("FLUXGATE_S3_FORCE_PATH_STYLE", true),
			MinFreeBytes:     envInt64("FLUXGATE_STORAGE_MIN_FREE_BYTES", 1073741824), // 1 GiB
		},
		Auth: AuthConfig{
			JWTSecret:        envStr("FLUXGATE_JWT_SECRET", ""),
			JWTExpiry:        envDuration("FLUXGATE_JWT_EXPIRY", 24*time.Hour),
			JWTRefreshExpiry: envDuration("FLUXGATE_JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			BcryptCost:       envInt("FLUXGATE_BCRYPT_COST", 12),
			AdminUsername:    envStr("FLUXGATE_ADMIN_USERNAME", "admin"),
			AdminPassword:    envStr("FLUXGATE_ADMIN_PASSWORD", ""),
			AdminEmail:       envStr("FLUXGATE_ADMIN_EMAIL", "admin@fluxgate.local"),
		},
		Signing: SigningConfig{
			DefaultKeyID:  envStr("FLUXGATE_SIGNING_KEY_ID", "default"),
			HMACSecret:    envStr("FLUXGATE_HMAC_SECRET", ""),
			DefaultExpiry: envDuration("FLUXGATE_SIGNING_DEFAULT_EXPIRY", 24*time.Hour),
			MaxExpiry:     envDuration("FLUXGATE_SIGNING_MAX_EXPIRY", 30*24*time.Hour),
		},
		Limits: LimitsConfig{
			MaxConcurrentDL:      envInt("FLUXGATE_MAX_CONCURRENT_DL", 100),
			MaxConcurrentUploads: envInt("FLUXGATE_MAX_CONCURRENT_UPLOADS", 16),
			MaxUploadSize:        envInt64("FLUXGATE_MAX_UPLOAD_SIZE", 107374182400), // 100 GB
			DefaultQuota:         envInt64("FLUXGATE_DEFAULT_QUOTA", 10737418240),    // 10 GB
			MaxFileNameLength:    envInt("FLUXGATE_MAX_FILENAME_LENGTH", 255),
			RateLimitRequests:    envInt("FLUXGATE_RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:      envDuration("FLUXGATE_RATE_LIMIT_WINDOW", time.Minute),
			AllowedExtensions:    envSlice("FLUXGATE_ALLOWED_EXTENSIONS", nil),
			BlockedExtensions:    envSlice("FLUXGATE_BLOCKED_EXTENSIONS", []string{".exe", ".bat", ".cmd", ".scr", ".pif"}),
			AllowedMIMETypes:     envSlice("FLUXGATE_ALLOWED_MIME_TYPES", nil),
		},
		Worker: WorkerConfig{
			CleanupInterval:   envDuration("FLUXGATE_CLEANUP_INTERVAL", 15*time.Minute),
			SessionExpiry:     envDuration("FLUXGATE_SESSION_EXPIRY", 24*time.Hour),
			StaleUploadExpiry: envDuration("FLUXGATE_STALE_UPLOAD_EXPIRY", 48*time.Hour),
			BatchSize:         envInt("FLUXGATE_CLEANUP_BATCH_SIZE", 100),
		},
		Metrics: MetricsConfig{
			Enabled: envBool("FLUXGATE_METRICS_ENABLED", true),
			Port:    envInt("FLUXGATE_METRICS_PORT", 9090),
		},
		Log: LogConfig{
			Level:  envStr("FLUXGATE_LOG_LEVEL", "info"),
			Format: envStr("FLUXGATE_LOG_FORMAT", "json"),
		},
		Security: SecurityConfig{
			TrustedProxies:    envSlice("FLUXGATE_TRUSTED_PROXIES", nil),
			CORSAllowedOrigin: envStr("FLUXGATE_CORS_ORIGIN", ""),
		},
	}
}

// Validate vérifie que les paramètres critiques sont définis et conformes :
// JWT_SECRET (≥32 car.), ADMIN_PASSWORD (≥8 car.), HMAC_SECRET (≥32 car.),
// configuration S3 complète si backend=s3.
func (c *Config) Validate() error {
	publicURL, err := url.Parse(c.Server.BaseURL)
	if err != nil || (publicURL.Scheme != "http" && publicURL.Scheme != "https") || publicURL.Hostname() == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" || (publicURL.Path != "" && publicURL.Path != "/") {
		return fmt.Errorf("FLUXGATE_BASE_URL must be an http or https origin without credentials, path, query or fragment")
	}
	c.Server.BaseURL = strings.TrimRight(publicURL.String(), "/")
	if c.Security.CORSAllowedOrigin == "" {
		c.Security.CORSAllowedOrigin = c.Server.BaseURL
	} else {
		u, err := url.Parse(c.Security.CORSAllowedOrigin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("FLUXGATE_CORS_ORIGIN must be an http or https origin")
		}
	}
	for _, proxy := range c.Security.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				return fmt.Errorf("FLUXGATE_TRUSTED_PROXIES must contain only IPs or CIDRs")
			}
		}
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("TLS certificate and key must be configured together")
	}
	if c.Database.Password == "" {
		return fmt.Errorf("FLUXGATE_DB_PASSWORD is required")
	}
	if c.Auth.JWTSecret == "" {
		return fmt.Errorf("FLUXGATE_JWT_SECRET is required")
	}
	if len(c.Auth.JWTSecret) < 32 {
		return fmt.Errorf("FLUXGATE_JWT_SECRET must be at least 32 characters")
	}
	if c.Auth.JWTExpiry <= 0 || c.Auth.BcryptCost < 4 || c.Auth.BcryptCost > 31 {
		return fmt.Errorf("FluxGate JWT expiry and bcrypt cost are invalid")
	}
	if c.Auth.AdminPassword != "" && (len(c.Auth.AdminPassword) < 8 || len(c.Auth.AdminPassword) > 72) {
		return fmt.Errorf("FLUXGATE_ADMIN_PASSWORD must be between 8 and 72 bytes")
	}
	if c.Signing.HMACSecret == "" {
		return fmt.Errorf("FLUXGATE_HMAC_SECRET is required")
	}
	if len(c.Signing.HMACSecret) < 32 {
		return fmt.Errorf("FLUXGATE_HMAC_SECRET must be at least 32 characters")
	}
	if c.Signing.DefaultExpiry <= 0 || c.Signing.MaxExpiry < c.Signing.DefaultExpiry {
		return fmt.Errorf("FluxGate signing expiry settings are invalid")
	}
	if c.Storage.Backend == "s3" {
		if c.Storage.S3Endpoint == "" || c.Storage.S3AccessKey == "" || c.Storage.S3SecretKey == "" {
			return fmt.Errorf("S3 configuration incomplete: endpoint, access key and secret key required")
		}
	}
	if c.Storage.MinFreeBytes < 0 {
		return fmt.Errorf("FLUXGATE_STORAGE_MIN_FREE_BYTES must not be negative")
	}
	if c.Limits.MaxUploadSize <= 0 || c.Limits.MaxUploadSize > math.MaxInt64-(1<<20) {
		return fmt.Errorf("FLUXGATE_MAX_UPLOAD_SIZE must be greater than zero")
	}
	if c.Limits.DefaultQuota < 0 || c.Limits.MaxFileNameLength < 1 || c.Limits.MaxFileNameLength > 255 {
		return fmt.Errorf("FluxGate quota or filename limits are invalid")
	}
	if c.Database.MaxOpenConns < 1 || c.Database.MaxIdleConns < 0 || c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("FluxGate database pool settings are invalid")
	}
	if c.Server.ReadHeaderTimeout <= 0 || c.Server.ReadTimeout < 0 || c.Server.WriteTimeout < 0 || c.Server.IdleTimeout <= 0 || c.Server.MaxHeaderBytes < 4096 {
		return fmt.Errorf("FluxGate HTTP server settings are invalid")
	}
	if c.Limits.RateLimitRequests <= 0 || c.Limits.RateLimitWindow <= 0 {
		return fmt.Errorf("FluxGate rate limit must be greater than zero")
	}
	if c.Limits.MaxConcurrentDL < 1 || c.Limits.MaxConcurrentDL > 10000 || c.Limits.MaxConcurrentUploads < 1 || c.Limits.MaxConcurrentUploads > 10000 {
		return fmt.Errorf("concurrent transfer limits must be between 1 and 10000")
	}
	if c.Worker.CleanupInterval <= 0 || c.Worker.BatchSize < 1 || c.Worker.BatchSize > 10000 {
		return fmt.Errorf("cleanup interval and batch size are invalid")
	}
	if c.Worker.SessionExpiry <= 0 || c.Worker.StaleUploadExpiry < c.Worker.SessionExpiry {
		return fmt.Errorf("upload expiry settings must be positive and stale upload expiry must be at least session expiry")
	}
	return nil
}

// --- helpers ---

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		slog.Warn("invalid env var, using default", "key", key, "value", v, "default", fallback)
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
		slog.Warn("invalid env var, using default", "key", key, "value", v, "default", fallback)
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
		slog.Warn("invalid env var, using default", "key", key, "value", v, "default", fallback)
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		slog.Warn("invalid env var, using default", "key", key, "value", v, "default", fallback)
	}
	return fallback
}

func envSlice(key string, fallback []string) []string {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}
	return fallback
}
