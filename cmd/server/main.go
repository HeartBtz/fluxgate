// FluxGate server — point d'entrée principal de l'application.
//
// Ce programme initialise tous les composants (base de données, stockage, services,
// handlers HTTP, workers de nettoyage, métriques Prometheus) puis démarre le
// serveur HTTP avec arrêt gracieux sur signal SIGINT/SIGTERM.
//
// Configuration via variables d'environnement préfixées FLUXGATE_.
// Voir internal/config pour la liste complète.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/HeartBtz/fluxgate/internal/config"
	fluxcrypto "github.com/HeartBtz/fluxgate/internal/crypto"
	"github.com/HeartBtz/fluxgate/internal/handler"
	fluxmetrics "github.com/HeartBtz/fluxgate/internal/metrics"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/HeartBtz/fluxgate/internal/storage"
	"github.com/HeartBtz/fluxgate/internal/worker"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	startTime = time.Now()
)

func main() {
	// Load config
	cfg := config.Load()

	// Setup structured logger
	var logHandler slog.Handler
	logLevel := parseLogLevel(cfg.Log.Level)

	if cfg.Log.Format == "json" {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	logger.Info("FluxGate starting",
		slog.String("version", Version),
		slog.String("build_time", BuildTime),
	)

	// Validate config
	if err := cfg.Validate(); err != nil {
		logger.Error("configuration validation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Connect to database
	db, err := repository.NewDB(
		cfg.Database.DSN(),
		cfg.Database.MaxOpenConns,
		cfg.Database.MaxIdleConns,
		cfg.Database.ConnMaxLifetime,
	)
	if err != nil {
		logger.Error("database connection failed", slog.Any("error", err))
		os.Exit(1)
	}
	defer db.Close()

	logger.Info("database connected",
		slog.String("host", cfg.Database.Host),
		slog.String("name", cfg.Database.Name),
	)

	// Run migrations
	if err := db.RunMigrations(cfg.Database.MigrationsPath); err != nil {
		logger.Error("migrations failed", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("migrations complete")

	// Initialize storage backend
	var store storage.Backend
	switch cfg.Storage.Backend {
	case "local":
		store, err = storage.NewLocalBackend(cfg.Storage.LocalPath)
		if err != nil {
			logger.Error("local storage init failed", slog.Any("error", err))
			os.Exit(1)
		}
		logger.Info("storage backend: local", slog.String("path", cfg.Storage.LocalPath))
	case "s3":
		store, err = storage.NewS3Backend(
			cfg.Storage.S3Endpoint,
			cfg.Storage.S3Region,
			cfg.Storage.S3Bucket,
			cfg.Storage.S3AccessKey,
			cfg.Storage.S3SecretKey,
			cfg.Storage.S3UseSSL,
			cfg.Storage.S3ForcePathStyle,
		)
		if err != nil {
			logger.Error("S3 storage init failed", slog.Any("error", err))
			os.Exit(1)
		}
		logger.Info("storage backend: s3",
			slog.String("endpoint", cfg.Storage.S3Endpoint),
			slog.String("bucket", cfg.Storage.S3Bucket),
		)
	default:
		logger.Error("unknown storage backend", slog.String("backend", cfg.Storage.Backend))
		os.Exit(1)
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	fileRepo := repository.NewFileRepository(db)
	linkRepo := repository.NewLinkRepository(db)
	apiKeyRepo := repository.NewAPIKeyRepository(db)
	dlLogRepo := repository.NewDownloadLogRepository(db)
	uploadRepo := repository.NewUploadSessionRepository(db)

	// Initialize URL signer
	signer := fluxcrypto.NewURLSigner(cfg.Signing.HMACSecret, cfg.Signing.DefaultKeyID)

	// Initialize services
	authService := service.NewAuthService(userRepo, apiKeyRepo, cfg)
	fileService := service.NewFileService(fileRepo, userRepo, uploadRepo, store, cfg)
	linkService := service.NewLinkService(linkRepo, fileRepo, signer, cfg)
	apiKeyService := service.NewAPIKeyService(apiKeyRepo)

	// Ensure admin user
	if err := authService.EnsureAdmin(context.Background()); err != nil {
		logger.Error("failed to ensure admin user", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("admin user ensured", slog.String("username", cfg.Auth.AdminUsername))

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	fileHandler := handler.NewFileHandler(fileService, linkService, cfg.Limits.MaxUploadSize)
	downloadHandler := handler.NewDownloadHandler(linkService, store, dlLogRepo, logger, cfg.Security.TrustedProxies)
	linkHandler := handler.NewLinkHandler(linkService)
	apiKeyHandler := handler.NewAPIKeyHandler(apiKeyService)

	// Initialize middleware
	authMW := middleware.NewAuthMiddleware(authService)
	rateLimiter := middleware.NewRateLimiter(cfg.Limits.RateLimitRequests, cfg.Limits.RateLimitWindow, cfg.Security.TrustedProxies)
	authRateLimiter := middleware.NewRateLimiter(5, time.Minute, cfg.Security.TrustedProxies)
	downloadRateLimiter := middleware.NewRateLimiter(cfg.Limits.RateLimitRequests, cfg.Limits.RateLimitWindow, cfg.Security.TrustedProxies)
	downloadPasswordLimiter := middleware.NewRateLimiter(10, time.Minute, cfg.Security.TrustedProxies)
	uploadConcurrency := middleware.ConcurrentRequests(cfg.Limits.MaxConcurrentUploads)
	authConcurrency := middleware.ConcurrentRequests(8)

	// Build router
	r := chi.NewRouter()

	// Truly global middleware — these do NOT wrap ResponseWriter
	r.Use(middleware.RequestID)
	r.Use(middleware.Recovery(logger))

	// === DOWNLOAD ROUTES — zero middleware wrapping ===
	// These routes get the raw http.ResponseWriter so io.Copy can use
	// sendfile(2) for zero-copy kernel-level streaming.
	// No Logger, no InstrumentHandler (both wrap ResponseWriter and
	// break sendfile detection). Download handler has its own metrics.
	downloadRoutes := r.With(middleware.SecurityHeaders, downloadRateLimiter.Handler, middleware.ConcurrentRequests(cfg.Limits.MaxConcurrentDL))
	downloadRoutes.With(middleware.RateLimitBasicAuth(downloadPasswordLimiter.Handler)).Get("/d/{token}/{filename}", downloadHandler.Download)
	downloadRoutes.With(middleware.RateLimitBasicAuth(downloadPasswordLimiter.Handler)).Head("/d/{token}/{filename}", downloadHandler.DownloadInfo)
	downloadRoutes.With(downloadPasswordLimiter.Handler).Post("/d/{token}/{filename}", downloadHandler.DownloadWithPassword)
	downloadRoutes.With(middleware.RateLimitBasicAuth(downloadPasswordLimiter.Handler)).Get("/d/{token}", downloadHandler.Download)
	downloadRoutes.With(middleware.RateLimitBasicAuth(downloadPasswordLimiter.Handler)).Head("/d/{token}", downloadHandler.DownloadInfo)
	downloadRoutes.With(downloadPasswordLimiter.Handler).Post("/d/{token}", downloadHandler.DownloadWithPassword)

	// === ALL OTHER ROUTES — full middleware stack ===
	r.Group(func(r chi.Router) {
		r.Use(middleware.Logger(logger, cfg.Security.TrustedProxies))
		r.Use(middleware.SecurityHeaders)
		r.Use(middleware.CORS(cfg.Security.CORSAllowedOrigin))
		r.Use(fluxmetrics.InstrumentHandler)

		// Health & readiness endpoints
		r.Get("/health", healthHandler(db, store))
		r.Get("/ready", readyHandler(db))

		// === API ROUTES (rate limited) ===
		r.Route("/api/v1", func(r chi.Router) {
			// Public auth endpoints
			r.With(rateLimiter.Handler, authRateLimiter.Handler, authConcurrency).Post("/auth/login", authHandler.Login)

			// Upload data paths are authenticated and bounded by quota, declared
			// file size, chunk size and offset. They intentionally bypass the
			// generic request-count limiter so fast multi-GB uploads cannot hit
			// an artificial ceiling after a few gigabytes.
			r.Group(func(r chi.Router) {
				r.Use(uploadConcurrency)
				r.Use(authMW.Required)
				r.With(authMW.RequireScope("upload")).Post("/files/upload", fileHandler.Upload)
				r.With(rateLimiter.Handler, authMW.RequireScope("upload")).Post("/files/upload/init", fileHandler.InitResumableUpload)
				r.With(authMW.RequireScope("upload")).Patch("/files/upload/{sessionID}", fileHandler.UploadChunk)
				r.With(authMW.RequireScope("upload")).Post("/files/upload/{sessionID}/complete", fileHandler.CompleteUpload)
				r.With(authMW.RequireScope("upload")).Get("/files/upload/{sessionID}", fileHandler.UploadStatus)
				r.With(authMW.RequireScope("upload")).Head("/files/upload/{sessionID}", fileHandler.UploadStatus)
				r.With(authMW.RequireScope("upload")).Delete("/files/upload/{sessionID}", fileHandler.CancelUpload)
			})

			// Other protected API operations remain request-rate limited.
			r.Group(func(r chi.Router) {
				r.Use(rateLimiter.Handler)
				r.Use(authMW.Required)

				// Auth
				r.Get("/auth/me", authHandler.Me)
				r.With(authMW.JWTOnly).Post("/auth/register", authHandler.Register) // admin only

				// Files
				r.With(authMW.RequireScope("download")).Get("/files", fileHandler.ListFiles)
				r.With(authMW.RequireScope("download")).Get("/files/quota", fileHandler.GetQuota)
				r.With(authMW.RequireScope("download")).Get("/files/{fileID}", fileHandler.GetFile)
				r.With(authMW.RequireScope("manage")).Delete("/files/{fileID}", fileHandler.DeleteFile)

				// Links
				r.With(authMW.RequireScope("manage")).Post("/links", linkHandler.CreateLink)
				r.With(authMW.RequireScope("download")).Get("/links/file/{fileID}", linkHandler.ListLinks)
				r.With(authMW.RequireScope("manage")).Post("/links/{linkID}/revoke", linkHandler.RevokeLink)
				r.With(authMW.RequireScope("manage")).Delete("/links/{linkID}", linkHandler.DeleteLink)

				// API Keys
				r.With(authMW.JWTOnly).Post("/apikeys", apiKeyHandler.Create)
				r.With(authMW.JWTOnly).Get("/apikeys", apiKeyHandler.List)
				r.With(authMW.JWTOnly).Post("/apikeys/{keyID}/revoke", apiKeyHandler.Revoke)
				r.With(authMW.JWTOnly).Delete("/apikeys/{keyID}", apiKeyHandler.Delete)
			})
		})

		// === WEB UI ROUTES (rate limited, with CSRF protection) ===
		webHandler := handler.NewWebHandler(authService, fileService, linkService, userRepo, fileRepo, linkRepo, cfg, logger)
		r.Get("/", webHandler.Index)
		r.Group(func(r chi.Router) {
			r.Use(middleware.WebOrigin(cfg.Server.BaseURL))
			r.Use(middleware.CSRFMiddleware(strings.HasPrefix(cfg.Server.BaseURL, "https://")))
			r.With(rateLimiter.Handler).Get("/login", webHandler.LoginPage)
			r.With(rateLimiter.Handler, authRateLimiter.Handler, authConcurrency).Post("/login", webHandler.LoginPost)
			r.With(rateLimiter.Handler).Get("/dashboard", webHandler.Dashboard)
			r.With(uploadConcurrency).Post("/web/upload", webHandler.WebUpload)
			r.With(rateLimiter.Handler).Post("/web/upload/init", webHandler.WebInitResumableUpload)
			r.With(uploadConcurrency).Patch("/web/upload/{sessionID}", webHandler.WebUploadChunk)
			r.Get("/web/upload/{sessionID}", webHandler.WebUploadStatus)
			r.Delete("/web/upload/{sessionID}", webHandler.WebCancelResumableUpload)
			r.With(uploadConcurrency).Post("/web/upload/{sessionID}/complete", webHandler.WebCompleteResumableUpload)
			r.With(rateLimiter.Handler).Post("/web/link", webHandler.WebCreateLink)
			r.With(rateLimiter.Handler).Post("/web/delete/{fileID}", webHandler.WebDeleteFile)
			r.With(rateLimiter.Handler).Post("/logout", webHandler.Logout)
			// Admin routes
			r.With(rateLimiter.Handler).Get("/admin", webHandler.AdminPage)
			r.With(rateLimiter.Handler).Post("/admin/user/create", webHandler.AdminCreateUser)
			r.With(rateLimiter.Handler).Post("/admin/user/update", webHandler.AdminUpdateUser)
			r.With(rateLimiter.Handler).Post("/admin/user/toggle/{userID}", webHandler.AdminToggleUser)
			r.With(rateLimiter.Handler).Post("/admin/user/delete/{userID}", webHandler.AdminDeleteUser)
		})
		// Static files
		fileServer := http.FileServer(http.Dir("web/static"))
		r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	})

	// Start background workers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanupWorker := worker.NewCleanupWorker(fileRepo, linkRepo, uploadRepo, userRepo, store, cfg, logger, fileService)
	go cleanupWorker.Start(ctx)

	// Start metrics server
	if cfg.Metrics.Enabled {
		// Register DB connection pool metrics
		prometheus.MustRegister(
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "fluxgate_db_open_connections",
				Help: "Number of open database connections",
			}, func() float64 { return float64(db.Stats().OpenConnections) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "fluxgate_db_in_use_connections",
				Help: "Number of in-use database connections",
			}, func() float64 { return float64(db.Stats().InUse) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "fluxgate_db_idle_connections",
				Help: "Number of idle database connections",
			}, func() float64 { return float64(db.Stats().Idle) }),
		)

		go func() {
			metricsAddr := fmt.Sprintf("127.0.0.1:%d", cfg.Metrics.Port)
			mux := http.NewServeMux()
			mux.Handle("/metrics", fluxmetrics.Handler())
			metricsSrv := &http.Server{
				Addr:              metricsAddr,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
				IdleTimeout:       30 * time.Second,
			}
			logger.Info("metrics server starting", slog.String("addr", metricsAddr))
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics server failed", slog.Any("error", err))
			}
		}()
	}

	// Start main server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh

		logger.Info("shutdown signal received", slog.String("signal", sig.String()))

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer shutdownCancel()

		// Stop workers
		cancel() // Cancel context before stopping workers
		cleanupWorker.Stop()
		authRateLimiter.Stop()
		rateLimiter.Stop()
		downloadRateLimiter.Stop()
		downloadPasswordLimiter.Stop()

		// Shutdown server
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown error", slog.Any("error", err))
		}
	}()

	logger.Info("FluxGate server starting",
		slog.String("addr", addr),
		slog.String("base_url", cfg.Server.BaseURL),
	)

	if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
		err = srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		logger.Error("server error", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("FluxGate server stopped gracefully")
}

func healthHandler(db *repository.DB, store storage.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := make(map[string]string)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// DB check — do not expose internal error details
		if err := db.HealthCheck(ctx); err != nil {
			checks["database"] = "unhealthy"
		} else {
			checks["database"] = "healthy"
		}

		// Storage check
		if _, err := store.Exists(ctx, ".fluxgate-healthcheck"); err != nil {
			checks["storage"] = "unhealthy"
		} else {
			checks["storage"] = "healthy"
		}

		status := "healthy"
		statusCode := http.StatusOK
		for _, v := range checks {
			if v != "healthy" {
				status = "degraded"
				statusCode = http.StatusServiceUnavailable
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, `{"status":"%s","version":"%s","uptime":"%s","checks":%s}`,
			status, Version, time.Since(startTime).String(),
			mustJSON(checks))
	}
}

func readyHandler(db *repository.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.HealthCheck(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"ready":false}`)
			return
		}
		fmt.Fprintf(w, `{"ready":true}`)
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
