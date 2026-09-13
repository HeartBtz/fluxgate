// Package worker contient les workers en arrière-plan de FluxGate.
//
// CleanupWorker effectue périodiquement le nettoyage :
//   - Suppression des fichiers expirés (et libération du stockage)
//   - Suppression des liens de téléchargement expirés
//   - Suppression des sessions d'upload abandonnées
//   - Mise à jour des métriques de stockage
package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/HeartBtz/fluxgate/internal/config"
	fluxmetrics "github.com/HeartBtz/fluxgate/internal/metrics"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/HeartBtz/fluxgate/internal/storage"
)

// CleanupWorker handles periodic cleanup tasks
type CleanupWorker struct {
	fileRepo    *repository.FileRepository
	linkRepo    *repository.LinkRepository
	uploadRepo  *repository.UploadSessionRepository
	userRepo    *repository.UserRepository
	storage     storage.Backend
	cfg         *config.Config
	logger      *slog.Logger
	stopCh      chan struct{}
	fileService *service.FileService
}

func NewCleanupWorker(
	fileRepo *repository.FileRepository,
	linkRepo *repository.LinkRepository,
	uploadRepo *repository.UploadSessionRepository,
	userRepo *repository.UserRepository,
	store storage.Backend,
	cfg *config.Config,
	logger *slog.Logger,
	fileService *service.FileService,
) *CleanupWorker {
	return &CleanupWorker{
		fileRepo:    fileRepo,
		linkRepo:    linkRepo,
		uploadRepo:  uploadRepo,
		userRepo:    userRepo,
		storage:     store,
		cfg:         cfg,
		logger:      logger,
		stopCh:      make(chan struct{}),
		fileService: fileService,
	}
}

// Start begins the cleanup worker loop
func (w *CleanupWorker) Start(ctx context.Context) {
	w.logger.Info("cleanup worker started",
		slog.Duration("interval", w.cfg.Worker.CleanupInterval),
	)

	ticker := time.NewTicker(w.cfg.Worker.CleanupInterval)
	defer ticker.Stop()

	// Run immediately on start
	w.runCleanup(ctx)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("cleanup worker stopping (context cancelled)")
			return
		case <-w.stopCh:
			w.logger.Info("cleanup worker stopping (stop signal)")
			return
		case <-ticker.C:
			w.runCleanup(ctx)
		}
	}
}

// Stop signals the worker to stop
func (w *CleanupWorker) Stop() {
	close(w.stopCh)
}

func (w *CleanupWorker) runCleanup(ctx context.Context) {
	w.logger.Debug("running cleanup cycle")

	// 1. Clean up expired files
	w.cleanExpiredFiles(ctx)

	// 2. Clean up soft-deleted files (after grace period)
	w.cleanDeletedFiles(ctx)

	// 3. Clean up expired links
	w.cleanExpiredLinks(ctx)

	// 4. Clean up stale upload sessions
	w.cleanStaleUploads(ctx)

	w.logger.Debug("cleanup cycle complete")
}

func (w *CleanupWorker) cleanExpiredFiles(ctx context.Context) {
	files, err := w.fileRepo.GetExpiredFiles(ctx, w.cfg.Worker.BatchSize)
	if err != nil {
		w.logger.Error("failed to get expired files", slog.Any("error", err))
		return
	}

	for _, file := range files {
		// Delete from storage
		if err := w.storage.Delete(ctx, file.StoragePath); err != nil {
			w.logger.Error("failed to delete file from storage",
				slog.String("file_id", file.ID.String()),
				slog.Any("error", err),
			)
			continue
		}

		// Hard delete and release quota atomically.
		if err := w.fileRepo.HardDeleteWithQuota(ctx, file); err != nil {
			w.logger.Error("failed to hard delete file",
				slog.String("file_id", file.ID.String()),
				slog.Any("error", err),
			)
			continue
		}
		w.logger.Info("cleaned expired file",
			slog.String("file_id", file.ID.String()),
			slog.String("name", file.OriginalName),
		)
	}

	if len(files) > 0 {
		w.logger.Info("cleaned expired files", slog.Int("count", len(files)))
	}
}

func (w *CleanupWorker) cleanDeletedFiles(ctx context.Context) {
	gracePeriod := 24 * time.Hour // Keep soft-deleted files for 24h
	files, err := w.fileRepo.GetSoftDeletedFiles(ctx, gracePeriod, w.cfg.Worker.BatchSize)
	if err != nil {
		w.logger.Error("failed to get soft-deleted files", slog.Any("error", err))
		return
	}

	for _, file := range files {
		if err := w.storage.Delete(ctx, file.StoragePath); err != nil {
			w.logger.Error("failed to delete file from storage",
				slog.String("file_id", file.ID.String()),
				slog.Any("error", err),
			)
			continue
		}

		if err := w.fileRepo.HardDelete(ctx, file.ID); err != nil {
			w.logger.Error("failed to hard delete file",
				slog.String("file_id", file.ID.String()),
				slog.Any("error", err),
			)
		}

		w.logger.Info("cleaned soft-deleted file",
			slog.String("file_id", file.ID.String()),
		)
	}

	if len(files) > 0 {
		w.logger.Info("cleaned soft-deleted files", slog.Int("count", len(files)))
	}
}

func (w *CleanupWorker) cleanExpiredLinks(ctx context.Context) {
	count, err := w.linkRepo.CleanupExpired(ctx, w.cfg.Worker.BatchSize)
	if err != nil {
		w.logger.Error("failed to cleanup expired links", slog.Any("error", err))
		return
	}

	if count > 0 {
		fluxmetrics.LinksExpired.Add(float64(count))
		w.logger.Info("cleaned expired links", slog.Int64("count", count))
	}
}

func (w *CleanupWorker) cleanStaleUploads(ctx context.Context) {
	updatedBefore := time.Now().Add(-w.cfg.Worker.StaleUploadExpiry)
	sessions, err := w.uploadRepo.GetStale(ctx, updatedBefore, w.cfg.Worker.BatchSize)
	if err != nil {
		w.logger.Error("failed to cleanup stale uploads", slog.Any("error", err))
		return
	}

	for _, session := range sessions {
		// Delete partial upload from storage
		if err := w.fileService.CleanupStaleUpload(ctx, session.ID); err != nil {
			w.logger.Warn("failed to delete stale upload",
				slog.String("session_id", session.ID.String()),
				slog.Any("error", err),
			)
			continue
		}
	}

	if len(sessions) > 0 {
		w.logger.Info("cleaned stale upload sessions", slog.Int("count", len(sessions)))
	}
}
