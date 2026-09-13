// Package service contient la logique métier de FluxGate :
//   - FileService  : upload, stockage, quota, suppression de fichiers
//   - AuthService  : authentification JWT, gestion des utilisateurs
//   - LinkService  : création et validation des liens de téléchargement
//   - APIKeyService: gestion des clés API
//
// Les services orchestrent les repositories et le stockage, et appliquent
// les règles métier (quotas, validations et stockage).
package service

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/HeartBtz/fluxgate/internal/config"
	"github.com/HeartBtz/fluxgate/internal/crypto"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/storage"
	"github.com/google/uuid"
)

const (
	defaultUploadChunkSize = 64 * 1024 * 1024
	minUploadChunkSize     = 1 * 1024 * 1024
	maxUploadChunkSize     = 256 * 1024 * 1024
)

// FileService gère les opérations sur les fichiers : upload (simple et par morceaux),
// calcul du hash SHA-256, vérification du quota,
// listage, suppression et gestion de l'espace disque.
type FileService struct {
	fileRepo   *repository.FileRepository
	userRepo   *repository.UserRepository
	uploadRepo *repository.UploadSessionRepository
	storage    storage.Backend
	cfg        *config.Config
	capacityMu sync.Mutex
	inFlight   int64
	sessionMu  [64]sync.Mutex
}

// NewFileService crée un nouveau service de gestion de fichiers.
func NewFileService(
	fileRepo *repository.FileRepository,
	userRepo *repository.UserRepository,
	uploadRepo *repository.UploadSessionRepository,
	store storage.Backend,
	cfg *config.Config,
) *FileService {
	return &FileService{
		fileRepo:   fileRepo,
		userRepo:   userRepo,
		uploadRepo: uploadRepo,
		storage:    store,
		cfg:        cfg,
	}
}

// Upload handles a direct file upload (streaming, no full buffering)
func (s *FileService) Upload(ctx context.Context, userID uuid.UUID, filename string, size int64, reader io.Reader) (*domain.File, error) {
	// Validate user quota
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	reservedBytes, err := s.uploadRepo.ReservedBytes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("inspect upload reservations: %w", err)
	}
	if user.QuotaRemaining()-reservedBytes < size && size > 0 {
		return nil, domain.ErrQuotaExceeded
	}

	if size > user.MaxFileSize && user.MaxFileSize > 0 {
		return nil, domain.ErrFileTooLarge
	}

	// Sanitize filename
	safeFilename := crypto.SanitizeFilenameLimit(filename, s.cfg.Limits.MaxFileNameLength)

	// Validate extension
	if err := crypto.ValidateExtension(safeFilename, s.cfg.Limits.AllowedExtensions, s.cfg.Limits.BlockedExtensions); err != nil {
		return nil, domain.ErrBlockedExtension
	}

	// Generate storage path
	fileID := uuid.New()
	storedName := fmt.Sprintf("%s%s", fileID.String(), filepath.Ext(safeFilename))
	storagePath := generateStoragePath(fileID.String(), storedName)

	maxAllowed := s.cfg.Limits.MaxUploadSize
	if user.MaxFileSize > 0 && user.MaxFileSize < maxAllowed {
		maxAllowed = user.MaxFileSize
	}
	if remaining := user.QuotaRemaining() - reservedBytes; remaining < maxAllowed {
		maxAllowed = remaining
	}
	if maxAllowed < 0 {
		return nil, domain.ErrQuotaExceeded
	}
	reservation := maxAllowed
	if size > 0 && size < reservation {
		reservation = size
	}
	unlock := s.lockSession(fileID)
	defer unlock()
	session := &domain.UploadSession{
		ID: fileID, UserID: userID, Filename: safeFilename, TotalSize: reservation,
		ChunkSize: defaultUploadChunkSize, StoragePath: storagePath, Status: "pending",
		ExpiresAt: time.Now().Add(s.cfg.Worker.SessionExpiry),
	}
	if err := s.createReservation(ctx, session); err != nil {
		return nil, err
	}
	// Keep a durable cleanup record until both quota and file metadata commit.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if _, err := s.uploadRepo.GetByID(cleanupCtx, session.ID); err != nil {
			// A missing row means finalization committed, even if its response was lost.
			// An unavailable DB is not permission to remove a possibly committed file.
			return
		}
		if err := s.storage.Delete(cleanupCtx, storagePath); err == nil {
			_ = s.uploadRepo.Delete(cleanupCtx, session.ID)
		}
	}()
	interval := max(time.Nanosecond, min(time.Minute, s.cfg.Worker.SessionExpiry/3))
	leaseReader := &uploadLeaseReader{
		reader: reader, interval: interval,
		nextRenewal: session.ExpiresAt.Add(-s.cfg.Worker.SessionExpiry + interval),
		renew: func(progressAt time.Time) error {
			renewCtx, cancel := context.WithTimeout(ctx, min(5*time.Second, interval))
			defer cancel()
			return s.uploadRepo.RenewLease(renewCtx, session.ID, progressAt.Add(s.cfg.Worker.SessionExpiry))
		},
	}
	buffered := bufio.NewReader(leaseReader)
	detectedMIME, err := sniffMIMEType(buffered, safeFilename)
	if err != nil {
		return nil, fmt.Errorf("read upload prefix: %w", err)
	}
	if err := validateMIMEType(detectedMIME, s.cfg.Limits.AllowedMIMETypes); err != nil {
		return nil, err
	}
	// Enforce the effective per-user limit while streaming, even when the
	// client omits or lies about Content-Length.
	hashReader := newHashReader(io.LimitReader(buffered, reservation+1))

	// Stream to storage
	written, err := s.storage.Put(ctx, storagePath, hashReader, size)
	if err != nil {
		return nil, fmt.Errorf("storage write failed: %w", err)
	}
	if written > s.cfg.Limits.MaxUploadSize || (user.MaxFileSize > 0 && written > user.MaxFileSize) {
		return nil, domain.ErrFileTooLarge
	}
	if user.QuotaRemaining()-reservedBytes < written {
		return nil, domain.ErrQuotaExceeded
	}
	if written > reservation {
		return nil, domain.ErrFileTooLarge
	}

	sha256Hash := hashReader.Sum()

	// Create file record
	file := &domain.File{
		ID:             fileID,
		UserID:         userID,
		OriginalName:   safeFilename,
		StoredName:     storedName,
		StoragePath:    storagePath,
		StorageBackend: s.storage.Type(),
		MIMEType:       detectedMIME,
		SizeBytes:      written,
		SHA256:         sha256Hash,
		UploadComplete: true,
		Metadata:       domain.JSONMap{},
	}

	if err := s.fileRepo.FinalizeUpload(ctx, file, session.ID); err != nil {
		if errors.Is(err, domain.ErrQuotaExceeded) {
			return nil, domain.ErrQuotaExceeded
		}
		return nil, fmt.Errorf("failed to create file record: %w", err)
	}

	return file, nil
}

// InitResumableUpload starts a resumable upload session
func (s *FileService) InitResumableUpload(ctx context.Context, userID uuid.UUID, req domain.UploadInitRequest) (*domain.UploadSession, error) {
	if s.storage.Type() == "s3" {
		return nil, fmt.Errorf("resumable uploads are not supported by the S3 backend")
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if req.TotalSize <= 0 {
		return nil, domain.ErrFileTooLarge
	}
	if req.TotalSize > s.cfg.Limits.MaxUploadSize {
		return nil, domain.ErrFileTooLarge
	}

	if req.TotalSize > user.MaxFileSize && user.MaxFileSize > 0 {
		return nil, domain.ErrFileTooLarge
	}

	safeFilename := crypto.SanitizeFilenameLimit(req.Filename, s.cfg.Limits.MaxFileNameLength)
	if req.MIMEType != "" {
		if err := validateMIMEType(req.MIMEType, s.cfg.Limits.AllowedMIMETypes); err != nil {
			return nil, err
		}
	}

	if err := crypto.ValidateExtension(safeFilename, s.cfg.Limits.AllowedExtensions, s.cfg.Limits.BlockedExtensions); err != nil {
		return nil, domain.ErrBlockedExtension
	}

	sessionID := uuid.New()
	storagePath := generateStoragePath(sessionID.String(), safeFilename)
	chunkSize := defaultUploadChunkSize
	if req.ChunkSize != 0 {
		if req.ChunkSize < minUploadChunkSize || req.ChunkSize > maxUploadChunkSize {
			return nil, fmt.Errorf("chunk_size must be between %d and %d bytes", minUploadChunkSize, maxUploadChunkSize)
		}
		chunkSize = req.ChunkSize
	}
	if req.TotalSize < int64(chunkSize) {
		chunkSize = int(req.TotalSize)
	}

	session := &domain.UploadSession{
		ID:          sessionID,
		UserID:      userID,
		Filename:    safeFilename,
		TotalSize:   req.TotalSize,
		ChunkSize:   chunkSize,
		MIMEType:    req.MIMEType,
		StoragePath: storagePath,
		Status:      "pending",
		ExpiresAt:   time.Now().Add(s.cfg.Worker.SessionExpiry),
	}

	if err := s.createReservation(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create upload session: %w", err)
	}

	return session, nil
}

// UploadChunk handles a chunk upload for resumable uploads
func (s *FileService) UploadChunk(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID, offset int64, reader io.Reader) (int64, error) {
	unlock := s.lockSession(sessionID)
	defer unlock()
	session, err := s.uploadRepo.GetByID(ctx, sessionID)
	if err != nil {
		return 0, err
	}

	// IDOR protection: verify the session belongs to this user
	if session.UserID != userID {
		return 0, domain.ErrForbidden
	}

	if time.Now().After(session.ExpiresAt) || (session.Status != "pending" && session.Status != "uploading") {
		return 0, domain.ErrUploadSessionExpired
	}

	if offset != session.UploadedBytes {
		return 0, domain.ErrChunkOutOfRange
	}
	exists, err := s.storage.Exists(ctx, session.StoragePath)
	if err != nil {
		return 0, fmt.Errorf("failed to validate upload state: %w", err)
	}
	if offset > 0 && !exists {
		return 0, domain.ErrUploadStateMismatch
	}
	if exists {
		actualOffset, err := s.storage.Size(ctx, session.StoragePath)
		if err != nil || actualOffset != offset {
			return 0, domain.ErrUploadStateMismatch
		}
	}
	remaining := session.TotalSize - offset
	if remaining <= 0 {
		return 0, domain.ErrChunkOutOfRange
	}
	chunkLimit := int64(session.ChunkSize)
	if chunkLimit <= 0 {
		return 0, domain.ErrChunkOutOfRange
	}
	if remaining < chunkLimit {
		chunkLimit = remaining
	}

	releaseCapacity, err := s.reserveCapacity(ctx, chunkLimit)
	if err != nil {
		return 0, err
	}
	defer releaseCapacity()

	// Write chunk to storage
	if err := s.storage.PutChunk(ctx, session.StoragePath, reader, offset, chunkLimit); err != nil {
		if errors.Is(err, storage.ErrChunkTooLarge) {
			return 0, domain.ErrChunkOutOfRange
		}
		if errors.Is(err, storage.ErrChunkOffsetMismatch) {
			return 0, domain.ErrUploadStateMismatch
		}
		return 0, fmt.Errorf("failed to write chunk: %w", err)
	}
	rollback := func(cause error) error {
		truncater, ok := s.storage.(storage.TruncateBackend)
		if !ok {
			return cause
		}
		if rollbackErr := truncater.Truncate(context.WithoutCancel(ctx), session.StoragePath, offset); rollbackErr != nil {
			return fmt.Errorf("%w (chunk rollback failed: %v)", cause, rollbackErr)
		}
		return cause
	}

	// Get actual size written
	newSize, err := s.storage.Size(ctx, session.StoragePath)
	if err != nil {
		return 0, rollback(fmt.Errorf("failed to inspect written chunk: %w", err))
	}
	if newSize > session.TotalSize {
		return 0, rollback(domain.ErrChunkOutOfRange)
	}

	if err := s.uploadRepo.UpdateProgress(ctx, sessionID, newSize, time.Now().Add(s.cfg.Worker.SessionExpiry)); err != nil {
		return 0, rollback(err)
	}

	return newSize, nil
}

// CompleteResumableUpload finalizes a resumable upload
func (s *FileService) CompleteResumableUpload(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID) (*domain.File, error) {
	unlock := s.lockSession(sessionID)
	defer unlock()
	session, err := s.uploadRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// IDOR protection: verify the session belongs to this user
	if session.UserID != userID {
		return nil, domain.ErrForbidden
	}
	if time.Now().After(session.ExpiresAt) || (session.Status != "pending" && session.Status != "uploading") {
		return nil, domain.ErrUploadSessionExpired
	}

	// Verify size
	actualSize, err := s.storage.Size(ctx, session.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to check file size: %w", err)
	}
	if actualSize != session.TotalSize || session.UploadedBytes != session.TotalSize {
		return nil, domain.ErrUploadIncomplete
	}

	// Sniff the stored content and compute SHA256 in a single sequential read.
	reader, err := s.storage.Get(ctx, session.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file for hash: %w", err)
	}
	defer reader.Close()

	buffered := bufio.NewReader(reader)
	mimeType, err := sniffMIMEType(buffered, session.Filename)
	if err != nil {
		return nil, domain.ErrInvalidMIMEType
	}
	if err := validateMIMEType(mimeType, s.cfg.Limits.AllowedMIMETypes); err != nil {
		return nil, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, buffered); err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	fileID := uuid.New()
	storedName := fmt.Sprintf("%s%s", fileID.String(), filepath.Ext(session.Filename))

	file := &domain.File{
		ID:             fileID,
		UserID:         session.UserID,
		OriginalName:   session.Filename,
		StoredName:     storedName,
		StoragePath:    session.StoragePath,
		StorageBackend: s.storage.Type(),
		MIMEType:       mimeType,
		SizeBytes:      actualSize,
		SHA256:         sha256Hash,
		UploadComplete: true,
		Metadata:       domain.JSONMap{},
	}

	if err := s.fileRepo.FinalizeUpload(ctx, file, sessionID); err != nil {
		if errors.Is(err, domain.ErrQuotaExceeded) {
			return nil, domain.ErrQuotaExceeded
		}
		return nil, fmt.Errorf("failed to create file record: %w", err)
	}

	return file, nil
}

// GetFile retrieves file metadata
func (s *FileService) GetFile(ctx context.Context, fileID uuid.UUID, userID uuid.UUID) (*domain.File, error) {
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, domain.ErrForbidden
	}

	if file.IsDeleted {
		return nil, domain.ErrFileDeleted
	}

	return file, nil
}

// ListFiles returns paginated files for a user
func (s *FileService) ListFiles(ctx context.Context, userID uuid.UUID, page, perPage int) ([]*domain.File, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	return s.fileRepo.ListByUser(ctx, userID, page, perPage)
}

// DeleteFile soft-deletes a file
func (s *FileService) DeleteFile(ctx context.Context, fileID uuid.UUID, userID uuid.UUID) error {
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return err
	}

	if file.UserID != userID {
		return domain.ErrForbidden
	}
	if file.IsDeleted {
		return domain.ErrFileDeleted
	}

	if err := s.fileRepo.SoftDeleteWithQuota(ctx, file); err != nil {
		return err
	}

	return nil
}

// GetQuota returns quota information for a user
func (s *FileService) GetQuota(ctx context.Context, userID uuid.UUID) (*domain.QuotaResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	fileCount, err := s.userRepo.GetFileCount(ctx, userID)
	if err != nil {
		return nil, err
	}
	reservedBytes, err := s.uploadRepo.ReservedBytes(ctx, userID)
	if err != nil {
		return nil, err
	}

	var usagePercent float64
	if user.QuotaBytes > 0 {
		usagePercent = float64(user.UsedBytes) / float64(user.QuotaBytes) * 100
	}

	return &domain.QuotaResponse{
		QuotaBytes:     user.QuotaBytes,
		UsedBytes:      user.UsedBytes,
		RemainingBytes: max64(0, user.QuotaRemaining()-reservedBytes),
		UsagePercent:   usagePercent,
		MaxFileSize:    user.MaxFileSize,
		FileCount:      fileCount,
	}, nil
}

// GetUploadStatus returns the status of a resumable upload
func (s *FileService) GetUploadStatus(ctx context.Context, sessionID, userID uuid.UUID) (*domain.UploadSession, error) {
	unlock := s.lockSession(sessionID)
	defer unlock()
	session, err := s.uploadRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.UserID != userID {
		return nil, domain.ErrForbidden
	}
	if time.Now().After(session.ExpiresAt) || (session.Status != "pending" && session.Status != "uploading") {
		return nil, domain.ErrUploadSessionExpired
	}
	exists, err := s.storage.Exists(ctx, session.StoragePath)
	if err != nil {
		return nil, err
	}
	if session.UploadedBytes > 0 && !exists {
		return nil, domain.ErrUploadStateMismatch
	}
	if exists {
		size, err := s.storage.Size(ctx, session.StoragePath)
		if err != nil || size != session.UploadedBytes {
			return nil, domain.ErrUploadStateMismatch
		}
	}
	return session, nil
}

// CleanupStaleUpload shares the same lock as writers and rechecks the claim.
func (s *FileService) CleanupStaleUpload(ctx context.Context, sessionID uuid.UUID) error {
	unlock := s.lockSession(sessionID)
	defer unlock()
	session, err := s.uploadRepo.GetByID(ctx, sessionID)
	if errors.Is(err, domain.ErrUploadSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if session.Status != "cleaning" {
		return nil
	}
	if err := s.storage.Delete(ctx, session.StoragePath); err != nil {
		return err
	}
	return s.uploadRepo.Delete(ctx, sessionID)
}

func (s *FileService) createReservation(ctx context.Context, session *domain.UploadSession) error {
	s.capacityMu.Lock()
	defer s.capacityMu.Unlock()
	available := int64(-1)
	if capacity, ok := s.storage.(storage.CapacityBackend); ok {
		var err error
		available, err = capacity.AvailableBytes(ctx)
		if err != nil {
			return err
		}
		available -= s.inFlight
		if available < 0 {
			return domain.ErrInsufficientStorage
		}
	}
	return s.uploadRepo.CreateWithQuota(ctx, session, available, s.cfg.Storage.MinFreeBytes)
}

// CancelUpload releases an active reservation and removes partial bytes.
func (s *FileService) CancelUpload(ctx context.Context, sessionID, userID uuid.UUID) error {
	unlock := s.lockSession(sessionID)
	defer unlock()
	session, err := s.uploadRepo.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != userID {
		return domain.ErrForbidden
	}
	if err := s.storage.Delete(ctx, session.StoragePath); err != nil {
		return fmt.Errorf("delete partial upload: %w", err)
	}
	return s.uploadRepo.DeleteOwned(ctx, sessionID, userID)
}

// --- helpers ---

// Renewal is driven by positive reads, including MIME sniffing. Empty or stalled
// reads never extend the lease, and a failed renewal is terminal.
type uploadLeaseReader struct {
	reader      io.Reader
	interval    time.Duration
	nextRenewal time.Time
	renew       func(time.Time) error
	err         error
}

func (r *uploadLeaseReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		progressAt := time.Now()
		if !progressAt.Before(r.nextRenewal) {
			if r.err = r.renew(progressAt); r.err != nil {
				return 0, r.err
			}
			r.nextRenewal = progressAt.Add(r.interval)
		}
	}
	return n, err
}

func newHashReader(r io.Reader) *hashingReader {
	h := sha256.New()
	return &hashingReader{
		reader: io.TeeReader(r, h),
		hasher: h,
	}
}

type hashingReader struct {
	reader io.Reader
	hasher interface {
		io.Writer
		Sum([]byte) []byte
	}
}

func (hr *hashingReader) Read(p []byte) (int, error) {
	return hr.reader.Read(p)
}

func (hr *hashingReader) Sum() string {
	return hex.EncodeToString(hr.hasher.Sum(nil))
}

func generateStoragePath(id, filename string) string {
	// Distribute files across directories: ab/cd/full-id/filename
	if len(id) >= 4 {
		return fmt.Sprintf("%s/%s/%s/%s", id[0:2], id[2:4], id, filename)
	}
	return fmt.Sprintf("%s/%s", id, filename)
}

func detectMIMEType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return "application/octet-stream"
	}

	// Try standard MIME detection
	mimeType := mime.TypeByExtension(ext)
	if mimeType != "" {
		return mimeType
	}

	// Common fallbacks
	mimeTypes := map[string]string{
		".cbz":  "application/x-cbz",
		".cbr":  "application/x-cbr",
		".epub": "application/epub+zip",
		".apk":  "application/vnd.android.package-archive",
		".iso":  "application/x-iso9660-image",
		".7z":   "application/x-7z-compressed",
		".dmg":  "application/x-apple-diskimage",
	}

	if mt, ok := mimeTypes[ext]; ok {
		return mt
	}

	return "application/octet-stream"
}

func sniffMIMEType(reader *bufio.Reader, filename string) (string, error) {
	header, err := reader.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return "", err
	}
	if len(header) == 0 {
		return detectMIMEType(filename), nil
	}
	return strings.ToLower(strings.TrimSpace(strings.SplitN(http.DetectContentType(header), ";", 2)[0])), nil
}

func validateMIMEType(value string, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	actual := strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	for _, candidate := range allowed {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == actual || (strings.HasSuffix(candidate, "/*") && strings.HasPrefix(actual, strings.TrimSuffix(candidate, "*"))) {
			return nil
		}
	}
	return domain.ErrInvalidMIMEType
}

func (s *FileService) reserveCapacity(ctx context.Context, bytes int64) (func(), error) {
	if bytes <= 0 {
		return func() {}, nil
	}
	capacity, ok := s.storage.(storage.CapacityBackend)
	if !ok {
		return func() {}, nil
	}
	s.capacityMu.Lock()
	defer s.capacityMu.Unlock()
	available, err := capacity.AvailableBytes(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect storage capacity: %w", err)
	}
	if bytes > available-s.cfg.Storage.MinFreeBytes-s.inFlight {
		return nil, domain.ErrInsufficientStorage
	}
	s.inFlight += bytes
	return func() {
		s.capacityMu.Lock()
		s.inFlight -= bytes
		s.capacityMu.Unlock()
	}, nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *FileService) lockSession(id uuid.UUID) func() {
	lock := &s.sessionMu[uint(id[0])%uint(len(s.sessionMu))]
	lock.Lock()
	return lock.Unlock
}
