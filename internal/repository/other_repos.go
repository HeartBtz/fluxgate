package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// APIKeyRepository gère les opérations CRUD sur les clés API en base de données.
// Les clés sont stockées sous forme de hash SHA-256, jamais en clair.
type APIKeyRepository struct {
	db *DB
}

// NewAPIKeyRepository crée un nouveau repository de clés API.
func NewAPIKeyRepository(db *DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// Create inserts a new API key
func (r *APIKeyRepository) Create(ctx context.Context, key *domain.APIKey) error {
	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}

	query := `INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, is_active, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created_at`

	return r.db.QueryRowContext(ctx, query,
		key.ID, key.UserID, key.Name, key.KeyHash, key.KeyPrefix,
		pq.Array(key.Scopes), key.IsActive, key.ExpiresAt,
	).Scan(&key.CreatedAt)
}

// GetByHash retrieves an API key by its hash
func (r *APIKeyRepository) GetByHash(ctx context.Context, hash string) (*domain.APIKey, error) {
	query := `SELECT id, user_id, name, key_hash, key_prefix, scopes, is_active, last_used_at, expires_at, created_at
		FROM api_keys WHERE key_hash = $1`

	key := &domain.APIKey{}
	err := r.db.QueryRowContext(ctx, query, hash).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyHash, &key.KeyPrefix,
		pq.Array(&key.Scopes), &key.IsActive, &key.LastUsedAt, &key.ExpiresAt, &key.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrInvalidAPIKey
	}
	return key, err
}

// ListByUser returns API keys for a user
func (r *APIKeyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*domain.APIKey, error) {
	query := `SELECT id, user_id, name, key_hash, key_prefix, scopes, is_active, last_used_at, expires_at, created_at
		FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*domain.APIKey
	for rows.Next() {
		k := &domain.APIKey{}
		if err := rows.Scan(
			&k.ID, &k.UserID, &k.Name, &k.KeyHash, &k.KeyPrefix,
			pq.Array(&k.Scopes), &k.IsActive, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

// UpdateLastUsed updates the last_used_at timestamp
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", id)
	return err
}

// Revoke deactivates an API key
func (r *APIKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE api_keys SET is_active = false WHERE id = $1", id)
	return err
}

// Delete removes an API key
func (r *APIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = $1", id)
	return err
}

// DownloadLogRepository handles download audit log operations
type DownloadLogRepository struct {
	db *DB
}

func NewDownloadLogRepository(db *DB) *DownloadLogRepository {
	return &DownloadLogRepository{db: db}
}

// Create inserts a download log entry
func (r *DownloadLogRepository) Create(ctx context.Context, log *domain.DownloadLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}

	query := `INSERT INTO download_logs (id, file_id, link_id, ip_address, user_agent, referer,
		bytes_sent, is_complete, is_resumed, started_at, completed_at)
		VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.ExecContext(ctx, query,
		log.ID, log.FileID, log.LinkID, log.IPAddress, log.UserAgent,
		log.Referer, log.BytesSent, log.IsComplete, log.IsResumed, log.StartedAt, log.CompletedAt)
	return err
}

// AuditLogRepository handles audit log operations
type AuditLogRepository struct {
	db *DB
}

func NewAuditLogRepository(db *DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// Create inserts an audit log entry
func (r *AuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}

	details, _ := json.Marshal(log.Details)

	query := `INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, ip_address, user_agent, details)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8) RETURNING created_at`

	return r.db.QueryRowContext(ctx, query,
		log.ID, log.UserID, log.Action, log.ResourceType, log.ResourceID,
		log.IPAddress, log.UserAgent, details,
	).Scan(&log.CreatedAt)
}

// UploadSessionRepository handles upload session operations
type UploadSessionRepository struct {
	db *DB
}

func NewUploadSessionRepository(db *DB) *UploadSessionRepository {
	return &UploadSessionRepository{db: db}
}

// CreateWithQuota atomically reserves user quota and filesystem capacity for a
// new upload session. Reservations are represented by active upload_sessions,
// so deleting or finalizing the row releases them without a second counter.
func (r *UploadSessionRepository) CreateWithQuota(ctx context.Context, session *domain.UploadSession, availableBytes, minFreeBytes int64) error {
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upload reservation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize capacity admission across users and processes.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(684290317)"); err != nil {
		return fmt.Errorf("lock upload capacity: %w", err)
	}

	var quotaBytes, usedBytes, userReserved, globalOutstanding int64
	if err := tx.QueryRowContext(ctx,
		"SELECT quota_bytes, used_bytes FROM users WHERE id=$1 AND is_active=true FOR UPDATE", session.UserID,
	).Scan(&quotaBytes, &usedBytes); err != nil {
		if err == sql.ErrNoRows {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("lock upload owner: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(total_size) FILTER (WHERE user_id=$1 AND status IN ('pending','uploading','cleaning')),0),
		COALESCE(SUM(GREATEST(total_size-uploaded_bytes,0)) FILTER (WHERE status IN ('pending','uploading','cleaning')),0)
		FROM upload_sessions`, session.UserID).Scan(&userReserved, &globalOutstanding); err != nil {
		return fmt.Errorf("calculate upload reservations: %w", err)
	}
	if session.TotalSize > quotaBytes-usedBytes-userReserved {
		return domain.ErrQuotaExceeded
	}
	if availableBytes >= 0 && session.TotalSize > availableBytes-minFreeBytes-globalOutstanding {
		return domain.ErrInsufficientStorage
	}

	query := `INSERT INTO upload_sessions (id, user_id, filename, total_size, chunk_size, mime_type, storage_path, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at, updated_at, expires_at`

	if err := tx.QueryRowContext(ctx, query,
		session.ID, session.UserID, session.Filename, session.TotalSize,
		session.ChunkSize, session.MIMEType, session.StoragePath, session.Status, session.ExpiresAt,
	).Scan(&session.CreatedAt, &session.UpdatedAt, &session.ExpiresAt); err != nil {
		return fmt.Errorf("create upload session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit upload reservation: %w", err)
	}
	return nil
}

// GetByID retrieves an upload session
func (r *UploadSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.UploadSession, error) {
	query := `SELECT id, user_id, filename, total_size, uploaded_bytes, chunk_size, mime_type, storage_path, status, created_at, updated_at, expires_at
		FROM upload_sessions WHERE id = $1`

	s := &domain.UploadSession{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&s.ID, &s.UserID, &s.Filename, &s.TotalSize, &s.UploadedBytes,
		&s.ChunkSize, &s.MIMEType, &s.StoragePath, &s.Status,
		&s.CreatedAt, &s.UpdatedAt, &s.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrUploadSessionNotFound
	}
	return s, err
}

// UpdateProgress updates the upload progress
func (r *UploadSessionRepository) UpdateProgress(ctx context.Context, id uuid.UUID, uploadedBytes int64, expiresAt time.Time) error {
	tx, err := r.lockSession(ctx, id)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`UPDATE upload_sessions SET uploaded_bytes = $1, status = 'uploading', expires_at = $2
		WHERE id = $3 AND status IN ('pending', 'uploading')
		AND expires_at > clock_timestamp() AND $2 > clock_timestamp()`,
		uploadedBytes, expiresAt, id,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return domain.ErrUploadSessionExpired
	}
	return tx.Commit()
}

// RenewLease never revives an expired or claimed upload. Lock first, then check
// wall-clock expiry in a new statement: NOW() would predate a lock wait.
func (r *UploadSessionRepository) RenewLease(ctx context.Context, id uuid.UUID, expiresAt time.Time) error {
	tx, err := r.lockSession(ctx, id)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE upload_sessions SET expires_at=$2
		WHERE id=$1 AND status IN ('pending','uploading')
		AND expires_at > clock_timestamp() AND $2 > clock_timestamp()`, id, expiresAt)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return domain.ErrUploadSessionExpired
	}
	return tx.Commit()
}

func (r *UploadSessionRepository) lockSession(ctx context.Context, id uuid.UUID) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var lockedID uuid.UUID
	if err := tx.QueryRowContext(ctx, "SELECT id FROM upload_sessions WHERE id=$1 FOR UPDATE", id).Scan(&lockedID); err != nil {
		_ = tx.Rollback()
		if err == sql.ErrNoRows {
			return nil, domain.ErrUploadSessionExpired
		}
		return nil, err
	}
	return tx, nil
}

// MarkComplete marks the upload session as complete
func (r *UploadSessionRepository) MarkComplete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE upload_sessions SET status = 'complete' WHERE id = $1", id)
	return err
}

// GetStale atomically claims a bounded batch of abandoned upload sessions.
// A concurrent finalization only accepts pending/uploading rows, so once a row
// is marked cleaning its storage object is safe for the worker to remove.
func (r *UploadSessionRepository) GetStale(ctx context.Context, updatedBefore time.Time, limit int) ([]*domain.UploadSession, error) {
	query := `WITH candidates AS (
			SELECT id FROM upload_sessions
			WHERE updated_at < $1 AND status != 'complete' AND expires_at <= clock_timestamp()
			ORDER BY updated_at LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		UPDATE upload_sessions AS sessions SET status = 'cleaning'
		FROM candidates WHERE sessions.id = candidates.id
		RETURNING sessions.id, sessions.user_id, sessions.filename, sessions.total_size,
			sessions.uploaded_bytes, sessions.chunk_size, sessions.mime_type, sessions.storage_path,
			sessions.status, sessions.created_at, sessions.updated_at, sessions.expires_at`

	rows, err := r.db.QueryContext(ctx, query, updatedBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*domain.UploadSession
	for rows.Next() {
		s := &domain.UploadSession{}
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.Filename, &s.TotalSize, &s.UploadedBytes,
			&s.ChunkSize, &s.MIMEType, &s.StoragePath, &s.Status,
			&s.CreatedAt, &s.UpdatedAt, &s.ExpiresAt,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

// Delete removes one upload session after its partial storage object is gone.
func (r *UploadSessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM upload_sessions WHERE id = $1", id)
	return err
}

func (r *UploadSessionRepository) DeleteOwned(ctx context.Context, id, userID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM upload_sessions WHERE id=$1 AND user_id=$2", id, userID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return domain.ErrUploadSessionNotFound
	}
	return nil
}

// ReservedBytes returns active upload reservations for one user.
func (r *UploadSessionRepository) ReservedBytes(ctx context.Context, userID uuid.UUID) (int64, error) {
	var reserved int64
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_size),0)
		FROM upload_sessions WHERE user_id=$1 AND status IN ('pending','uploading','cleaning')`, userID).Scan(&reserved)
	return reserved, err
}

func (r *UploadSessionRepository) OutstandingBytes(ctx context.Context) (int64, error) {
	var outstanding int64
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(GREATEST(total_size-uploaded_bytes,0)),0)
		FROM upload_sessions WHERE status IN ('pending','uploading','cleaning')`).Scan(&outstanding)
	return outstanding, err
}
