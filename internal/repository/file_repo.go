package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
)

// FileRepository gère les opérations CRUD sur les fichiers en base de données.
// Supporte le listage paginé, la recherche par ID/hash, la gestion de l'expiration
// et le comptage des téléchargements.
type FileRepository struct {
	db *DB
}

// NewFileRepository crée un nouveau repository fichier.
func NewFileRepository(db *DB) *FileRepository {
	return &FileRepository{db: db}
}

// Create inserts a new file record
func (r *FileRepository) Create(ctx context.Context, file *domain.File) error {
	if file.ID == uuid.Nil {
		file.ID = uuid.New()
	}

	metadata, _ := json.Marshal(file.Metadata)

	query := `
		INSERT INTO files (id, user_id, original_name, stored_name, storage_path, storage_backend,
			mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING created_at, updated_at`

	return r.db.QueryRowContext(ctx, query,
		file.ID, file.UserID, file.OriginalName, file.StoredName, file.StoragePath,
		file.StorageBackend, file.MIMEType, file.SizeBytes, file.SHA256,
		file.IsEncrypted, file.EncryptionKeyID, file.UploadComplete, file.ExpiresAt,
		metadata,
	).Scan(&file.CreatedAt, &file.UpdatedAt)
}

// CreateWithQuota atomically reserves the user's quota and inserts the file.
// Keeping both operations in one transaction prevents concurrent uploads from
// exceeding the configured quota or leaving used_bytes out of sync.
func (r *FileRepository) CreateWithQuota(ctx context.Context, file *domain.File) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin file transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := reserveQuota(ctx, tx, file.UserID, file.SizeBytes); err != nil {
		return err
	}
	if err := createFile(ctx, tx, file); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit file transaction: %w", err)
	}
	return nil
}

// FinalizeUpload atomically consumes an upload session, reserves quota and
// creates the final file record. Deleting the session in the same transaction
// makes repeated or concurrent completion requests safe.
func (r *FileRepository) FinalizeUpload(ctx context.Context, file *domain.File, sessionID uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upload finalization: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var owner uuid.UUID
	if err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id=$1 AND is_active=true FOR UPDATE", file.UserID).Scan(&owner); err != nil {
		return fmt.Errorf("lock finalization owner: %w", err)
	}
	var lockedSession uuid.UUID
	if err := tx.QueryRowContext(ctx, "SELECT id FROM upload_sessions WHERE id=$1 AND user_id=$2 FOR UPDATE", sessionID, file.UserID).Scan(&lockedSession); err != nil {
		if err == sql.ErrNoRows {
			return domain.ErrUploadSessionNotFound
		}
		return fmt.Errorf("lock finalization session: %w", err)
	}

	result, err := tx.ExecContext(ctx,
		"DELETE FROM upload_sessions WHERE id = $1 AND user_id = $2 AND status IN ('pending', 'uploading') AND expires_at > clock_timestamp()",
		sessionID, file.UserID,
	)
	if err != nil {
		return fmt.Errorf("consume upload session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check upload session: %w", err)
	}
	if rows != 1 {
		return domain.ErrUploadSessionNotFound
	}

	if err := reserveQuota(ctx, tx, file.UserID, file.SizeBytes); err != nil {
		return err
	}
	if err := createFile(ctx, tx, file); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit upload finalization: %w", err)
	}
	return nil
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func reserveQuota(ctx context.Context, exec sqlExecutor, userID uuid.UUID, size int64) error {
	// Take the owner lock before the reservation subquery's statement snapshot.
	var owner uuid.UUID
	if err := exec.QueryRowContext(ctx, "SELECT id FROM users WHERE id=$1 AND is_active=true FOR UPDATE", userID).Scan(&owner); err != nil {
		return fmt.Errorf("lock quota owner: %w", err)
	}
	result, err := exec.ExecContext(ctx, `UPDATE users
		SET used_bytes = used_bytes + $1::bigint
		WHERE id = $2 AND $1::bigint >= 0
		AND used_bytes + $1::bigint + COALESCE((
			SELECT SUM(total_size) FROM upload_sessions
			WHERE user_id=$2 AND status IN ('pending','uploading','cleaning')
		),0) <= quota_bytes`, size, userID)
	if err != nil {
		return fmt.Errorf("reserve user quota: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check user quota: %w", err)
	}
	if rows != 1 {
		return domain.ErrQuotaExceeded
	}
	return nil
}

func createFile(ctx context.Context, exec sqlExecutor, file *domain.File) error {
	if file.ID == uuid.Nil {
		file.ID = uuid.New()
	}
	metadata, err := json.Marshal(file.Metadata)
	if err != nil {
		return fmt.Errorf("encode file metadata: %w", err)
	}
	query := `
		INSERT INTO files (id, user_id, original_name, stored_name, storage_path, storage_backend,
			mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING created_at, updated_at`
	if err := exec.QueryRowContext(ctx, query,
		file.ID, file.UserID, file.OriginalName, file.StoredName, file.StoragePath,
		file.StorageBackend, file.MIMEType, file.SizeBytes, file.SHA256,
		file.IsEncrypted, file.EncryptionKeyID, file.UploadComplete, file.ExpiresAt,
		metadata,
	).Scan(&file.CreatedAt, &file.UpdatedAt); err != nil {
		return fmt.Errorf("create file record: %w", err)
	}
	return nil
}

// GetByID retrieves a file by ID
func (r *FileRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.File, error) {
	query := `SELECT id, user_id, original_name, stored_name, storage_path, storage_backend,
		mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete,
		download_count, is_deleted, deleted_at, expires_at, metadata, created_at, updated_at
		FROM files WHERE id = $1`

	file := &domain.File{}
	var metadata []byte
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&file.ID, &file.UserID, &file.OriginalName, &file.StoredName, &file.StoragePath,
		&file.StorageBackend, &file.MIMEType, &file.SizeBytes, &file.SHA256,
		&file.IsEncrypted, &file.EncryptionKeyID, &file.UploadComplete,
		&file.DownloadCount, &file.IsDeleted, &file.DeletedAt, &file.ExpiresAt,
		&metadata, &file.CreatedAt, &file.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get file: %w", err)
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &file.Metadata); err != nil {
			return nil, fmt.Errorf("decode file metadata: %w", err)
		}
	}

	return file, nil
}

// ListByUser returns files for a user with pagination
func (r *FileRepository) ListByUser(ctx context.Context, userID uuid.UUID, page, perPage int) ([]*domain.File, int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM files WHERE user_id = $1 AND is_deleted = false",
		userID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	query := `SELECT id, user_id, original_name, stored_name, storage_path, storage_backend,
		mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete,
		download_count, is_deleted, deleted_at, expires_at, metadata, created_at, updated_at
		FROM files WHERE user_id = $1 AND is_deleted = false
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, userID, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var files []*domain.File
	for rows.Next() {
		f := &domain.File{}
		var metadata []byte
		if err := rows.Scan(
			&f.ID, &f.UserID, &f.OriginalName, &f.StoredName, &f.StoragePath,
			&f.StorageBackend, &f.MIMEType, &f.SizeBytes, &f.SHA256,
			&f.IsEncrypted, &f.EncryptionKeyID, &f.UploadComplete,
			&f.DownloadCount, &f.IsDeleted, &f.DeletedAt, &f.ExpiresAt,
			&metadata, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &f.Metadata); err != nil {
				return nil, 0, fmt.Errorf("decode file metadata: %w", err)
			}
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return files, total, nil
}

// MarkComplete sets upload_complete = true
func (r *FileRepository) MarkComplete(ctx context.Context, id uuid.UUID, sha256 string, sizeBytes int64) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE files SET upload_complete = true, sha256 = $1, size_bytes = $2 WHERE id = $3",
		sha256, sizeBytes, id,
	)
	return err
}

// IncrementDownloads atomically increments the download count
func (r *FileRepository) IncrementDownloads(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE files SET download_count = download_count + 1 WHERE id = $1",
		id,
	)
	return err
}

// SoftDelete marks a file as deleted
func (r *FileRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		"UPDATE files SET is_deleted = true, deleted_at = $1 WHERE id = $2",
		now, id,
	)
	return err
}

// SoftDeleteWithQuota marks a live file deleted and releases owner quota in
// one transaction. Repeated deletes cannot decrement quota twice.
func (r *FileRepository) SoftDeleteWithQuota(ctx context.Context, file *domain.File) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin file deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE files SET is_deleted=true, deleted_at=NOW()
		WHERE id=$1 AND is_deleted=false`, file.ID)
	if err != nil {
		return fmt.Errorf("soft delete file: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return domain.ErrFileDeleted
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users
		SET used_bytes=GREATEST(0, used_bytes-$1::bigint) WHERE id=$2`, file.SizeBytes, file.UserID); err != nil {
		return fmt.Errorf("release file quota: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit file deletion: %w", err)
	}
	return nil
}

// HardDeleteWithQuota permanently removes a live file and releases quota
// atomically. It is used by expiration cleanup after storage deletion.
func (r *FileRepository) HardDeleteWithQuota(ctx context.Context, file *domain.File) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin expired file deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, "DELETE FROM files WHERE id=$1 AND is_deleted=false", file.ID)
	if err != nil {
		return fmt.Errorf("delete expired file: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return domain.ErrFileNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users
		SET used_bytes=GREATEST(0, used_bytes-$1::bigint) WHERE id=$2`, file.SizeBytes, file.UserID); err != nil {
		return fmt.Errorf("release expired file quota: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit expired file deletion: %w", err)
	}
	return nil
}

// HardDelete removes the file record
func (r *FileRepository) HardDelete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM files WHERE id = $1", id)
	return err
}

// GetExpiredFiles returns files that have expired
func (r *FileRepository) GetExpiredFiles(ctx context.Context, limit int) ([]*domain.File, error) {
	query := `SELECT id, user_id, original_name, stored_name, storage_path, storage_backend,
		mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete,
		download_count, is_deleted, deleted_at, expires_at, metadata, created_at, updated_at
		FROM files WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_deleted = false
		LIMIT $1`

	return r.scanFiles(ctx, query, limit)
}

// GetSoftDeletedFiles returns files marked for cleanup
func (r *FileRepository) GetSoftDeletedFiles(ctx context.Context, olderThan time.Duration, limit int) ([]*domain.File, error) {
	cutoff := time.Now().Add(-olderThan)
	query := `SELECT id, user_id, original_name, stored_name, storage_path, storage_backend,
		mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete,
		download_count, is_deleted, deleted_at, expires_at, metadata, created_at, updated_at
		FROM files WHERE is_deleted = true AND deleted_at < $1
		LIMIT $2`

	return r.scanFiles(ctx, query, cutoff, limit)
}

// UpdateSize updates file size
func (r *FileRepository) UpdateSize(ctx context.Context, id uuid.UUID, size int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE files SET size_bytes = $1 WHERE id = $2", size, id)
	return err
}

func (r *FileRepository) scanFiles(ctx context.Context, query string, args ...interface{}) ([]*domain.File, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*domain.File
	for rows.Next() {
		f := &domain.File{}
		var metadata []byte
		if err := rows.Scan(
			&f.ID, &f.UserID, &f.OriginalName, &f.StoredName, &f.StoragePath,
			&f.StorageBackend, &f.MIMEType, &f.SizeBytes, &f.SHA256,
			&f.IsEncrypted, &f.EncryptionKeyID, &f.UploadComplete,
			&f.DownloadCount, &f.IsDeleted, &f.DeletedAt, &f.ExpiresAt,
			&metadata, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &f.Metadata); err != nil {
				return nil, fmt.Errorf("decode file metadata: %w", err)
			}
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

// GetBySHA256 finds files by hash (for deduplication)
func (r *FileRepository) GetBySHA256(ctx context.Context, hash string, userID uuid.UUID) (*domain.File, error) {
	query := `SELECT id, user_id, original_name, stored_name, storage_path, storage_backend,
		mime_type, size_bytes, sha256, is_encrypted, encryption_key_id, upload_complete,
		download_count, is_deleted, deleted_at, expires_at, metadata, created_at, updated_at
		FROM files WHERE sha256 = $1 AND user_id = $2 AND is_deleted = false AND upload_complete = true
		LIMIT 1`

	file := &domain.File{}
	var metadata []byte
	err := r.db.QueryRowContext(ctx, query, hash, userID).Scan(
		&file.ID, &file.UserID, &file.OriginalName, &file.StoredName, &file.StoragePath,
		&file.StorageBackend, &file.MIMEType, &file.SizeBytes, &file.SHA256,
		&file.IsEncrypted, &file.EncryptionKeyID, &file.UploadComplete,
		&file.DownloadCount, &file.IsDeleted, &file.DeletedAt, &file.ExpiresAt,
		&metadata, &file.CreatedAt, &file.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Not found is not an error
	}
	if err != nil {
		return nil, err
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &file.Metadata); err != nil {
			return nil, fmt.Errorf("decode file metadata: %w", err)
		}
	}

	return file, nil
}
