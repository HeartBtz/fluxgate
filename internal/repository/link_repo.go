package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// LinkRepository gère les opérations CRUD sur les liens de téléchargement.
// Supporte la recherche par token, le compteur de téléchargements,
// la révocation et la suppression des liens expirés.
type LinkRepository struct {
	db *DB
}

// NewLinkRepository crée un nouveau repository de liens.
func NewLinkRepository(db *DB) *LinkRepository {
	return &LinkRepository{db: db}
}

// Create inserts a new download link
func (r *LinkRepository) Create(ctx context.Context, link *domain.DownloadLink) error {
	if link.ID == uuid.Nil {
		link.ID = uuid.New()
	}

	query := `
		INSERT INTO download_links (id, file_id, user_id, token, link_type, is_active,
			password_hash, max_downloads, allowed_ips, forced_filename, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING created_at`

	return r.db.QueryRowContext(ctx, query,
		link.ID, link.FileID, link.UserID, hashLinkToken(link.Token), link.LinkType, link.IsActive,
		link.PasswordHash, link.MaxDownloads, pq.Array(link.AllowedIPs),
		link.ForcedFilename, link.ExpiresAt,
	).Scan(&link.CreatedAt)
}

// GetByToken retrieves a link by its download token
func (r *LinkRepository) GetByToken(ctx context.Context, token string) (*domain.DownloadLink, error) {
	// The legacy plaintext fallback must never accept a stored digest as a bearer.
	if strings.HasPrefix(token, "sha256:") {
		return nil, domain.ErrLinkNotFound
	}
	query := `SELECT id, file_id, user_id, token, link_type, is_active,
		password_hash, max_downloads, current_downloads, allowed_ips,
		forced_filename, expires_at, created_at, revoked_at
			FROM download_links WHERE token = $1 OR token = $2
			ORDER BY CASE WHEN token = $1 THEN 0 ELSE 1 END LIMIT 1`

	link := &domain.DownloadLink{}
	err := r.db.QueryRowContext(ctx, query, hashLinkToken(token), token).Scan(
		&link.ID, &link.FileID, &link.UserID, &link.Token, &link.LinkType, &link.IsActive,
		&link.PasswordHash, &link.MaxDownloads, &link.CurrentDownloads, pq.Array(&link.AllowedIPs),
		&link.ForcedFilename, &link.ExpiresAt, &link.CreatedAt, &link.RevokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get link: %w", err)
	}

	return link, nil
}

func hashLinkToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// GetByID retrieves a link by ID
func (r *LinkRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.DownloadLink, error) {
	query := `SELECT id, file_id, user_id, token, link_type, is_active,
		password_hash, max_downloads, current_downloads, allowed_ips,
		forced_filename, expires_at, created_at, revoked_at
		FROM download_links WHERE id = $1`

	link := &domain.DownloadLink{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&link.ID, &link.FileID, &link.UserID, &link.Token, &link.LinkType, &link.IsActive,
		&link.PasswordHash, &link.MaxDownloads, &link.CurrentDownloads, pq.Array(&link.AllowedIPs),
		&link.ForcedFilename, &link.ExpiresAt, &link.CreatedAt, &link.RevokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get link: %w", err)
	}

	return link, nil
}

// ListByFile returns all links for a file
func (r *LinkRepository) ListByFile(ctx context.Context, fileID uuid.UUID) ([]*domain.DownloadLink, error) {
	query := `SELECT id, file_id, user_id, token, link_type, is_active,
		password_hash, max_downloads, current_downloads, allowed_ips,
		forced_filename, expires_at, created_at, revoked_at
		FROM download_links WHERE file_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []*domain.DownloadLink
	for rows.Next() {
		link := &domain.DownloadLink{}
		if err := rows.Scan(
			&link.ID, &link.FileID, &link.UserID, &link.Token, &link.LinkType, &link.IsActive,
			&link.PasswordHash, &link.MaxDownloads, &link.CurrentDownloads, pq.Array(&link.AllowedIPs),
			&link.ForcedFilename, &link.ExpiresAt, &link.CreatedAt, &link.RevokedAt,
		); err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return links, nil
}

// ListByUser returns links created by a user
func (r *LinkRepository) ListByUser(ctx context.Context, userID uuid.UUID, page, perPage int) ([]*domain.DownloadLink, int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM download_links WHERE user_id = $1",
		userID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	query := `SELECT id, file_id, user_id, token, link_type, is_active,
		password_hash, max_downloads, current_downloads, allowed_ips,
		forced_filename, expires_at, created_at, revoked_at
		FROM download_links WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, userID, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var links []*domain.DownloadLink
	for rows.Next() {
		link := &domain.DownloadLink{}
		if err := rows.Scan(
			&link.ID, &link.FileID, &link.UserID, &link.Token, &link.LinkType, &link.IsActive,
			&link.PasswordHash, &link.MaxDownloads, &link.CurrentDownloads, pq.Array(&link.AllowedIPs),
			&link.ForcedFilename, &link.ExpiresAt, &link.CreatedAt, &link.RevokedAt,
		); err != nil {
			return nil, 0, err
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return links, total, nil
}

// IncrementDownloads atomically increments the download counter
func (r *LinkRepository) IncrementDownloads(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE download_links SET current_downloads = current_downloads + 1 WHERE id = $1",
		id,
	)
	return err
}

// ReserveDownload atomically consumes one download slot. This prevents
// concurrent requests from exceeding max_downloads after validating the same
// stale counter value.
func (r *LinkRepository) ReserveDownload(ctx context.Context, id uuid.UUID) (bool, error) {
	result, err := r.db.ExecContext(ctx,
		`UPDATE download_links SET current_downloads = current_downloads + 1
		 WHERE id = $1 AND is_active = true AND revoked_at IS NULL
		 AND (expires_at IS NULL OR expires_at > NOW())
		 AND EXISTS (SELECT 1 FROM files WHERE files.id=download_links.file_id
		     AND is_deleted=false AND upload_complete=true
		     AND (files.expires_at IS NULL OR files.expires_at > NOW()))
		 AND (max_downloads IS NULL OR current_downloads < max_downloads)`, id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (r *LinkRepository) ReleaseDownload(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE download_links SET current_downloads = GREATEST(current_downloads - 1, 0) WHERE id = $1", id)
	return err
}

// Revoke deactivates a download link
func (r *LinkRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		"UPDATE download_links SET is_active = false, revoked_at = $1 WHERE id = $2",
		now, id,
	)
	return err
}

// Delete removes a link
func (r *LinkRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM download_links WHERE id = $1", id)
	return err
}

// CountByFile returns count of active links for a file
func (r *LinkRepository) CountByFile(ctx context.Context, fileID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM download_links WHERE file_id = $1 AND is_active = true",
		fileID,
	).Scan(&count)
	return count, err
}

func (r *LinkRepository) CountByFiles(ctx context.Context, fileIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	counts := make(map[uuid.UUID]int, len(fileIDs))
	if len(fileIDs) == 0 {
		return counts, nil
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT file_id, COUNT(*) FROM download_links
		 WHERE file_id = ANY($1) AND is_active = true GROUP BY file_id`, pq.Array(fileIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		counts[id] = count
	}
	return counts, rows.Err()
}

// CountAll returns total count of active, non-expired links
func (r *LinkRepository) CountAll(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM download_links WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())",
	).Scan(&count)
	return count, err
}

// CleanupExpired removes expired links
func (r *LinkRepository) CleanupExpired(ctx context.Context, limit int) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM download_links WHERE id IN (
			SELECT id FROM download_links
			WHERE expires_at IS NOT NULL AND expires_at < NOW()
			LIMIT $1
		)`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
