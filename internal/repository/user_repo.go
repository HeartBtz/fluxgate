package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
)

// UserRepository gère les opérations CRUD sur les utilisateurs en base de données.
// Fournit la recherche par ID, username et email, ainsi que la mise à jour du quota.
type UserRepository struct {
	db *DB
}

// NewUserRepository crée un nouveau repository utilisateur.
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, role, is_active, quota_bytes, used_bytes, max_file_size)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at, updated_at`

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	return r.db.QueryRowContext(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash,
		user.Role, user.IsActive, user.QuotaBytes, user.UsedBytes, user.MaxFileSize,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_active, quota_bytes, used_bytes, max_file_size, created_at, updated_at
		FROM users WHERE id = $1`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.Role, &user.IsActive, &user.QuotaBytes, &user.UsedBytes,
		&user.MaxFileSize, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_active, quota_bytes, used_bytes, max_file_size, created_at, updated_at
		FROM users WHERE username = $1`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.Role, &user.IsActive, &user.QuotaBytes, &user.UsedBytes,
		&user.MaxFileSize, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, username, email, password_hash, role, is_active, quota_bytes, used_bytes, max_file_size, created_at, updated_at
		FROM users WHERE email = $1`

	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.Role, &user.IsActive, &user.QuotaBytes, &user.UsedBytes,
		&user.MaxFileSize, &user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// UpdateUsedBytes atomically updates the used_bytes for a user
func (r *UserRepository) UpdateUsedBytes(ctx context.Context, userID uuid.UUID, delta int64) error {
	query := `UPDATE users SET used_bytes = used_bytes + $1 WHERE id = $2 AND used_bytes + $1 >= 0`
	result, err := r.db.ExecContext(ctx, query, delta, userID)
	if err != nil {
		return fmt.Errorf("failed to update used bytes: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found or insufficient space")
	}
	return nil
}

// Update updates user fields
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `UPDATE users SET username=$1, email=$2, role=$3, is_active=$4, quota_bytes=$5, max_file_size=$6, updated_at=NOW()
		WHERE id = $7`
	_, err := r.db.ExecContext(ctx, query,
		user.Username, user.Email, user.Role, user.IsActive,
		user.QuotaBytes, user.MaxFileSize, user.ID,
	)
	return err
}

func (r *UserRepository) UpdateAdmin(ctx context.Context, user *domain.User, passwordHash *string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := protectAdminChange(ctx, tx, user.ID, user.Role == "admin" && user.IsActive); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET username=$1, email=$2, role=$3,
		is_active=$4, quota_bytes=$5, max_file_size=$6,
		password_hash=COALESCE($7::text, password_hash), updated_at=NOW()
		WHERE id=$8`, user.Username, user.Email, user.Role, user.IsActive,
		user.QuotaBytes, user.MaxFileSize, passwordHash, user.ID)
	if err != nil {
		return fmt.Errorf("admin update user: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return domain.ErrUserNotFound
	}
	return tx.Commit()
}

func protectAdminChange(ctx context.Context, tx *sql.Tx, id uuid.UUID, remainsAdmin bool) error {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(684290318)"); err != nil {
		return err
	}
	var activeAdmin bool
	if err := tx.QueryRowContext(ctx, "SELECT role='admin' AND is_active FROM users WHERE id=$1 FOR UPDATE", id).Scan(&activeAdmin); err != nil {
		return err
	}
	if activeAdmin && !remainsAdmin {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=true AND id<>$1", id).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return domain.ErrForbidden
		}
	}
	return nil
}

func (r *UserRepository) CountActiveAdmins(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=true").Scan(&count)
	return count, err
}

func (r *UserRepository) HasStoredData(ctx context.Context, userID uuid.UUID) (bool, error) {
	var hasData bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM files WHERE user_id=$1
		UNION ALL SELECT 1 FROM upload_sessions WHERE user_id=$1
	)`, userID).Scan(&hasData)
	return hasData, err
}

// List returns paginated users
func (r *UserRepository) List(ctx context.Context, page, perPage int) ([]*domain.User, int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	query := `SELECT id, username, email, password_hash, role, is_active, quota_bytes, used_bytes, max_file_size, created_at, updated_at
		FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := r.db.QueryContext(ctx, query, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u := &domain.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash,
			&u.Role, &u.IsActive, &u.QuotaBytes, &u.UsedBytes,
			&u.MaxFileSize, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// Delete removes a user
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := protectAdminChange(ctx, tx, id, false); err != nil {
		return err
	}
	var hasData bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM files WHERE user_id=$1
		UNION ALL SELECT 1 FROM upload_sessions WHERE user_id=$1
	)`, id).Scan(&hasData); err != nil {
		return err
	}
	if hasData {
		return domain.ErrUserHasData
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return domain.ErrUserNotFound
	}
	return tx.Commit()
}

// Exists checks if a username or email exists
func (r *UserRepository) Exists(ctx context.Context, username, email string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2",
		username, email,
	).Scan(&count)
	return count > 0, err
}

// UpdatePassword updates the password hash
func (r *UserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, hash string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET password_hash = $1, updated_at=NOW() WHERE id = $2",
		hash, userID,
	)
	return err
}

// GetUsedBytes returns total bytes used by a user (recalculated from files)
func (r *UserRepository) GetUsedBytes(ctx context.Context, userID uuid.UUID) (int64, error) {
	var total sql.NullInt64
	err := r.db.QueryRowContext(ctx,
		"SELECT COALESCE(SUM(size_bytes), 0) FROM files WHERE user_id = $1 AND is_deleted = false AND upload_complete = true",
		userID,
	).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total.Int64, nil
}

// GetFileCount returns total file count for a user
func (r *UserRepository) GetFileCount(ctx context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM files WHERE user_id = $1 AND is_deleted = false AND upload_complete = true",
		userID,
	).Scan(&count)
	return count, err
}
