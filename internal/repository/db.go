// Package repository implémente la couche d'accès aux données PostgreSQL de FluxGate.
//
// Chaque repository est spécialisé pour une entité du domaine :
//   - UserRepository         : utilisateurs (CRUD, recherche, quota)
//   - FileRepository         : fichiers (CRUD, listage, expiration)
//   - LinkRepository         : liens de téléchargement (CRUD, compteur)
//   - APIKeyRepository       : clés API (CRUD, recherche par hash)
//   - DownloadLogRepository  : logs d'audit des téléchargements
//   - UploadSessionRepository: sessions d'upload par morceaux
//
// Les requêtes SQL utilisent des paramètres ($1, $2...) pour éviter les injections.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// DB encapsule le pool de connexions PostgreSQL.
// Fournit les méthodes HealthCheck et RunMigrations en plus du sql.DB standard.
type DB struct {
	*sql.DB
}

// NewDB crée une nouvelle connexion à la base de données avec les paramètres de pool.
func NewDB(dsn string, maxOpen, maxIdle int, maxLifetime time.Duration) (*DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(maxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{db}, nil
}

// RunMigrations executes SQL migration files
func (db *DB) RunMigrations(migrationsPath string) error {
	// Create migrations tracking table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Find migration files
	files, err := filepath.Glob(filepath.Join(migrationsPath, "*.up.sql"))
	if err != nil {
		return fmt.Errorf("failed to find migration files: %w", err)
	}

	sort.Strings(files)

	for _, file := range files {
		version := filepath.Base(file)
		version = strings.TrimSuffix(version, ".up.sql")

		// Check if already applied
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = $1", version).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}

		if count > 0 {
			continue
		}

		// Read and execute migration
		content, err := os.ReadFile(file) // #nosec G304 -- file comes from the configured migration directory glob
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", file, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", version, err)
		}

		fmt.Printf("[migration] Applied: %s\n", version)
	}

	return nil
}

// HealthCheck verifies database connectivity
func (db *DB) HealthCheck(ctx context.Context) error {
	return db.PingContext(ctx)
}
