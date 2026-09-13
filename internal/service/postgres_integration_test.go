package service

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HeartBtz/fluxgate/internal/config"
	fluxcrypto "github.com/HeartBtz/fluxgate/internal/crypto"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// No environment/config files are loaded. Validate before opening any connection.
func guardedTestDSN(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid disposable PostgreSQL URL")
	}
	if u.User == nil {
		return nil, errors.New("test credentials required")
	}
	password, _ := u.User.Password()
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 || port == 5432 ||
		u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" ||
		u.User.Username() != "fluxgate_test" || password != "fluxgate-test-only" ||
		!regexp.MustCompile(`^/fluxgate_test_[a-z0-9_]+$`).MatchString(u.Path) ||
		u.RawPath != "" || u.Fragment != "" || u.RawQuery != "sslmode=disable" {
		return nil, errors.New("refusing non-disposable PostgreSQL target")
	}
	return u, nil
}

func TestPostgresGuardRejectsUnsafeTargets(t *testing.T) {
	base := "postgres://fluxgate_test:fluxgate-test-only@127.0.0.1:15432/fluxgate_test_guard?sslmode=disable"
	for _, raw := range []string{
		"", "host=production dbname=fluxgate", strings.Replace(base, "127.0.0.1", "192.0.2.1", 1),
		strings.Replace(base, ":15432", ":5432", 1), strings.Replace(base, "/fluxgate_test_guard", "/fluxgate", 1),
		base + "&host=production", strings.Replace(base, "fluxgate-test-only", "other", 1),
	} {
		if _, err := guardedTestDSN(raw); err == nil {
			t.Fatal("unsafe PostgreSQL target accepted")
		}
	}
	if _, err := guardedTestDSN(base); err != nil {
		t.Fatal(err)
	}
}

func disposablePostgres(t *testing.T) *repository.DB {
	t.Helper()
	if os.Getenv("FLUXGATE_TEST_POSTGRES") != "1" {
		t.Skip("PostgreSQL integration disabled: set FLUXGATE_TEST_POSTGRES=1 and an explicitly guarded POSTGRES_DSN")
	}
	u, err := guardedTestDSN(os.Getenv("POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("cannot open disposable PostgreSQL")
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var name, user, version string
	if err := admin.QueryRowContext(ctx, "SELECT current_database(), current_user, current_setting('server_version_num')").Scan(&name, &user, &version); err != nil {
		t.Fatal("cannot verify disposable PostgreSQL identity")
	}
	if name != strings.TrimPrefix(u.Path, "/") || user != "fluxgate_test" || !strings.HasPrefix(version, "16") {
		t.Fatal("disposable PostgreSQL identity/version mismatch")
	}
	t.Logf("PostgreSQL server_version_num=%s; loopback test target verified", version)
	schema := "fluxgate_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP SCHEMA "`+schema+`" CASCADE`); err != nil {
			t.Error(err)
		}
	})
	q := u.Query()
	q.Set("search_path", schema+",public")
	q.Set("statement_timeout", "10000")
	u.RawQuery = q.Encode()
	pool, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("cannot open isolated test schema")
	}
	pool.SetMaxOpenConns(20)
	t.Cleanup(func() { pool.Close() })
	db := &repository.DB{DB: pool}
	if err := db.RunMigrations(filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPostgresIntegration(t *testing.T) {
	db := disposablePostgres(t)
	users := repository.NewUserRepository(db)
	files := repository.NewFileRepository(db)
	uploads := repository.NewUploadSessionRepository(db)
	links := repository.NewLinkRepository(db)
	keys := repository.NewAPIKeyRepository(db)
	ctx := context.Background()
	newService := func(t *testing.T, ttl time.Duration, quota int64) (*FileService, *domain.User, *storage.LocalBackend) {
		t.Helper()
		store, err := storage.NewLocalBackend(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		user := &domain.User{ID: id, Username: "test_" + id.String()[:12], Email: id.String() + "@example.test", PasswordHash: "test-hash", Role: "user", IsActive: true, QuotaBytes: quota, MaxFileSize: quota}
		if err := users.Create(ctx, user); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Limits: config.LimitsConfig{MaxUploadSize: quota, MaxFileNameLength: 255}, Worker: config.WorkerConfig{SessionExpiry: ttl}}
		return NewFileService(files, users, uploads, store, cfg), user, store
	}

	t.Run("DirectProgressBeyondInitialTTL", func(t *testing.T) {
		ttl := 800 * time.Millisecond
		svc, user, store := newService(t, ttl, 1<<20)
		payload := strings.Repeat("p", 512*24)
		var initialExpiry time.Time
		reader := &observedUploadReader{reader: slowUploadReader{strings.NewReader(payload), 80 * time.Millisecond}, observe: func() error {
			if initialExpiry.IsZero() {
				if err := db.QueryRow("SELECT expires_at FROM upload_sessions WHERE user_id=$1", user.ID).Scan(&initialExpiry); err != nil {
					return err
				}
			}
			claimed, err := uploads.GetStale(ctx, time.Now().Add(-ttl), 100)
			if err != nil {
				return err
			}
			for _, session := range claimed {
				if session.UserID == user.ID {
					return errors.New("cleaner claimed progressing upload")
				}
			}
			return nil
		}}
		file, err := svc.Upload(ctx, user.ID, "slow.txt", int64(len(payload)), reader)
		if err != nil {
			t.Fatal(err)
		}
		if !time.Now().After(initialExpiry) {
			t.Fatal("test did not cross initial lease expiry")
		}
		r, err := store.Get(ctx, file.StoragePath)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		got, err := io.ReadAll(r)
		if err != nil || string(got) != payload {
			t.Fatal("finalized bytes not preserved")
		}
		if reserved, err := uploads.ReservedBytes(ctx, user.ID); err != nil || reserved != 0 {
			t.Fatalf("reservation: %d, %v", reserved, err)
		}
		current, err := users.GetByID(ctx, user.ID)
		if err != nil || current.UsedBytes != int64(len(payload)) {
			t.Fatalf("quota after finalize: %v, %v", current, err)
		}
		t.Logf("preserved %d bytes after crossing initial %s TTL", len(payload), ttl)
	})

	t.Run("AbandonedExpiresThenCleans", func(t *testing.T) {
		svc, user, store := newService(t, 150*time.Millisecond, 100)
		session, err := svc.InitResumableUpload(ctx, user.ID, domain.UploadInitRequest{Filename: "partial.txt", TotalSize: 7})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UploadChunk(ctx, session.ID, user.ID, 0, strings.NewReader("abc")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		if err := uploads.RenewLease(ctx, session.ID, time.Now().Add(time.Hour)); !errors.Is(err, domain.ErrUploadSessionExpired) {
			t.Fatalf("expired lease revived: %v", err)
		}
		claimed, err := uploads.GetStale(ctx, time.Now(), 100)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range claimed {
			if row.ID == session.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("abandoned session not claimed")
		}
		if err := svc.CleanupStaleUpload(ctx, session.ID); err != nil {
			t.Fatal(err)
		}
		if exists, err := store.Exists(ctx, session.StoragePath); err != nil || exists {
			t.Fatalf("partial bytes retained: %v, %v", exists, err)
		}
		if _, err := uploads.GetByID(ctx, session.ID); !errors.Is(err, domain.ErrUploadSessionNotFound) {
			t.Fatalf("session retained: %v", err)
		}
		if reserved, err := uploads.ReservedBytes(ctx, user.ID); err != nil || reserved != 0 {
			t.Fatalf("reservation retained: %d, %v", reserved, err)
		}
	})

	t.Run("DirectIdleExpiryCannotFinalize", func(t *testing.T) {
		svc, user, store := newService(t, 150*time.Millisecond, 2048)
		var path string
		reads := 0
		reader := &observedUploadReader{reader: strings.NewReader(strings.Repeat("x", 1024)), observe: func() error {
			reads++
			if reads == 1 {
				return db.QueryRow("SELECT storage_path FROM upload_sessions WHERE user_id=$1", user.ID).Scan(&path)
			}
			time.Sleep(250 * time.Millisecond)
			return nil
		}}
		_, err := svc.Upload(ctx, user.ID, "idle.txt", 1024, reader)
		if !errors.Is(err, domain.ErrUploadSessionExpired) {
			t.Fatalf("idle direct upload revived: %v", err)
		}
		if exists, err := store.Exists(ctx, path); err != nil || exists {
			t.Fatalf("idle direct bytes retained: %v, %v", exists, err)
		}
		if reserved, err := uploads.ReservedBytes(ctx, user.ID); err != nil || reserved != 0 {
			t.Fatalf("idle direct reservation retained: %d, %v", reserved, err)
		}
		if count, err := users.GetFileCount(ctx, user.ID); err != nil || count != 0 {
			t.Fatalf("idle upload finalized: %d, %v", count, err)
		}
	})

	t.Run("NoRevivalAfterLockWait", func(t *testing.T) {
		for _, operation := range []string{"renew", "progress", "finalize"} {
			svc, user, _ := newService(t, 500*time.Millisecond, 100)
			session, err := svc.InitResumableUpload(ctx, user.ID, domain.UploadInitRequest{Filename: "locked.txt", TotalSize: 7})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.Exec("SELECT id FROM upload_sessions WHERE id=$1 FOR UPDATE", session.ID); err != nil {
				t.Fatal(err)
			}
			waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				switch operation {
				case "finalize":
					result <- files.FinalizeUpload(waitCtx, &domain.File{ID: uuid.New(), UserID: user.ID, SizeBytes: 7}, session.ID)
				case "progress":
					result <- uploads.UpdateProgress(waitCtx, session.ID, 7, time.Now().Add(time.Hour))
				default:
					result <- uploads.RenewLease(waitCtx, session.ID, time.Now().Add(time.Hour))
				}
			}()
			waitForPostgresLock(t, db)
			time.Sleep(max(0, time.Until(session.ExpiresAt.Add(100*time.Millisecond))))
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			err = <-result
			if operation == "finalize" && !errors.Is(err, domain.ErrUploadSessionNotFound) || operation != "finalize" && !errors.Is(err, domain.ErrUploadSessionExpired) {
				t.Fatalf("operation survived expiry during lock wait (%s): %v", operation, err)
			}
			row, err := uploads.GetByID(ctx, session.ID)
			if err != nil || !row.ExpiresAt.Equal(session.ExpiresAt) {
				t.Fatal("expired lease was changed")
			}
		}
	})

	t.Run("ClaimedLeaseCannotRenew", func(t *testing.T) {
		svc, user, _ := newService(t, time.Hour, 100)
		session, err := svc.InitResumableUpload(ctx, user.ID, domain.UploadInitRequest{Filename: "claimed.txt", TotalSize: 7})
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"cleaning", "failed", "complete"} {
			if _, err := db.Exec("UPDATE upload_sessions SET status=$2 WHERE id=$1", session.ID, status); err != nil {
				t.Fatal(err)
			}
			if err := uploads.RenewLease(ctx, session.ID, time.Now().Add(time.Hour)); !errors.Is(err, domain.ErrUploadSessionExpired) {
				t.Fatalf("%s lease renewed: %v", status, err)
			}
		}
	})

	t.Run("ConcurrentReservationAndAtomicFinalize", func(t *testing.T) {
		_, user, _ := newService(t, time.Hour, 10)
		var wg sync.WaitGroup
		winners := make(chan *domain.UploadSession, 12)
		for range 12 {
			wg.Go(func() {
				session := &domain.UploadSession{ID: uuid.New(), UserID: user.ID, Filename: "quota.txt", TotalSize: 7, ChunkSize: 7, Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
				// Exercise database admission without the service's process-local lock.
				err := uploads.CreateWithQuota(ctx, session, -1, 0)
				if err == nil {
					winners <- session
				} else if !errors.Is(err, domain.ErrQuotaExceeded) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		close(winners)
		if len(winners) != 1 {
			t.Fatalf("reservation winners = %d, want 1", len(winners))
		}
		session := <-winners
		file := &domain.File{ID: uuid.New(), UserID: user.ID, OriginalName: strings.Repeat("x", 1025), SizeBytes: 7, UploadComplete: true, Metadata: domain.JSONMap{}}
		if err := files.FinalizeUpload(ctx, file, session.ID); err == nil {
			t.Fatal("invalid insert unexpectedly committed")
		}
		if reserved, err := uploads.ReservedBytes(ctx, user.ID); err != nil || reserved != 7 {
			t.Fatalf("rollback reservation: %d, %v", reserved, err)
		}
		current, err := users.GetByID(ctx, user.ID)
		if err != nil || current.UsedBytes != 0 {
			t.Fatal("quota changed despite rollback")
		}
		file.OriginalName = "quota.txt"
		if err := files.FinalizeUpload(ctx, file, session.ID); err != nil {
			t.Fatal(err)
		}
		if err := files.FinalizeUpload(ctx, file, session.ID); !errors.Is(err, domain.ErrUploadSessionNotFound) {
			t.Fatalf("double finalization: %v", err)
		}
		current, err = users.GetByID(ctx, user.ID)
		if err != nil || current.UsedBytes != 7 {
			t.Fatal("finalized quota incorrect")
		}
		if reserved, err := uploads.ReservedBytes(ctx, user.ID); err != nil || reserved != 0 {
			t.Fatalf("finalized reservation: %d, %v", reserved, err)
		}
	})

	t.Run("DownloadLimitsLegacyHashAndRevocation", func(t *testing.T) {
		svc, user, _ := newService(t, time.Hour, 100)
		file, err := svc.Upload(ctx, user.ID, "download.txt", 7, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Server: config.ServerConfig{BaseURL: "https://example.test"}, Signing: config.SigningConfig{MaxExpiry: time.Hour}}
		linkService := NewLinkService(links, files, fluxcrypto.NewURLSigner(strings.Repeat("h", 32), "test"), cfg)
		limit := 3
		link, err := linkService.CreateLink(ctx, user.ID, domain.CreateLinkRequest{FileID: file.ID.String(), MaxDownloads: &limit})
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(link.ID)
		var successes atomic.Int32
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				if err := linkService.ReserveDownload(ctx, id); err == nil {
					successes.Add(1)
				} else if !errors.Is(err, domain.ErrLinkExhausted) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 3 {
			t.Fatalf("download admissions = %d", successes.Load())
		}
		if err := linkService.ReleaseDownload(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := linkService.ReserveDownload(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := linkService.RevokeLink(ctx, id, user.ID); err != nil {
			t.Fatal(err)
		}
		if err := linkService.ReserveDownload(ctx, id); err == nil {
			t.Fatal("revoked link admitted")
		}
		legacy, err := linkService.CreateLink(ctx, user.ID, domain.CreateLinkRequest{FileID: file.ID.String()})
		if err != nil {
			t.Fatal(err)
		}
		var digest string
		if err := db.QueryRow("SELECT token FROM download_links WHERE id=$1", legacy.ID).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		if _, err := links.GetByToken(ctx, digest); !errors.Is(err, domain.ErrLinkNotFound) {
			t.Fatal("stored digest accepted as bearer")
		}
		if _, _, err := linkService.ValidateDownload(ctx, legacy.Token, "127.0.0.1", "", legacy.DirectURL); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("UPDATE download_links SET token=$2 WHERE id=$1", legacy.ID, legacy.Token); err != nil {
			t.Fatal(err)
		}
		if _, _, err := linkService.ValidateDownload(ctx, legacy.Token, "127.0.0.1", "", legacy.DirectURL); err != nil {
			t.Fatalf("legacy token: %v", err)
		}
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "003_hash_link_tokens.up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(migration)); err != nil {
			t.Fatal(err)
		}
		var migrated string
		if err := db.QueryRow("SELECT token FROM download_links WHERE id=$1", legacy.ID).Scan(&migrated); err != nil {
			t.Fatal(err)
		}
		if migrated != digest {
			t.Fatal("legacy migration did not preserve the expected token digest")
		}
		if _, _, err := linkService.ValidateDownload(ctx, legacy.Token, "127.0.0.1", "", legacy.DirectURL); err != nil {
			t.Fatalf("migrated legacy token: %v", err)
		}
		if err := linkService.RevokeLink(ctx, uuid.MustParse(legacy.ID), user.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := linkService.ValidateDownload(ctx, legacy.Token, "127.0.0.1", "", legacy.DirectURL); err == nil {
			t.Fatal("legacy revoked link accepted")
		}
	})

	t.Run("AccountPasswordAndAPIKeyRevocation", func(t *testing.T) {
		cfg := &config.Config{Auth: config.AuthConfig{JWTSecret: strings.Repeat("j", 32), JWTExpiry: time.Hour, BcryptCost: bcrypt.MinCost}, Limits: config.LimitsConfig{DefaultQuota: 100, MaxUploadSize: 100}}
		auth := &AuthService{userRepo: users, apiKeyRepo: keys, cfg: cfg}
		username := "auth_" + uuid.NewString()[:12]
		user, err := auth.Register(ctx, domain.CreateUserRequest{Username: username, Email: username + "@example.test", Password: "test-password"})
		if err != nil {
			t.Fatal(err)
		}
		login, err := auth.Login(ctx, domain.AuthLoginRequest{Username: username, Password: "test-password"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.ValidateJWTUser(ctx, login.Token); err != nil {
			t.Fatal(err)
		}
		keyService := NewAPIKeyService(keys)
		key, err := keyService.Create(ctx, user.ID, domain.CreateAPIKeyRequest{Name: "test-key", Scopes: []string{"download"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.ValidateAPIKey(ctx, key.Key); err != nil {
			t.Fatal(err)
		}
		user.IsActive = false
		if err := users.Update(ctx, user); err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.ValidateJWTUser(ctx, login.Token); !errors.Is(err, domain.ErrUserInactive) {
			t.Fatal("inactive JWT accepted")
		}
		if _, _, err := auth.ValidateAPIKey(ctx, key.Key); !errors.Is(err, domain.ErrUserInactive) {
			t.Fatal("inactive API key accepted")
		}
		user.IsActive = true
		if err := users.Update(ctx, user); err != nil {
			t.Fatal(err)
		}
		if err := auth.UpdatePasswordAsAdmin(ctx, user.ID, "new-test-password"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.ValidateJWTUser(ctx, login.Token); !errors.Is(err, domain.ErrInvalidToken) {
			t.Fatal("old-password JWT accepted")
		}
		if _, _, err := auth.ValidateAPIKey(ctx, key.Key); err != nil {
			t.Fatal("password reset unexpectedly revoked API key")
		}
		if err := keyService.Revoke(ctx, uuid.MustParse(key.ID), user.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.ValidateAPIKey(ctx, key.Key); !errors.Is(err, domain.ErrInvalidAPIKey) {
			t.Fatal("revoked API key accepted")
		}
	})
}

type observedUploadReader struct {
	reader  io.Reader
	observe func() error
}

func (r *observedUploadReader) Read(p []byte) (int, error) {
	if err := r.observe(); err != nil {
		return 0, err
	}
	return r.reader.Read(p[:min(len(p), 512)])
}

func waitForPostgresLock(t *testing.T, db *repository.DB) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM upload_sessions%'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("test operation did not wait on session row lock")
}
