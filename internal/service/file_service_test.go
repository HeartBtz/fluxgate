package service

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/HeartBtz/fluxgate/internal/config"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/storage"
	"github.com/google/uuid"
)

func testFileService(t *testing.T, store storage.Backend) (*FileService, sqlmock.Sqlmock, uuid.UUID) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	repoDB := &repository.DB{DB: db}
	cfg := &config.Config{Limits: config.LimitsConfig{MaxUploadSize: 100, MaxFileNameLength: 255}, Worker: config.WorkerConfig{SessionExpiry: time.Hour}}
	return NewFileService(repository.NewFileRepository(repoDB), repository.NewUserRepository(repoDB), repository.NewUploadSessionRepository(repoDB), store, cfg), mock, uuid.New()
}

func expectUploadOwner(mock sqlmock.Sqlmock, id uuid.UUID) {
	mock.ExpectQuery("FROM users WHERE id").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password_hash", "role", "active", "quota", "used", "max", "created", "updated"}).AddRow(id, "test", "test@example.test", "hash", "user", true, 10, 0, 100, time.Now(), time.Now()))
	mock.ExpectQuery("SELECT COALESCE\\(SUM\\(total_size\\)").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"reserved"}).AddRow(0))
}

func expectReservation(mock sqlmock.Sqlmock, id uuid.UUID, reserved int64) {
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT quota_bytes, used_bytes").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"quota", "used"}).AddRow(10, 0))
	mock.ExpectQuery("SELECT.*COALESCE").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"reserved", "outstanding"}).AddRow(reserved, reserved))
}

func uploadSessionRows(id, user uuid.UUID, path, status string, uploaded int64) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "user", "filename", "total", "uploaded", "chunk", "mime", "path", "status", "created", "updated", "expires"}).AddRow(id, user, "file.txt", 7, uploaded, 7, "text/plain", path, status, time.Now(), time.Now(), time.Now().Add(time.Hour))
}

type unreadableBody struct{ t *testing.T }

func (r unreadableBody) Read([]byte) (int, error) {
	r.t.Error("body read before admission")
	return 0, io.EOF
}

func TestDirectUploadReservesBeforeReading(t *testing.T) {
	svc, mock, user := testFileService(t, nil)
	expectUploadOwner(mock, user)
	expectReservation(mock, user, 9)
	mock.ExpectRollback()
	_, err := svc.Upload(context.Background(), user, "file.txt", 7, unreadableBody{t})
	if !errors.Is(err, domain.ErrQuotaExceeded) {
		t.Fatalf("Upload: %v", err)
	}
}

type canceledStore struct {
	storage.Backend
	cancel  context.CancelFunc
	deleted bool
}

func (s *canceledStore) Type() string { return "test" }
func (s *canceledStore) Put(context.Context, string, io.Reader, int64) (int64, error) {
	s.cancel()
	return 0, context.Canceled
}
func (s *canceledStore) Delete(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.deleted = true
	return nil
}

func TestDirectUploadCancellationReleasesDurableReservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &canceledStore{cancel: cancel}
	svc, mock, user := testFileService(t, store)
	expectUploadOwner(mock, user)
	expectReservation(mock, user, 0)
	mock.ExpectQuery("INSERT INTO upload_sessions").WillReturnRows(sqlmock.NewRows([]string{"created", "updated", "expires"}).AddRow(time.Now(), time.Now(), time.Now().Add(time.Hour)))
	mock.ExpectCommit()
	mock.ExpectQuery("FROM upload_sessions WHERE id").WillReturnRows(uploadSessionRows(uuid.New(), user, "file", "pending", 0))
	mock.ExpectExec("DELETE FROM upload_sessions").WillReturnResult(sqlmock.NewResult(0, 1))
	_, err := svc.Upload(ctx, user, "file.txt", 7, strings.NewReader("payload"))
	if !errors.Is(err, context.Canceled) || !store.deleted {
		t.Fatalf("Upload: %v, cleanup %v", err, store.deleted)
	}
}

func TestFinalizeFailureKeepsResumableBytes(t *testing.T) {
	store, err := storage.NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), "file", strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	svc, mock, user := testFileService(t, store)
	id := uuid.New()
	mock.ExpectQuery("FROM upload_sessions WHERE id").WithArgs(id).WillReturnRows(uploadSessionRows(id, user, "file", "uploading", 7))
	mock.ExpectBegin().WillReturnError(errors.New("test DB unavailable"))
	if _, err := svc.CompleteResumableUpload(context.Background(), id, user); err == nil {
		t.Fatal("expected finalization error")
	}
	if size, err := store.Size(context.Background(), "file"); err != nil || size != 7 {
		t.Fatalf("bytes lost after failed finalize: %d, %v", size, err)
	}
}

func TestCleaningSessionCannotWriteOrFinalize(t *testing.T) {
	for _, complete := range []bool{false, true} {
		svc, mock, user := testFileService(t, nil)
		id := uuid.New()
		mock.ExpectQuery("FROM upload_sessions WHERE id").WithArgs(id).WillReturnRows(uploadSessionRows(id, user, "file", "cleaning", 7))
		var err error
		if complete {
			_, err = svc.CompleteResumableUpload(context.Background(), id, user)
		} else {
			_, err = svc.UploadChunk(context.Background(), id, user, 7, unreadableBody{t})
		}
		if !errors.Is(err, domain.ErrUploadSessionExpired) {
			t.Fatalf("cleaning session: %v", err)
		}
	}
}

func TestChunkDatabaseFailureRollsBackBytes(t *testing.T) {
	store, err := storage.NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), "file", strings.NewReader("abc"), 3); err != nil {
		t.Fatal(err)
	}
	svc, mock, user := testFileService(t, store)
	id := uuid.New()
	mock.ExpectQuery("FROM upload_sessions WHERE id").WithArgs(id).WillReturnRows(uploadSessionRows(id, user, "file", "uploading", 3))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM upload_sessions.*FOR UPDATE").WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	mock.ExpectExec("UPDATE upload_sessions SET uploaded_bytes").WillReturnError(errors.New("test progress failure"))
	mock.ExpectRollback()
	if _, err := svc.UploadChunk(context.Background(), id, user, 3, strings.NewReader("defg")); err == nil {
		t.Fatal("expected progress failure")
	}
	if size, err := store.Size(context.Background(), "file"); err != nil || size != 3 {
		t.Fatalf("offset not rolled back: %d, %v", size, err)
	}
}

type slowUploadReader struct {
	reader io.Reader
	delay  time.Duration
}

func (r slowUploadReader) Read(p []byte) (int, error) {
	time.Sleep(r.delay)
	return r.reader.Read(p[:min(len(p), 512)])
}

func TestUploadLeaseReaderProgressOutlivesInitialExpiry(t *testing.T) {
	ttl := 500 * time.Millisecond
	initialExpiry := time.Now().Add(ttl)
	expires := initialExpiry
	renewals := 0
	r := &uploadLeaseReader{
		reader:   slowUploadReader{strings.NewReader(strings.Repeat("x", 512*20)), 50 * time.Millisecond},
		interval: ttl / 3, nextRenewal: time.Now().Add(ttl / 3),
		renew: func(progressAt time.Time) error {
			if !progressAt.Before(expires) {
				return domain.ErrUploadSessionExpired
			}
			expires = progressAt.Add(ttl)
			renewals++
			return nil
		},
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil || n != 512*20 || renewals == 0 || !time.Now().After(initialExpiry) || !expires.After(time.Now()) {
		t.Fatalf("progress lease: bytes=%d renewals=%d error=%v", n, renewals, err)
	}
}

func TestUploadLeaseReaderDoesNotRenewIdleAndDoesNotRetryFailure(t *testing.T) {
	for _, reader := range []io.Reader{strings.NewReader(""), zeroProgressReader{}} {
		r := &uploadLeaseReader{reader: reader, renew: func(time.Time) error { t.Error("idle read renewed lease"); return nil }}
		_, _ = r.Read(make([]byte, 8))
	}
	renewals := 0
	r := &uploadLeaseReader{reader: strings.NewReader("payload"), renew: func(time.Time) error {
		renewals++
		return domain.ErrUploadSessionExpired
	}}
	for range 2 {
		n, err := r.Read(make([]byte, 1))
		if n != 0 || !errors.Is(err, domain.ErrUploadSessionExpired) {
			t.Fatalf("expired read: %d, %v", n, err)
		}
	}
	if renewals != 1 {
		t.Fatalf("failed lease was retried %d times", renewals)
	}
}

type zeroProgressReader struct{}

func (zeroProgressReader) Read([]byte) (int, error) { return 0, nil }
