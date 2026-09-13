package handler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/HeartBtz/fluxgate/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		size       int64
		start, end int64
		wantErr    bool
	}{
		{name: "explicit", header: "bytes=10-19", size: 100, start: 10, end: 19},
		{name: "clamp end", header: "bytes=90-999", size: 100, start: 90, end: 99},
		{name: "open ended", header: "bytes=90-", size: 100, start: 90, end: 99},
		{name: "suffix", header: "bytes=-10", size: 100, start: 90, end: 99},
		{name: "oversized suffix", header: "bytes=-1000", size: 100, start: 0, end: 99},
		{name: "multiple ranges rejected", header: "bytes=0-1,5-6", size: 100, wantErr: true},
		{name: "empty suffix rejected", header: "bytes=-0", size: 100, wantErr: true},
		{name: "empty file", header: "bytes=0-", size: 0, wantErr: true},
		{name: "out of bounds", header: "bytes=100-100", size: 100, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parseRange(tt.header, tt.size)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseRange() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (start != tt.start || end != tt.end) {
				t.Fatalf("parseRange() = %d-%d, want %d-%d", start, end, tt.start, tt.end)
			}
		})
	}
}

func downloadFixture(t *testing.T, password bool) (*DownloadHandler, sqlmock.Sqlmock, uuid.UUID) {
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
	id, fileID, user := uuid.New(), uuid.New(), uuid.New()
	var hash any
	if password {
		b, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		hash = string(b)
	}
	mock.ExpectQuery("FROM download_links WHERE token").WillReturnRows(sqlmock.NewRows([]string{"id", "file", "user", "token", "type", "active", "password", "max", "current", "ips", "name", "expires", "created", "revoked"}).AddRow(id, fileID, user, "digest", "public", true, hash, 1, 0, nil, nil, nil, time.Now(), nil))
	if !password {
		mock.ExpectQuery("FROM files WHERE id").WithArgs(fileID).WillReturnRows(sqlmock.NewRows([]string{"id", "user", "name", "stored", "path", "backend", "mime", "size", "hash", "encrypted", "key", "complete", "downloads", "deleted", "deleted_at", "expires", "metadata", "created", "updated"}).AddRow(fileID, user, "file.txt", "file", "file", "local", "text/plain", 7, "sha256-test", false, nil, true, 0, false, nil, nil, []byte(`{}`), time.Now(), time.Now()))
	}
	store, err := storage.NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), "file", strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	return &DownloadHandler{
		linkService: service.NewLinkService(repository.NewLinkRepository(repoDB), repository.NewFileRepository(repoDB), nil, nil),
		storage:     store, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditQueue: make(chan downloadAudit, 10),
	}, mock, id
}

func downloadRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("token", "test-token")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestDownloadRangeAndIfRange(t *testing.T) {
	for _, tc := range []struct {
		ifRange, content string
		status           int
	}{
		{"", "load", 206}, {`"sha256-test"`, "load", 206}, {`"old-hash"`, "payload", 200},
	} {
		h, mock, id := downloadFixture(t, false)
		mock.ExpectExec("UPDATE download_links SET current_downloads").WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 1))
		r := downloadRequest("GET", "/d/test-token/file.txt")
		r.Header.Set("Range", "bytes=3-999")
		r.Header.Set("If-Range", tc.ifRange)
		w := httptest.NewRecorder()
		h.Download(w, r)
		if w.Code != tc.status || w.Body.String() != tc.content {
			t.Fatalf("status %d body %q", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("download cacheable")
		}
	}
}

type interruptedWriter struct {
	*httptest.ResponseRecorder
	bytes int
}

func (w interruptedWriter) Write(p []byte) (int, error) {
	return min(w.bytes, len(p)), errors.New("test disconnect")
}

func TestDownloadInterruptionAccounting(t *testing.T) {
	for _, bytes := range []int{0, 3} {
		h, mock, id := downloadFixture(t, false)
		mock.ExpectExec("UPDATE download_links SET current_downloads").WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 1))
		if bytes == 0 {
			mock.ExpectExec("UPDATE download_links SET current_downloads = GREATEST").WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 1))
		}
		h.Download(interruptedWriter{httptest.NewRecorder(), bytes}, downloadRequest("GET", "/d/test-token/file.txt"))
	}
}

func TestPasswordQueryIsNotAccepted(t *testing.T) {
	h, _, _ := downloadFixture(t, true)
	r := downloadRequest("POST", "/d/test-token/file.txt?password=test-password")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.DownloadWithPassword(w, r)
	if w.Code != 401 {
		t.Fatalf("password from URL accepted: %d", w.Code)
	}
}

func TestDownloadHeadDoesNotReserve(t *testing.T) {
	h, _, _ := downloadFixture(t, false)
	w := httptest.NewRecorder()
	h.DownloadInfo(w, downloadRequest("HEAD", "/d/test-token/file.txt"))
	if w.Code != 200 || w.Header().Get("Content-Length") != "7" || w.Body.Len() != 0 {
		t.Fatalf("HEAD status %d", w.Code)
	}
}

func TestContentDispositionSafelyEncodesFilename(t *testing.T) {
	value := contentDisposition("résumé.txt")
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "attachment" || params["filename"] != "résumé.txt" {
		t.Fatalf("contentDisposition() = %q, parsed as %q %#v, %v", value, mediaType, params, err)
	}
	if strings.ContainsAny(value, "\r\n") {
		t.Fatalf("contentDisposition contains a header delimiter: %q", value)
	}
}
