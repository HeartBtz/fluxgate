// Package handler contient les handlers HTTP de FluxGate :
//   - DownloadHandler : téléchargement direct (cœur de l'application)
//   - FileHandler     : upload et gestion des fichiers
//   - AuthHandler     : authentification (login, register)
//   - LinkHandler     : gestion des liens de téléchargement
//   - APIKeyHandler   : gestion des clés API
//   - WebHandler      : interface web (dashboard, login page)
//
// Tous les handlers utilisent le routeur chi v5 et renvoient du JSON
// sauf le DownloadHandler qui renvoie un flux binaire direct.
package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/HeartBtz/fluxgate/internal/domain"
	fluxmetrics "github.com/HeartBtz/fluxgate/internal/metrics"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/HeartBtz/fluxgate/internal/storage"
	"github.com/google/uuid"
)

// DownloadHandler gère les endpoints de téléchargement de fichiers.
// C'est le CŒUR de FluxGate — streaming binaire direct, compatible wget/curl.
// Supporte les Range Requests, la reprise de téléchargement et les liens
// protégés par mot de passe.
type DownloadHandler struct {
	linkService    *service.LinkService
	storage        storage.Backend
	dlLogRepo      *repository.DownloadLogRepository
	logger         *slog.Logger
	trustedProxies []string
	auditQueue     chan downloadAudit
}

type downloadAudit struct {
	log      *domain.DownloadLog
	complete bool
	fileID   uuid.UUID
}

// NewDownloadHandler crée un nouveau handler de téléchargement.
func NewDownloadHandler(
	linkService *service.LinkService,
	store storage.Backend,
	dlLogRepo *repository.DownloadLogRepository,
	logger *slog.Logger,
	trustedProxies []string,
) *DownloadHandler {
	h := &DownloadHandler{
		linkService:    linkService,
		storage:        store,
		dlLogRepo:      dlLogRepo,
		logger:         logger,
		trustedProxies: append([]string(nil), trustedProxies...),
		auditQueue:     make(chan downloadAudit, 2048),
	}
	go h.runAuditWorker()
	return h
}

// Download handles GET /d/{token}/{filename}
// This is the DIRECT download endpoint — no HTML, no JS, no redirects
// Binary stream starts immediately
func (h *DownloadHandler) Download(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Extract password from Basic Auth only (not query params to avoid URL leakage)
	_, password, _ := r.BasicAuth()

	clientIP := middleware.RealIP(r, h.trustedProxies)

	// Validate the download link
	link, file, err := h.linkService.ValidateDownload(r.Context(), token, clientIP, password, r.URL.String())
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrLinkNotFound), errors.Is(err, domain.ErrFileNotFound):
			status = http.StatusNotFound
		case errors.Is(err, domain.ErrFileDeleted), errors.Is(err, domain.ErrUploadIncomplete):
			status = http.StatusGone
		case errors.Is(err, domain.ErrLinkExpired), errors.Is(err, domain.ErrFileExpired):
			status = http.StatusGone
		case errors.Is(err, domain.ErrLinkExhausted):
			status = http.StatusGone
		case errors.Is(err, domain.ErrLinkRevoked), errors.Is(err, domain.ErrLinkInactive):
			status = http.StatusForbidden
		case errors.Is(err, domain.ErrIPNotAllowed):
			status = http.StatusForbidden
		case errors.Is(err, domain.ErrPasswordRequired):
			w.Header().Set("WWW-Authenticate", `Basic realm="FluxGate Download"`)
			status = http.StatusUnauthorized
		case errors.Is(err, domain.ErrPasswordInvalid):
			w.Header().Set("WWW-Authenticate", `Basic realm="FluxGate Download"`)
			status = http.StatusUnauthorized
			h.logger.Warn("download password rejected",
				slog.String("client_ip", clientIP),
				slog.String("request_id", w.Header().Get("X-Request-ID")),
			)
		case errors.Is(err, domain.ErrInvalidSignature):
			status = http.StatusNotFound
		}
		http.Error(w, safeErrorMessage(err), status)
		fluxmetrics.DownloadErrors.Inc()
		return
	}
	// Determine filename
	filename := file.OriginalName
	if link.ForcedFilename != nil && *link.ForcedFilename != "" {
		filename = *link.ForcedFilename
	}

	// Parse Range header for resume support
	var rangeStart, rangeEnd int64
	rangeEnd = file.SizeBytes - 1
	isRangeRequest := false

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" && (r.Header.Get("If-Range") == "" || r.Header.Get("If-Range") == fmt.Sprintf(`"%s"`, file.SHA256)) {
		start, end, err := parseRange(rangeHeader, file.SizeBytes)
		if err != nil {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", file.SizeBytes))
			http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		rangeStart = start
		rangeEnd = end
		isRangeRequest = true
	}

	// Get reader from storage
	var reader io.ReadCloser
	contentLength := file.SizeBytes

	if isRangeRequest {
		length := rangeEnd - rangeStart + 1
		reader, err = h.storage.GetRange(r.Context(), file.StoragePath, rangeStart, length)
		contentLength = length
	} else {
		reader, err = h.storage.Get(r.Context(), file.StoragePath)
	}

	if err != nil {
		h.logger.Error("storage read failed",
			slog.String("file_id", file.ID.String()),
			slog.String("path", file.StoragePath),
			slog.Any("error", err),
		)
		http.Error(w, "file unavailable", http.StatusInternalServerError)
		fluxmetrics.DownloadErrors.Inc()
		return
	}
	defer reader.Close()
	if err := h.linkService.ReserveDownload(r.Context(), link.ID); err != nil {
		status := http.StatusInternalServerError
		message := "download unavailable"
		if errors.Is(err, domain.ErrLinkExhausted) {
			status = http.StatusGone
			message = domain.ErrLinkExhausted.Error()
		}
		http.Error(w, message, status)
		fluxmetrics.DownloadErrors.Inc()
		return
	}
	consumed := false
	defer func() {
		if !consumed {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.linkService.ReleaseDownload(ctx, link.ID); err != nil {
				h.logger.Warn("download reservation release failed", slog.String("link_id", link.ID.String()))
			}
		}
	}()

	// Set response headers BEFORE writing body
	w.Header().Set("Content-Type", file.MIMEType)
	w.Header().Set("Content-Disposition", contentDisposition(filename))
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, file.SHA256))
	w.Header().Set("X-Content-SHA256", file.SHA256)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if isRangeRequest {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rangeStart, rangeEnd, file.SizeBytes))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Track download
	fluxmetrics.ActiveDownloads.Inc()
	defer fluxmetrics.ActiveDownloads.Dec()

	// Create download log entry (non-blocking — don't delay the stream)
	dlLog := &domain.DownloadLog{
		ID:        uuid.New(),
		FileID:    file.ID,
		LinkID:    &link.ID,
		IPAddress: clientIP,
		UserAgent: boundedAuditText(r.UserAgent()),
		IsResumed: isRangeRequest,
		StartedAt: time.Now(),
	}
	// Stream the file — this is where the magic happens
	// io.Copy uses sendfile(2) when possible for zero-copy
	consumed = true // A panic after partial delivery must also fail closed.
	bytesSent, err := io.Copy(w, reader)

	// Record download completion (non-blocking)
	isComplete := err == nil && bytesSent == contentLength
	// Delivered bytes consume a slot even on interruption; otherwise repeated
	// aborted ranges can reconstruct the file without ever spending a download.
	consumed = isComplete || bytesSent > 0
	completedAt := time.Now()
	dlLog.BytesSent = bytesSent
	dlLog.IsComplete = isComplete
	dlLog.CompletedAt = &completedAt
	h.queueAudit(downloadAudit{log: dlLog, complete: isComplete, fileID: file.ID})

	if isComplete {
		fluxmetrics.DownloadsTotal.Inc()
	}

	fluxmetrics.DownloadBytesTotal.Add(float64(bytesSent))

	if err != nil {
		h.logger.Warn("download interrupted",
			slog.String("file_id", file.ID.String()),
			slog.Int64("bytes_sent", bytesSent),
			slog.Any("error", err),
		)
	}
}

func (h *DownloadHandler) queueAudit(a downloadAudit) {
	select {
	case h.auditQueue <- a:
	default:
		h.logger.Warn("download audit queue full", slog.String("file_id", a.fileID.String()))
	}
}

func (h *DownloadHandler) runAuditWorker() {
	for a := range h.auditQueue {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = h.dlLogRepo.Create(ctx, a.log)
		if a.complete {
			h.linkService.RecordFileDownload(ctx, a.fileID)
		}
		cancel()
	}
}

// parseRange parses an HTTP Range header
func parseRange(rangeHeader string, fileSize int64) (start, end int64, err error) {
	if fileSize <= 0 {
		return 0, 0, fmt.Errorf("empty file has no ranges")
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, fmt.Errorf("invalid range header")
	}

	rangeSpec := strings.TrimSpace(strings.TrimPrefix(rangeHeader, "bytes="))
	if strings.Contains(rangeSpec, ",") {
		return 0, 0, fmt.Errorf("multiple ranges are not supported")
	}
	startText, endText, ok := strings.Cut(rangeSpec, "-")
	if !ok || (startText == "" && endText == "") {
		return 0, 0, fmt.Errorf("invalid range format")
	}

	if startText == "" {
		// Suffix range: -500 means last 500 bytes
		suffix, err := strconv.ParseInt(endText, 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, fmt.Errorf("invalid suffix range")
		}
		if suffix > fileSize {
			suffix = fileSize
		}
		start = fileSize - suffix
		end = fileSize - 1
	} else {
		start, err = strconv.ParseInt(startText, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid start range")
		}

		if endText != "" {
			end, err = strconv.ParseInt(endText, 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid end range")
			}
		} else {
			end = fileSize - 1
		}
	}

	if end >= fileSize {
		end = fileSize - 1
	}
	if start < 0 || start >= fileSize || start > end {
		return 0, 0, fmt.Errorf("range out of bounds")
	}

	return start, end, nil
}

// DownloadWithPassword handles POST /d/{token}/{filename} for password-protected downloads
func (h *DownloadHandler) DownloadWithPassword(w http.ResponseWriter, r *http.Request) {
	// For form-based password submission, set Basic Auth and delegate to Download
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid password form", http.StatusBadRequest)
		return
	}
	password := r.PostForm.Get("password")

	if password != "" {
		// Set the password as Basic Auth so Download() can extract it
		r.SetBasicAuth("", password)
	}

	h.Download(w, r)
}

// DownloadInfo handles HEAD /d/{token}/{filename}
// Returns file metadata without starting download
func (h *DownloadHandler) DownloadInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	token := chi.URLParam(r, "token")
	clientIP := middleware.RealIP(r, h.trustedProxies)
	_, password, _ := r.BasicAuth()

	link, file, err := h.linkService.ValidateDownload(r.Context(), token, clientIP, password, r.URL.String())
	if err != nil {
		if errors.Is(err, domain.ErrPasswordRequired) {
			w.Header().Set("X-Password-Required", "true")
		}
		http.Error(w, "", http.StatusNotFound)
		return
	}

	filename := file.OriginalName
	if link.ForcedFilename != nil {
		filename = *link.ForcedFilename
	}

	w.Header().Set("Content-Type", file.MIMEType)
	w.Header().Set("Content-Disposition", contentDisposition(filename))
	w.Header().Set("Content-Length", strconv.FormatInt(file.SizeBytes, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, file.SHA256))
	w.Header().Set("X-Content-SHA256", file.SHA256)
	w.WriteHeader(http.StatusOK)
}

func boundedAuditText(value string) string {
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func contentDisposition(filename string) string {
	value := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	if value == "" {
		return "attachment"
	}
	return value
}
