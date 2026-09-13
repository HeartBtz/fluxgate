package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/HeartBtz/fluxgate/internal/domain"
	fluxmetrics "github.com/HeartBtz/fluxgate/internal/metrics"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/google/uuid"
)

// FileHandler gère les endpoints d'upload et de gestion des fichiers :
// upload simple, upload multipart, upload par morceaux (chunked/resumable),
// listage, détails, quota et suppression.
type FileHandler struct {
	fileService *service.FileService
	linkService *service.LinkService
	maxUpload   int64
}

const multipartOverheadAllowance int64 = 1 << 20

func NewFileHandler(fileService *service.FileService, linkService *service.LinkService, maxUpload int64) *FileHandler {
	return &FileHandler{
		fileService: fileService,
		linkService: linkService,
		maxUpload:   maxUpload,
	}
}

// Upload handles POST /api/v1/files/upload
// Supports multipart/form-data and raw body upload
func (h *FileHandler) Upload(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	// Bound the complete request while leaving room for multipart headers and
	// boundaries. FileService independently enforces the actual file size.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxUpload+multipartOverheadAllowance)

	var filename string
	var size int64
	var reader = io.Reader(r.Body)

	// Check if multipart
	contentType := r.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)
	if mediaType == "multipart/form-data" {
		part, err := streamMultipartFile(mediaType, params, r.Body)
		if errors.Is(err, errMultipartFileMissing) {
			writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "file field required"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "failed to parse multipart form"})
			return
		}
		filename = part.FileName()
		reader = part
	} else {
		// Raw body upload
		filename = r.Header.Get("X-Filename")
		if filename == "" {
			filename = r.URL.Query().Get("filename")
		}
		if filename == "" {
			filename = "upload"
		}

		size = r.ContentLength
	}
	if size > h.maxUpload {
		writeJSON(w, http.StatusRequestEntityTooLarge, domain.ErrorResponse{Error: domain.ErrFileTooLarge.Error()})
		return
	}
	reader = io.LimitReader(reader, h.maxUpload+1)

	uploadedFile, err := h.fileService.Upload(r.Context(), userID, filename, size, reader)
	if err != nil {
		fluxmetrics.UploadErrors.Inc()
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrQuotaExceeded):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, domain.ErrFileTooLarge):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, domain.ErrBlockedExtension), errors.Is(err, domain.ErrInvalidMIMEType):
			status = http.StatusUnsupportedMediaType
		case errors.Is(err, domain.ErrInsufficientStorage):
			status = http.StatusInsufficientStorage
		case errors.Is(err, domain.ErrUploadSessionExpired):
			status = http.StatusGone
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	fluxmetrics.UploadsTotal.Inc()
	fluxmetrics.UploadBytesTotal.Add(float64(uploadedFile.SizeBytes))

	writeJSON(w, http.StatusCreated, fileInfo(uploadedFile, 0))
}

var errMultipartFileMissing = errors.New("multipart file field missing")

func streamMultipartFile(mediaType string, params map[string]string, body io.Reader) (*multipart.Part, error) {
	if mediaType != "multipart/form-data" || params["boundary"] == "" {
		return nil, fmt.Errorf("invalid multipart content type")
	}
	preamble := &io.LimitedReader{R: body, N: multipartOverheadAllowance}
	mr := multipart.NewReader(preamble, params["boundary"])
	for parts := 0; parts < 32; parts++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, errMultipartFileMissing
		}
		if err != nil {
			return nil, err
		}
		if part.FormName() == "file" && part.FileName() != "" {
			preamble.N = math.MaxInt64
			return part, nil
		}
		_ = part.Close()
	}
	return nil, fmt.Errorf("too many multipart fields")
}

// InitResumableUpload handles POST /api/v1/files/upload/init
func (h *FileHandler) InitResumableUpload(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	var req domain.UploadInitRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max for JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid request"})
		return
	}

	session, err := h.fileService.InitResumableUpload(r.Context(), userID, req)
	if err != nil {
		writeJSON(w, uploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	writeJSON(w, http.StatusCreated, domain.UploadInitResponse{
		SessionID: session.ID.String(),
		ChunkSize: session.ChunkSize,
		UploadURL: fmt.Sprintf("/api/v1/files/upload/%s", session.ID.String()),
	})
}

// UploadChunk handles PATCH /api/v1/files/upload/{sessionID}
func (h *FileHandler) UploadChunk(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}

	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid upload offset"})
		return
	}

	uploaded, err := h.fileService.UploadChunk(r.Context(), sessionID, userID, offset, r.Body)
	if err != nil {
		writeJSON(w, uploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	w.Header().Set("Upload-Offset", strconv.FormatInt(uploaded, 10))
	w.WriteHeader(http.StatusNoContent)
}

// CompleteUpload handles POST /api/v1/files/upload/{sessionID}/complete
func (h *FileHandler) CompleteUpload(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}

	file, err := h.fileService.CompleteResumableUpload(r.Context(), sessionID, userID)
	if err != nil {
		writeJSON(w, uploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	fluxmetrics.UploadsTotal.Inc()
	fluxmetrics.UploadBytesTotal.Add(float64(file.SizeBytes))

	writeJSON(w, http.StatusOK, fileInfo(file, 0))
}

// UploadStatus handles HEAD /api/v1/files/upload/{sessionID}
func (h *FileHandler) UploadStatus(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}

	session, err := h.fileService.GetUploadStatus(r.Context(), sessionID, userID)
	if err != nil {
		writeJSON(w, uploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	var progress float64
	if session.TotalSize > 0 {
		progress = float64(session.UploadedBytes) / float64(session.TotalSize) * 100
	}

	w.Header().Set("Upload-Offset", strconv.FormatInt(session.UploadedBytes, 10))
	w.Header().Set("Upload-Length", strconv.FormatInt(session.TotalSize, 10))

	if r.Method == "GET" {
		writeJSON(w, http.StatusOK, domain.UploadStatusResponse{
			SessionID:     session.ID.String(),
			Filename:      session.Filename,
			UploadedBytes: session.UploadedBytes,
			TotalSize:     session.TotalSize,
			ChunkSize:     session.ChunkSize,
			Status:        session.Status,
			Progress:      progress,
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CancelUpload handles DELETE /api/v1/files/upload/{sessionID}.
func (h *FileHandler) CancelUpload(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}
	if err := h.fileService.CancelUpload(r.Context(), sessionID, userID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrUploadSessionNotFound):
			status = http.StatusNotFound
		case errors.Is(err, domain.ErrForbidden):
			status = http.StatusForbidden
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetFile handles GET /api/v1/files/{fileID}
func (h *FileHandler) GetFile(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid file ID"})
		return
	}

	file, err := h.fileService.GetFile(r.Context(), fileID, userID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrFileNotFound), errors.Is(err, domain.ErrFileDeleted):
			status = http.StatusNotFound
		case errors.Is(err, domain.ErrForbidden):
			status = http.StatusForbidden
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	linkCount, _ := h.linkService.GetLinkCount(r.Context(), fileID)

	var expiresAt *string
	if file.ExpiresAt != nil {
		s := file.ExpiresAt.Format(time.RFC3339)
		expiresAt = &s
	}

	writeJSON(w, http.StatusOK, domain.FileInfoResponse{
		ID:            file.ID.String(),
		OriginalName:  file.OriginalName,
		MIMEType:      file.MIMEType,
		SizeBytes:     file.SizeBytes,
		SHA256:        file.SHA256,
		DownloadCount: file.DownloadCount,
		CreatedAt:     file.CreatedAt.Format(time.RFC3339),
		ExpiresAt:     expiresAt,
		Links:         linkCount,
	})
}

// ListFiles handles GET /api/v1/files
func (h *FileHandler) ListFiles(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	files, total, err := h.fileService.ListFiles(r.Context(), userID, page, perPage)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "failed to list files"})
		return
	}

	fileIDs := make([]uuid.UUID, 0, len(files))
	for _, f := range files {
		fileIDs = append(fileIDs, f.ID)
	}
	linkCounts, err := h.linkService.GetLinkCounts(r.Context(), fileIDs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "failed to list files"})
		return
	}

	fileResponses := make([]domain.FileInfoResponse, 0, len(files))
	for _, f := range files {
		var expiresAt *string
		if f.ExpiresAt != nil {
			s := f.ExpiresAt.Format(time.RFC3339)
			expiresAt = &s
		}

		fileResponses = append(fileResponses, domain.FileInfoResponse{
			ID:            f.ID.String(),
			OriginalName:  f.OriginalName,
			MIMEType:      f.MIMEType,
			SizeBytes:     f.SizeBytes,
			SHA256:        f.SHA256,
			DownloadCount: f.DownloadCount,
			CreatedAt:     f.CreatedAt.Format(time.RFC3339),
			ExpiresAt:     expiresAt,
			Links:         linkCounts[f.ID],
		})
	}

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))

	writeJSON(w, http.StatusOK, domain.FileListResponse{
		Files:      fileResponses,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	})
}

// DeleteFile handles DELETE /api/v1/files/{fileID}
func (h *FileHandler) DeleteFile(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid file ID"})
		return
	}

	if err := h.fileService.DeleteFile(r.Context(), fileID, userID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrFileNotFound):
			status = http.StatusNotFound
		case errors.Is(err, domain.ErrForbidden):
			status = http.StatusForbidden
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func uploadErrorStatus(err error) int {
	switch {
	case errors.Is(err, domain.ErrQuotaExceeded), errors.Is(err, domain.ErrFileTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, domain.ErrInsufficientStorage):
		return http.StatusInsufficientStorage
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrUploadSessionNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrUploadSessionExpired):
		return http.StatusGone
	case errors.Is(err, domain.ErrUploadStateMismatch), errors.Is(err, domain.ErrChunkOutOfRange):
		return http.StatusConflict
	case errors.Is(err, domain.ErrBlockedExtension), errors.Is(err, domain.ErrInvalidMIMEType):
		return http.StatusUnsupportedMediaType
	default:
		return http.StatusBadRequest
	}
}

func fileInfo(file *domain.File, linkCount int) domain.FileInfoResponse {
	var expiresAt *string
	if file.ExpiresAt != nil {
		value := file.ExpiresAt.Format(time.RFC3339)
		expiresAt = &value
	}
	return domain.FileInfoResponse{
		ID: file.ID.String(), OriginalName: file.OriginalName, MIMEType: file.MIMEType,
		SizeBytes: file.SizeBytes, SHA256: file.SHA256, DownloadCount: file.DownloadCount,
		CreatedAt: file.CreatedAt.Format(time.RFC3339), ExpiresAt: expiresAt, Links: linkCount,
	}
}

// GetQuota handles GET /api/v1/files/quota
func (h *FileHandler) GetQuota(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	quota, err := h.fileService.GetQuota(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "failed to get quota"})
		return
	}

	writeJSON(w, http.StatusOK, quota)
}
