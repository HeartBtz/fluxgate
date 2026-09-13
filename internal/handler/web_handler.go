package handler

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/HeartBtz/fluxgate/internal/config"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/HeartBtz/fluxgate/internal/service"
)

// templateFS contient les templates HTML embarquées dans le binaire.
// Permet un déploiement en un seul fichier sans dépendances externes.
//
//go:embed templates/*.html
var templateFS embed.FS

var funcMap = template.FuncMap{
	"humanSize":  humanSize,
	"timeAgo":    timeAgo,
	"truncate":   truncateStr,
	"divPercent": divPercent,
}

// WebHandler gère l'interface web de FluxGate (dashboard, page de login, upload).
// Les templates HTML sont embarquées dans le binaire via go:embed.
type WebHandler struct {
	auth        *service.AuthService
	fileService *service.FileService
	linkService *service.LinkService
	userRepo    *repository.UserRepository
	fileRepo    *repository.FileRepository
	linkRepo    *repository.LinkRepository
	cfg         *config.Config
	logger      *slog.Logger
	templates   *template.Template
}

// NewWebHandler crée un nouveau handler web avec les templates parsées.
func NewWebHandler(auth *service.AuthService, fileService *service.FileService, linkService *service.LinkService, userRepo *repository.UserRepository, fileRepo *repository.FileRepository, linkRepo *repository.LinkRepository, cfg *config.Config, logger *slog.Logger) *WebHandler {
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))
	return &WebHandler{
		auth:        auth,
		fileService: fileService,
		linkService: linkService,
		userRepo:    userRepo,
		fileRepo:    fileRepo,
		linkRepo:    linkRepo,
		cfg:         cfg,
		logger:      logger,
		templates:   tmpl,
	}
}

type pageData struct {
	Title     string
	User      *domain.User
	BaseURL   string
	Flash     string
	FlashErr  string
	CSRFToken string
	Nonce     string
	Data      interface{}
}

func (h *WebHandler) newPageData(title string, r *http.Request) pageData {
	pd := pageData{
		Title:     title,
		BaseURL:   h.cfg.Server.BaseURL,
		CSRFToken: middleware.GetCSRFToken(r.Context()),
		Nonce:     middleware.GetCSPNonce(r.Context()),
	}
	// Check session cookie
	if cookie, err := r.Cookie("fluxgate_session"); err == nil {
		_, user, err := h.auth.ValidateJWTUser(r.Context(), cookie.Value)
		if err == nil {
			pd.User = user
		}
	}
	return pd
}

func (h *WebHandler) render(w http.ResponseWriter, tmplName string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, tmplName, data); err != nil {
		h.logger.Error("template render failed", slog.String("template", tmplName), slog.Any("error", err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Index redirects to dashboard if logged in, otherwise login
func (h *WebHandler) Index(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("fluxgate_session"); err == nil {
		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

func (h *WebHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Login", r)
	if pd.User != nil {
		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		return
	}
	h.render(w, "login.html", pd)
}

func (h *WebHandler) LoginPost(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	resp, err := h.auth.Login(r.Context(), domain.AuthLoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		pd := h.newPageData("Login", r)
		pd.FlashErr = "Invalid credentials"
		h.render(w, "login.html", pd)
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the validated public URL; production is HTTPS
		Name:     "fluxgate_session",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(strings.ToLower(h.cfg.Server.BaseURL), "https://"),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(resp.ExpiresIn),
	})
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *WebHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the validated public URL; production is HTTPS
		Name:     "fluxgate_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(strings.ToLower(h.cfg.Server.BaseURL), "https://"),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type dashboardData struct {
	Files      []domain.File
	Quota      *domain.QuotaResponse
	TotalFiles int
}

func (h *WebHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Dashboard", r)
	if pd.User == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// Fetch files
	files, total, err := h.fileService.ListFiles(r.Context(), pd.User.ID, 1, 50)
	if err != nil {
		h.logger.Error("list files failed", slog.Any("error", err))
		http.Error(w, "File list unavailable; please retry", http.StatusServiceUnavailable)
		return
	}

	// Convert for template
	fileList := make([]domain.File, 0, len(files))
	for _, f := range files {
		fileList = append(fileList, *f)
	}

	// Fetch quota
	quota, err := h.fileService.GetQuota(r.Context(), pd.User.ID)
	if err != nil {
		h.logger.Error("get quota failed", slog.Any("error", err))
		http.Error(w, "Quota unavailable; please retry", http.StatusServiceUnavailable)
		return
	}

	pd.Data = dashboardData{
		Files:      fileList,
		Quota:      quota,
		TotalFiles: int(total),
	}
	h.render(w, "dashboard.html", pd)
}

func (h *WebHandler) WebUpload(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Upload", r)
	if pd.User == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Set user in context for file service
	ctx := middleware.SetUserContext(r.Context(), pd.User.ID, pd.User.Username, pd.User.Role)

	// Stream multipart data directly into storage. Request.FormFile would first
	// spool multi-gigabyte files to /tmp and then copy them a second time.
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.Limits.MaxUploadSize+multipartOverheadAllowance)
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "Invalid multipart upload", http.StatusBadRequest)
		return
	}
	file, err := streamMultipartFile(mediaType, params, r.Body)
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}

	result, err := h.fileService.Upload(ctx, pd.User.ID, file.FileName(), 0, file)
	if err != nil {
		h.logger.Error("web upload failed", slog.Any("error", err))
		http.Error(w, "Upload failed: "+safeErrorMessage(err), webUploadErrorStatus(err))
		return
	}

	// Auto-create a 1h public download link
	linkReq := domain.CreateLinkRequest{
		FileID:    result.ID.String(),
		LinkType:  "public",
		ExpiresIn: "1h",
	}
	linkResp, err := h.linkService.CreateLink(ctx, pd.User.ID, linkReq)
	if err != nil {
		h.logger.Error("auto-link creation failed", slog.Any("error", err))
	}

	// Build response with link
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	downloadURL := ""
	expiresAt := ""
	if linkResp != nil {
		downloadURL = linkResp.DirectURL
		if linkResp.ExpiresAt != nil {
			expiresAt = *linkResp.ExpiresAt
		}
	}
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"file":         result.OriginalName,
		"size":         result.SizeBytes,
		"download_url": downloadURL,
		"expires_at":   expiresAt,
	}); err != nil {
		h.logger.Debug("write upload response failed", slog.String("error", err.Error()))
	}
}

// WebInitResumableUpload starts a cookie-authenticated upload session for the
// dashboard. It lives under the CSRF-protected web router; API endpoints keep
// requiring bearer or API-key authentication.
func (h *WebHandler) WebInitResumableUpload(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Upload", r)
	if pd.User == nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	var req domain.UploadInitRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid request"})
		return
	}
	ctx := middleware.SetUserContext(r.Context(), pd.User.ID, pd.User.Username, pd.User.Role)
	session, err := h.fileService.InitResumableUpload(ctx, pd.User.ID, req)
	if err != nil {
		writeJSON(w, webUploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}
	writeJSON(w, http.StatusCreated, domain.UploadInitResponse{
		SessionID: session.ID.String(),
		ChunkSize: session.ChunkSize,
		UploadURL: "/web/upload/" + session.ID.String(),
	})
}

// WebUploadChunk appends one bounded chunk to a dashboard upload session.
func (h *WebHandler) WebUploadChunk(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Upload", r)
	if pd.User == nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid upload offset"})
		return
	}
	ctx := middleware.SetUserContext(r.Context(), pd.User.ID, pd.User.Username, pd.User.Role)
	uploaded, err := h.fileService.UploadChunk(ctx, sessionID, pd.User.ID, offset, r.Body)
	if err != nil {
		writeJSON(w, webUploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(uploaded, 10))
	w.WriteHeader(http.StatusNoContent)
}

// WebUploadStatus returns the authoritative offset after a lost response or a
// page reload so the browser can resume without retransmitting prior chunks.
func (h *WebHandler) WebUploadStatus(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Upload", r)
	if pd.User == nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}
	session, err := h.fileService.GetUploadStatus(r.Context(), sessionID, pd.User.ID)
	if err != nil {
		writeJSON(w, webUploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}
	if session.UserID != pd.User.ID {
		writeJSON(w, http.StatusForbidden, domain.ErrorResponse{Error: "forbidden"})
		return
	}
	progress := float64(0)
	if session.TotalSize > 0 {
		progress = float64(session.UploadedBytes) / float64(session.TotalSize) * 100
	}
	writeJSON(w, http.StatusOK, domain.UploadStatusResponse{
		SessionID:     session.ID.String(),
		Filename:      session.Filename,
		UploadedBytes: session.UploadedBytes,
		TotalSize:     session.TotalSize,
		ChunkSize:     session.ChunkSize,
		Status:        session.Status,
		Progress:      progress,
	})
}

func (h *WebHandler) WebCancelResumableUpload(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Upload", r)
	if pd.User == nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}
	if err := h.fileService.CancelUpload(r.Context(), sessionID, pd.User.ID); err != nil {
		writeJSON(w, webUploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// WebCompleteResumableUpload finalizes the file and returns the same one-hour
// public link as the legacy dashboard upload endpoint.
func (h *WebHandler) WebCompleteResumableUpload(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Upload", r)
	if pd.User == nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid session ID"})
		return
	}
	ctx := middleware.SetUserContext(r.Context(), pd.User.ID, pd.User.Username, pd.User.Role)
	file, err := h.fileService.CompleteResumableUpload(ctx, sessionID, pd.User.ID)
	if err != nil {
		writeJSON(w, webUploadErrorStatus(err), domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}
	h.writeWebUploadResult(w, ctx, pd.User.ID, file)
}

func webUploadErrorStatus(err error) int {
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

func (h *WebHandler) writeWebUploadResult(w http.ResponseWriter, ctx context.Context, userID uuid.UUID, file *domain.File) {
	linkResp, err := h.linkService.CreateLink(ctx, userID, domain.CreateLinkRequest{
		FileID: file.ID.String(), LinkType: "public", ExpiresIn: "1h",
	})
	if err != nil {
		h.logger.Error("auto-link creation failed", slog.Any("error", err))
	}
	downloadURL, expiresAt := "", ""
	if linkResp != nil {
		downloadURL = linkResp.DirectURL
		if linkResp.ExpiresAt != nil {
			expiresAt = *linkResp.ExpiresAt
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "file": file.OriginalName, "size": file.SizeBytes,
		"download_url": downloadURL, "expires_at": expiresAt,
	})
}

func (h *WebHandler) WebCreateLink(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	pd := h.newPageData("Create Link", r)
	if pd.User == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fileID := r.FormValue("file_id")
	linkType := r.FormValue("type")
	if linkType == "" {
		linkType = "public"
	}
	expiresIn := r.FormValue("expires_in")
	if expiresIn == "" {
		expiresIn = "7d"
	}
	password := r.FormValue("password")

	req := domain.CreateLinkRequest{
		FileID:    fileID,
		LinkType:  linkType,
		ExpiresIn: expiresIn,
		Password:  password,
	}
	if value := r.PostForm.Get("max_downloads"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 {
			http.Error(w, "Invalid download limit", http.StatusBadRequest)
			return
		}
		req.MaxDownloads = &limit
	}

	link, err := h.linkService.CreateLink(r.Context(), pd.User.ID, req)
	if err != nil {
		h.logger.Error("web create link failed", slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrInvalidInput) || errors.Is(err, domain.ErrInvalidLinkType) || errors.Is(err, domain.ErrInvalidExpiration) || errors.Is(err, domain.ErrPasswordRequired) || errors.Is(err, domain.ErrPasswordWeak) {
			status = http.StatusBadRequest
		}
		http.Error(w, "Failed to create link: "+safeErrorMessage(err), status)
		return
	}

	downloadURL := link.DirectURL
	if downloadURL == "" {
		downloadURL = link.URL
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(`<div class="alert success">
			<strong>Download link created:</strong><br>
			<code class="url-display">` + html.EscapeString(downloadURL) + `</code><br>
			<small>wget ` + html.EscapeString(downloadURL) + `</small>
		</div>`)); err != nil {
			h.logger.Debug("write link response failed", slog.String("error", err.Error()))
		}
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *WebHandler) WebDeleteFile(w http.ResponseWriter, r *http.Request) {
	pd := h.newPageData("Delete", r)
	if pd.User == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}
	err = h.fileService.DeleteFile(r.Context(), fileID, pd.User.ID)
	if err != nil {
		h.logger.Error("web delete failed", slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrForbidden) {
			status = http.StatusForbidden
		} else if errors.Is(err, domain.ErrFileNotFound) || errors.Is(err, domain.ErrFileDeleted) {
			status = http.StatusNotFound
		}
		http.Error(w, "Delete failed: "+safeErrorMessage(err), status)
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Template helpers
func humanSize(bytes int64) string {
	sizes := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	if bytes == 0 {
		return "0 B"
	}
	size := float64(bytes)
	i := 0
	for size >= 1024 && i < len(sizes)-1 {
		size /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", size, sizes[i])
}

func divPercent(used, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// ── Admin handlers ──

type adminData struct {
	Users        []*domain.User
	TotalUsers   int
	TotalFiles   int64
	TotalLinks   int64
	TotalStorage int64
}

func (h *WebHandler) requireAdmin(w http.ResponseWriter, r *http.Request) (*pageData, bool) {
	pd := h.newPageData("Admin", r)
	if pd.User == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return nil, false
	}
	if pd.User.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}
	return &pd, true
}

func (h *WebHandler) AdminPage(w http.ResponseWriter, r *http.Request) {
	pd, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	users, total, err := h.userRepo.List(r.Context(), 1, 200)
	if err != nil {
		h.logger.Error("admin list users failed", slog.Any("error", err))
		http.Error(w, "User list unavailable; please retry", http.StatusServiceUnavailable)
		return
	}

	// Count files & storage
	var totalFiles int64
	var totalStorage int64
	for _, u := range users {
		fc, err := h.userRepo.GetFileCount(r.Context(), u.ID)
		if err != nil {
			http.Error(w, "File statistics unavailable; please retry", http.StatusServiceUnavailable)
			return
		}
		totalFiles += fc
		totalStorage += u.UsedBytes
	}

	// Count active links
	totalLinks, err := h.linkRepo.CountAll(r.Context())
	if err != nil {
		http.Error(w, "Link statistics unavailable; please retry", http.StatusServiceUnavailable)
		return
	}

	pd.Data = adminData{
		Users:        users,
		TotalUsers:   int(total),
		TotalFiles:   totalFiles,
		TotalLinks:   totalLinks,
		TotalStorage: totalStorage,
	}
	h.render(w, "admin.html", *pd)
}

func parseQuotaBytes(valueStr, unit string) int64 {
	val, err := strconv.ParseFloat(valueStr, 64)
	if err != nil || val < 0 || math.IsNaN(val) || math.IsInf(val, 0) {
		return -1
	}
	// Prevent integer overflow on max limits (e.g. realistic max 10000)
	if val > 1000000 {
		val = 1000000
	}
	switch unit {
	case "TB":
		return int64(val * 1024 * 1024 * 1024 * 1024)
	case "GB":
		return int64(val * 1024 * 1024 * 1024)
	case "MB":
		return int64(val * 1024 * 1024)
	default:
		return int64(val * 1024 * 1024 * 1024) // default GB
	}
}

func (h *WebHandler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")
	if role == "" {
		role = "user"
	}

	quotaBytes := parseQuotaBytes(r.FormValue("quota_value"), r.FormValue("quota_unit"))
	maxFileSize := parseQuotaBytes(r.FormValue("max_file_value"), r.FormValue("max_file_unit"))
	if quotaBytes < 0 || maxFileSize < 0 {
		http.Error(w, "Invalid quota or maximum file size", http.StatusBadRequest)
		return
	}

	req := domain.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password,
		Role:     role,
	}

	user, err := h.auth.Register(r.Context(), req)
	if err != nil {
		h.logger.Error("admin create user failed", slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrUserExists) {
			status = http.StatusConflict
		} else if errors.Is(err, domain.ErrInvalidInput) || errors.Is(err, domain.ErrPasswordWeak) {
			status = http.StatusBadRequest
		}
		http.Error(w, "Création échouée: "+safeErrorMessage(err), status)
		return
	}

	// Update quota and max file size
	user.QuotaBytes = quotaBytes
	user.MaxFileSize = maxFileSize
	if err := h.userRepo.Update(r.Context(), user); err != nil {
		h.logger.Error("admin update quota failed", slog.Any("error", err))
		http.Error(w, "User created but quota update failed; review the account", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *WebHandler) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	pd, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	userID, err := uuid.Parse(r.FormValue("user_id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	user.Username = r.FormValue("username")
	user.Email = r.FormValue("email")
	user.Role = r.FormValue("role")
	user.QuotaBytes = parseQuotaBytes(r.FormValue("quota_value"), r.FormValue("quota_unit"))
	user.MaxFileSize = parseQuotaBytes(r.FormValue("max_file_value"), r.FormValue("max_file_unit"))

	newPassword := r.FormValue("password")
	if err := h.auth.AdminUpdateUser(r.Context(), pd.User.ID, user, newPassword); err != nil {
		h.logger.Error("admin update user failed", slog.Any("error", err))
		status := http.StatusBadRequest
		if errors.Is(err, domain.ErrForbidden) {
			status = http.StatusForbidden
		}
		http.Error(w, "Mise à jour échouée: "+safeErrorMessage(err), status)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *WebHandler) AdminToggleUser(w http.ResponseWriter, r *http.Request) {
	if !parseSmallForm(w, r) {
		return
	}
	pd, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	active := r.FormValue("active") == "true"

	user, err := h.userRepo.GetByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	user.IsActive = active
	if err := h.auth.AdminUpdateUser(r.Context(), pd.User.ID, user, ""); err != nil {
		h.logger.Error("admin toggle user failed", slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrForbidden) {
			status = http.StatusForbidden
		}
		http.Error(w, "Update failed: "+safeErrorMessage(err), status)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// Management forms never need upload-sized bodies or temporary file parts.
func parseSmallForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var err error
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		err = r.ParseMultipartForm(64 << 10)
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
			if len(r.MultipartForm.File) != 0 {
				err = domain.ErrInvalidInput
			}
		}
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		http.Error(w, "Invalid or oversized form", http.StatusBadRequest)
		return false
	}
	// State-changing fields must come from the body, not the URL query.
	r.Form = r.PostForm
	return true
}

func (h *WebHandler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	pd, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := h.auth.AdminDeleteUser(r.Context(), pd.User.ID, userID); err != nil {
		h.logger.Error("admin delete user failed", slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrForbidden) || errors.Is(err, domain.ErrUserHasData) {
			status = http.StatusConflict
		}
		http.Error(w, "Delete failed: "+safeErrorMessage(err), status)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
