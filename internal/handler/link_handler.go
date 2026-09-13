package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/HeartBtz/fluxgate/internal/domain"
	fluxmetrics "github.com/HeartBtz/fluxgate/internal/metrics"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/google/uuid"
)

// LinkHandler gère les endpoints de liens de téléchargement :
// création (POST /api/v1/links), listage par fichier, révocation et suppression.
type LinkHandler struct {
	linkService *service.LinkService
}

// NewLinkHandler crée un nouveau handler de liens.
func NewLinkHandler(linkService *service.LinkService) *LinkHandler {
	return &LinkHandler{linkService: linkService}
}

// CreateLink handles POST /api/v1/links
func (h *LinkHandler) CreateLink(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	var req domain.CreateLinkRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid request"})
		return
	}

	if req.FileID == "" {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "file_id required"})
		return
	}

	resp, err := h.linkService.CreateLink(r.Context(), userID, req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrFileNotFound):
			status = http.StatusNotFound
		case errors.Is(err, domain.ErrForbidden):
			status = http.StatusForbidden
		case errors.Is(err, domain.ErrFileDeleted):
			status = http.StatusGone
		case errors.Is(err, domain.ErrUploadIncomplete):
			status = http.StatusConflict
		case errors.Is(err, domain.ErrInvalidLinkType), errors.Is(err, domain.ErrInvalidExpiration), errors.Is(err, domain.ErrPasswordRequired), errors.Is(err, domain.ErrInvalidInput), errors.Is(err, domain.ErrPasswordWeak):
			status = http.StatusBadRequest
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	fluxmetrics.LinksCreated.Inc()
	writeJSON(w, http.StatusCreated, resp)
}

// RevokeLink handles POST /api/v1/links/{linkID}/revoke
func (h *LinkHandler) RevokeLink(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	linkIDStr := chi.URLParam(r, "linkID")
	linkID, err := uuid.Parse(linkIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid link ID"})
		return
	}

	if err := h.linkService.RevokeLink(r.Context(), linkID, userID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrLinkNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, domain.ErrForbidden) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteLink handles DELETE /api/v1/links/{linkID}
func (h *LinkHandler) DeleteLink(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	linkIDStr := chi.URLParam(r, "linkID")
	linkID, err := uuid.Parse(linkIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid link ID"})
		return
	}

	if err := h.linkService.DeleteLink(r.Context(), linkID, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListLinks handles GET /api/v1/links/file/{fileID}
func (h *LinkHandler) ListLinks(w http.ResponseWriter, r *http.Request) {
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

	links, err := h.linkService.ListLinks(r.Context(), fileID, userID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, domain.ErrForbidden) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	if links == nil {
		links = []*domain.DownloadLink{}
	}

	writeJSON(w, http.StatusOK, links)
}
