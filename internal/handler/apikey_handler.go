package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/google/uuid"
)

// APIKeyHandler gère les endpoints de gestion des clés API :
// création, listage, révocation et suppression.
type APIKeyHandler struct {
	apiKeyService *service.APIKeyService
}

// NewAPIKeyHandler crée un nouveau handler de clés API.
func NewAPIKeyHandler(apiKeyService *service.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{apiKeyService: apiKeyService}
}

// Create handles POST /api/v1/apikeys
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	var req domain.CreateAPIKeyRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid request"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "name required"})
		return
	}

	resp, err := h.apiKeyService.Create(r.Context(), userID, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "failed to create API key"})
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// List handles GET /api/v1/apikeys
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	keys, err := h.apiKeyService.List(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "failed to list keys"})
		return
	}

	if keys == nil {
		keys = []*domain.APIKey{}
	}

	writeJSON(w, http.StatusOK, keys)
}

// Revoke handles POST /api/v1/apikeys/{keyID}/revoke
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	keyIDStr := chi.URLParam(r, "keyID")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid key ID"})
		return
	}

	if err := h.apiKeyService.Revoke(r.Context(), keyID, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete handles DELETE /api/v1/apikeys/{keyID}
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	keyIDStr := chi.URLParam(r, "keyID")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid key ID"})
		return
	}

	if err := h.apiKeyService.Delete(r.Context(), keyID, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: safeErrorMessage(err)})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
