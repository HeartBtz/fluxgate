package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/HeartBtz/fluxgate/internal/domain"
	fluxmetrics "github.com/HeartBtz/fluxgate/internal/metrics"
	"github.com/HeartBtz/fluxgate/internal/middleware"
	"github.com/HeartBtz/fluxgate/internal/service"
)

// AuthHandler gère les endpoints d'authentification :
// login (POST /api/v1/auth/login), profil (GET /auth/me),
// et enregistrement d'utilisateurs (POST /auth/register, admin seulement).
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler crée un nouveau handler d'authentification.
func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req domain.AuthLoginRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "username and password required"})
		return
	}

	if len(req.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "password too long (max 72 chars)"})
		return
	}
	if len(req.Username) > 255 {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "username too long"})
		return
	}

	resp, err := h.authService.Login(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			fluxmetrics.AuthFailures.WithLabelValues("invalid_credentials").Inc()
			writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "invalid credentials"})
		case errors.Is(err, domain.ErrUserInactive):
			fluxmetrics.AuthFailures.WithLabelValues("user_inactive").Inc()
			writeJSON(w, http.StatusForbidden, domain.ErrorResponse{Error: "account is inactive"})
		default:
			fluxmetrics.AuthFailures.WithLabelValues("unknown").Inc()
			writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "login failed"})
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Register handles POST /api/v1/auth/register (admin only)
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Only admins can create new users
	role := middleware.GetRole(r.Context())
	if role != "admin" {
		writeJSON(w, http.StatusForbidden, domain.ErrorResponse{Error: "admin access required"})
		return
	}

	var req domain.CreateUserRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "username, email and password required"})
		return
	}

	if len(req.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "password too long (max 72 chars)"})
		return
	}
	if len(req.Username) > 255 {
		writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: "username too long"})
		return
	}

	user, err := h.authService.Register(r.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrUserExists) {
			writeJSON(w, http.StatusConflict, domain.ErrorResponse{Error: "user already exists"})
			return
		}
		if errors.Is(err, domain.ErrInvalidInput) || errors.Is(err, domain.ErrPasswordWeak) {
			writeJSON(w, http.StatusBadRequest, domain.ErrorResponse{Error: safeErrorMessage(err)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "registration failed"})
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// Me handles GET /api/v1/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, domain.ErrorResponse{Error: "unauthorized"})
		return
	}

	user, err := h.authService.GetUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, domain.ErrorResponse{Error: "failed to get user"})
		return
	}

	writeJSON(w, http.StatusOK, user)
}
