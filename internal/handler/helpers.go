package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/HeartBtz/fluxgate/internal/domain"
)

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			slog.Error("failed to encode JSON response", "error", err)
		}
	}
}

// safeErrorMessage exposes only stable domain errors. Wrapped database,
// filesystem and internal errors remain in server logs and never reach users.
func safeErrorMessage(err error) string {
	public := []error{
		domain.ErrUnauthorized, domain.ErrForbidden, domain.ErrInvalidToken,
		domain.ErrTokenExpired, domain.ErrInvalidAPIKey, domain.ErrInvalidCredentials,
		domain.ErrUserNotFound, domain.ErrUserExists, domain.ErrUserInactive,
		domain.ErrQuotaExceeded, domain.ErrFileNotFound, domain.ErrFileTooLarge,
		domain.ErrInvalidFileName, domain.ErrInvalidMIMEType, domain.ErrBlockedExtension,
		domain.ErrUploadIncomplete, domain.ErrFileDeleted, domain.ErrFileExpired,
		domain.ErrLinkNotFound, domain.ErrLinkExpired, domain.ErrLinkExhausted,
		domain.ErrLinkRevoked, domain.ErrLinkInactive, domain.ErrIPNotAllowed,
		domain.ErrPasswordRequired, domain.ErrPasswordInvalid, domain.ErrInvalidSignature,
		domain.ErrInvalidLinkType, domain.ErrInvalidExpiration,
		domain.ErrUploadSessionNotFound, domain.ErrUploadSessionExpired,
		domain.ErrUploadStateMismatch, domain.ErrChunkOutOfRange,
		domain.ErrInsufficientStorage, domain.ErrRateLimited, domain.ErrInvalidScope,
		domain.ErrInvalidInput, domain.ErrPasswordWeak,
		domain.ErrUserHasData,
	}
	for _, candidate := range public {
		if errors.Is(err, candidate) {
			return candidate.Error()
		}
	}
	return "internal server error"
}
