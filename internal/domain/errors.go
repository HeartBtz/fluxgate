package domain

import "errors"

// Erreurs sentinelle du domaine, utilisées dans toutes les couches (service, handler, repository).
// Permettent de distinguer les erreurs métier des erreurs techniques
// et de renvoyer le bon code HTTP dans les handlers.
var (
	// Auth errors
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidAPIKey      = errors.New("invalid api key")
	ErrInvalidCredentials = errors.New("invalid credentials")

	// User errors
	ErrUserNotFound  = errors.New("user not found")
	ErrUserExists    = errors.New("user already exists")
	ErrUserInactive  = errors.New("user account is inactive")
	ErrQuotaExceeded = errors.New("storage quota exceeded")
	ErrInvalidInput  = errors.New("invalid input")
	ErrPasswordWeak  = errors.New("password must be between 8 and 72 bytes")
	ErrUserHasData   = errors.New("user still owns files or active uploads")

	// File errors
	ErrFileNotFound     = errors.New("file not found")
	ErrFileTooLarge     = errors.New("file exceeds maximum size")
	ErrInvalidFileName  = errors.New("invalid file name")
	ErrInvalidMIMEType  = errors.New("file type not allowed")
	ErrBlockedExtension = errors.New("file extension is blocked")
	ErrUploadIncomplete = errors.New("upload is not complete")
	ErrFileDeleted      = errors.New("file has been deleted")
	ErrFileExpired      = errors.New("file has expired")

	// Link errors
	ErrLinkNotFound      = errors.New("download link not found")
	ErrLinkExpired       = errors.New("download link has expired")
	ErrLinkExhausted     = errors.New("download limit reached")
	ErrLinkRevoked       = errors.New("download link has been revoked")
	ErrLinkInactive      = errors.New("download link is inactive")
	ErrIPNotAllowed      = errors.New("ip address not allowed")
	ErrPasswordRequired  = errors.New("password required")
	ErrPasswordInvalid   = errors.New("invalid password")
	ErrInvalidSignature  = errors.New("invalid url signature")
	ErrInvalidLinkType   = errors.New("invalid link type")
	ErrInvalidExpiration = errors.New("link expiration must be greater than zero")

	// Upload errors
	ErrUploadSessionNotFound = errors.New("upload session not found")
	ErrUploadSessionExpired  = errors.New("upload session expired")
	ErrUploadStateMismatch   = errors.New("upload state does not match stored data")
	ErrChunkOutOfRange       = errors.New("chunk offset out of range")

	// Storage errors
	ErrStorageWriteFailed  = errors.New("failed to write to storage")
	ErrStorageReadFailed   = errors.New("failed to read from storage")
	ErrStorageDeleteFailed = errors.New("failed to delete from storage")
	ErrInsufficientStorage = errors.New("insufficient storage capacity")

	// API key errors
	ErrInvalidScope = errors.New("invalid api key scope")

	// Rate limiting
	ErrRateLimited = errors.New("rate limit exceeded")
)
