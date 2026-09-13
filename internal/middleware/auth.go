package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/service"
	"github.com/google/uuid"
)

type contextKey string

const (
	ContextUserID   contextKey = "user_id"
	ContextUsername contextKey = "username"
	ContextRole     contextKey = "role"
	ContextUser     contextKey = "user"
	ContextScopes   contextKey = "scopes"
	ContextAuthType contextKey = "auth_type"
)

// AuthMiddleware handles JWT and API key authentication
type AuthMiddleware struct {
	authService *service.AuthService
}

func NewAuthMiddleware(authService *service.AuthService) *AuthMiddleware {
	return &AuthMiddleware{authService: authService}
}

// Required enforces authentication
func (m *AuthMiddleware) Required(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try Bearer JWT first
		if token := extractBearerToken(r); token != "" {
			_, user, err := m.authService.ValidateJWTUser(r.Context(), token)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			ctx := authenticatedContext(r.Context(), user, "jwt", nil)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Try API key
		if apiKey := extractAPIKey(r); apiKey != "" {
			user, scopes, err := m.authService.ValidateAPIKey(r.Context(), apiKey)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid api key")
				return
			}

			ctx := authenticatedContext(r.Context(), user, "apikey", scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		writeJSONError(w, http.StatusUnauthorized, "authentication required")
	})
}

// RequireScope enforces one scope for API-key requests. JWT sessions retain
// their normal user privileges and are not artificially scoped.
func (m *AuthMiddleware) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authType, _ := r.Context().Value(ContextAuthType).(string)
			if authType != "apikey" {
				next.ServeHTTP(w, r)
				return
			}
			scopes, _ := r.Context().Value(ContextScopes).([]string)
			for _, candidate := range scopes {
				if candidate == scope {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeJSONError(w, http.StatusForbidden, "api key scope required: "+scope)
		})
	}
}

// JWTOnly prevents API keys from minting credentials or performing account
// administration, even when the owning user is an administrator.
func (m *AuthMiddleware) JWTOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authType, _ := r.Context().Value(ContextAuthType).(string)
		if authType != "jwt" {
			writeJSONError(w, http.StatusForbidden, "interactive session required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminOnly restricts access to admin users
func (m *AuthMiddleware) AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, ok := r.Context().Value(ContextRole).(string)
		if !ok || role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Optional tries to authenticate but doesn't require it
func (m *AuthMiddleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := extractBearerToken(r); token != "" {
			_, user, err := m.authService.ValidateJWTUser(r.Context(), token)
			if err == nil {
				ctx := authenticatedContext(r.Context(), user, "jwt", nil)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		if apiKey := extractAPIKey(r); apiKey != "" {
			user, scopes, err := m.authService.ValidateAPIKey(r.Context(), apiKey)
			if err == nil {
				ctx := authenticatedContext(r.Context(), user, "apikey", scopes)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func authenticatedContext(ctx context.Context, user *domain.User, authType string, scopes []string) context.Context {
	ctx = context.WithValue(ctx, ContextUserID, user.ID)
	ctx = context.WithValue(ctx, ContextUsername, user.Username)
	ctx = context.WithValue(ctx, ContextRole, user.Role)
	ctx = context.WithValue(ctx, ContextUser, user)
	ctx = context.WithValue(ctx, ContextAuthType, authType)
	if scopes != nil {
		ctx = context.WithValue(ctx, ContextScopes, scopes)
	}
	return ctx
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) (uuid.UUID, error) {
	id, ok := ctx.Value(ContextUserID).(uuid.UUID)
	if !ok {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return id, nil
}

// GetRole extracts role from context
func GetRole(ctx context.Context) string {
	role, _ := ctx.Value(ContextRole).(string)
	return role
}

// SetUserContext adds user info to context (for internal use, e.g. web handler)
func SetUserContext(ctx context.Context, userID uuid.UUID, username, role string) context.Context {
	ctx = context.WithValue(ctx, ContextUserID, userID)
	ctx = context.WithValue(ctx, ContextUsername, username)
	ctx = context.WithValue(ctx, ContextRole, role)
	return ctx
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func extractAPIKey(r *http.Request) string {
	// Check header first
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Check Authorization header with ApiKey scheme
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "ApiKey ") {
		return strings.TrimPrefix(auth, "ApiKey ")
	}

	return ""
}
