package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/HeartBtz/fluxgate/internal/config"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthService gère l'authentification et la gestion des utilisateurs.
// Fournit : login (JWT), vérification de tokens, validation de clés API,
// hachage bcrypt des mots de passe, et création du compte admin initial.
type AuthService struct {
	userRepo   *repository.UserRepository
	apiKeyRepo *repository.APIKeyRepository
	cfg        *config.Config
	lastUsedQ  chan uuid.UUID
}

// NewAuthService crée un nouveau service d'authentification.
func NewAuthService(userRepo *repository.UserRepository, apiKeyRepo *repository.APIKeyRepository, cfg *config.Config) *AuthService {
	svc := &AuthService{
		userRepo:   userRepo,
		apiKeyRepo: apiKeyRepo,
		cfg:        cfg,
		lastUsedQ:  make(chan uuid.UUID, 1024),
	}
	go svc.runLastUsedWorker()
	return svc
}

func (s *AuthService) runLastUsedWorker() {
	for id := range s.lastUsedQ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.apiKeyRepo.UpdateLastUsed(ctx, id)
		cancel()
	}
}

// JWTClaims custom claims
type JWTClaims struct {
	UserID   string `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	AuthTag  string `json:"atg"`
	jwt.RegisteredClaims
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,30}$`)

// Login authenticates a user and returns a JWT
func (s *AuthService) Login(ctx context.Context, req domain.AuthLoginRequest) (*domain.AuthLoginResponse, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" || len(req.Password) > 72 {
		return nil, domain.ErrInvalidCredentials
	}
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, domain.ErrUserInactive
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	token, err := s.generateJWT(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &domain.AuthLoginResponse{
		Token:     token,
		ExpiresIn: int64(s.cfg.Auth.JWTExpiry.Seconds()),
		User:      user,
	}, nil
}

// ValidateJWT validates a JWT token and returns claims
func (s *AuthService) ValidateJWT(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(s.cfg.Auth.JWTSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer("fluxgate"), jwt.WithExpirationRequired())

	if err != nil || !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	return claims, nil
}

// ValidateJWTUser validates the token and resolves the current user state.
// Roles and account activation are never trusted solely from stale JWT claims.
func (s *AuthService) ValidateJWTUser(ctx context.Context, tokenString string) (*JWTClaims, *domain.User, error) {
	claims, err := s.ValidateJWT(tokenString)
	if err != nil {
		return nil, nil, err
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil || claims.Subject != userID.String() {
		return nil, nil, domain.ErrInvalidToken
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || !user.IsActive {
		return nil, nil, domain.ErrUserInactive
	}
	if claims.IssuedAt == nil || !hmac.Equal([]byte(claims.AuthTag), []byte(s.authTag(user.PasswordHash))) {
		return nil, nil, domain.ErrInvalidToken
	}
	return claims, user, nil
}

// ValidateAPIKey validates an API key and returns the associated user
func (s *AuthService) ValidateAPIKey(ctx context.Context, key string) (*domain.User, []string, error) {
	hash := HashAPIKey(key)

	apiKey, err := s.apiKeyRepo.GetByHash(ctx, hash)
	if err != nil {
		return nil, nil, domain.ErrInvalidAPIKey
	}

	if !apiKey.IsActive {
		return nil, nil, domain.ErrInvalidAPIKey
	}

	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, nil, domain.ErrTokenExpired
	}

	select {
	case s.lastUsedQ <- apiKey.ID:
	default:
		// last_used_at is informational; authentication must not block when the
		// bounded telemetry queue is saturated.
	}

	user, err := s.userRepo.GetByID(ctx, apiKey.UserID)
	if err != nil {
		return nil, nil, err
	}

	if !user.IsActive {
		return nil, nil, domain.ErrUserInactive
	}

	return user, apiKey.Scopes, nil
}

// Register creates a new user
func (s *AuthService) Register(ctx context.Context, req domain.CreateUserRequest) (*domain.User, error) {
	username := strings.TrimSpace(req.Username)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	parsedEmail, emailErr := mail.ParseAddress(email)
	if !usernamePattern.MatchString(username) || emailErr != nil || parsedEmail.Address != email || len(email) > 254 || len(req.Password) < 8 || len(req.Password) > 72 {
		return nil, domain.ErrInvalidInput
	}
	if req.Role != "" && req.Role != "user" && req.Role != "admin" {
		return nil, domain.ErrInvalidInput
	}
	req.Username = username
	req.Email = email
	exists, err := s.userRepo.Exists(ctx, req.Username, req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.cfg.Auth.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	role := "user"
	if req.Role == "admin" {
		role = "admin"
	}

	user := &domain.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Role:         role,
		IsActive:     true,
		QuotaBytes:   s.cfg.Limits.DefaultQuota,
		MaxFileSize:  s.cfg.Limits.MaxUploadSize,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// EnsureAdmin creates the default admin user only on first bootstrap. Keeping
// a bootstrap password in the environment must never reset a live account.
func (s *AuthService) EnsureAdmin(ctx context.Context) error {
	_, err := s.userRepo.GetByUsername(ctx, s.cfg.Auth.AdminUsername)
	if err == nil {
		return nil
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return err
	}
	if s.cfg.Auth.AdminPassword == "" {
		return fmt.Errorf("admin user %q does not exist; FLUXGATE_ADMIN_PASSWORD is required for initial bootstrap", s.cfg.Auth.AdminUsername)
	}

	_, err = s.Register(ctx, domain.CreateUserRequest{
		Username: s.cfg.Auth.AdminUsername,
		Email:    s.cfg.Auth.AdminEmail,
		Password: s.cfg.Auth.AdminPassword,
		Role:     "admin",
	})
	if err != nil && !errors.Is(err, domain.ErrUserExists) {
		return fmt.Errorf("failed to create admin: %w", err)
	}

	return nil
}

// GetUser retrieves a user by ID
func (s *AuthService) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *AuthService) generateJWT(user *domain.User) (string, error) {
	claims := JWTClaims{
		UserID:   user.ID.String(),
		Username: user.Username,
		Role:     user.Role,
		AuthTag:  s.authTag(user.PasswordHash),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.Auth.JWTExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "fluxgate",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.Auth.JWTSecret))
}

func (s *AuthService) authTag(passwordHash string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Auth.JWTSecret))
	_, _ = mac.Write([]byte("fluxgate-auth-tag\x00"))
	_, _ = mac.Write([]byte(passwordHash))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *AuthService) UpdatePasswordAsAdmin(ctx context.Context, userID uuid.UUID, password string) error {
	if len(password) < 8 || len(password) > 72 {
		return domain.ErrPasswordWeak
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	return s.userRepo.UpdatePassword(ctx, userID, string(hash))
}

func (s *AuthService) AdminUpdateUser(ctx context.Context, actorID uuid.UUID, user *domain.User, password string) error {
	current, err := s.userRepo.GetByID(ctx, user.ID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(user.Username)
	email := strings.ToLower(strings.TrimSpace(user.Email))
	parsedEmail, emailErr := mail.ParseAddress(email)
	if !usernamePattern.MatchString(username) || emailErr != nil || parsedEmail.Address != email || len(email) > 254 {
		return domain.ErrInvalidInput
	}
	if user.Role != "user" && user.Role != "admin" || user.QuotaBytes < 0 || user.MaxFileSize < 0 {
		return domain.ErrInvalidInput
	}
	if actorID == user.ID && (user.Role != "admin" || !user.IsActive) {
		return domain.ErrForbidden
	}
	if current.Role == "admin" && current.IsActive && (user.Role != "admin" || !user.IsActive) {
		count, err := s.userRepo.CountActiveAdmins(ctx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return domain.ErrForbidden
		}
	}
	var passwordHash *string
	if password != "" {
		if len(password) < 8 || len(password) > 72 {
			return domain.ErrPasswordWeak
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.Auth.BcryptCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		value := string(hash)
		passwordHash = &value
	}
	user.Username = username
	user.Email = email
	return s.userRepo.UpdateAdmin(ctx, user, passwordHash)
}

func (s *AuthService) AdminDeleteUser(ctx context.Context, actorID, userID uuid.UUID) error {
	if actorID == userID {
		return domain.ErrForbidden
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Role == "admin" && user.IsActive {
		count, err := s.userRepo.CountActiveAdmins(ctx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return domain.ErrForbidden
		}
	}
	hasData, err := s.userRepo.HasStoredData(ctx, userID)
	if err != nil {
		return err
	}
	if hasData {
		return domain.ErrUserHasData
	}
	return s.userRepo.Delete(ctx, userID)
}

// HashAPIKey computes SHA256 hash of an API key
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
