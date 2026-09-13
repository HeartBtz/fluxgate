package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/google/uuid"
)

// APIKeyService gère le cycle de vie des clés API :
// génération (préfixe fg_ + 32 octets aléatoires), hachage SHA-256,
// listage, révocation et suppression.
type APIKeyService struct {
	apiKeyRepo *repository.APIKeyRepository
}

// NewAPIKeyService crée un nouveau service de gestion de clés API.
func NewAPIKeyService(apiKeyRepo *repository.APIKeyRepository) *APIKeyService {
	return &APIKeyService{apiKeyRepo: apiKeyRepo}
}

// Create generates a new API key for a user
func (s *APIKeyService) Create(ctx context.Context, userID uuid.UUID, req domain.CreateAPIKeyRequest) (*domain.CreateAPIKeyResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		return nil, fmt.Errorf("invalid api key name")
	}
	// Generate key
	rawKey, prefix, hash, err := generateAPIKey()
	if err != nil {
		return nil, err
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"upload", "download", "manage"}
	}
	seen := make(map[string]struct{}, len(scopes))
	validated := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope != "upload" && scope != "download" && scope != "manage" {
			return nil, domain.ErrInvalidScope
		}
		if _, ok := seen[scope]; !ok {
			seen[scope] = struct{}{}
			validated = append(validated, scope)
		}
	}
	scopes = validated

	key := &domain.APIKey{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      name,
		KeyHash:   hash,
		KeyPrefix: prefix,
		Scopes:    scopes,
		IsActive:  true,
	}

	if err := s.apiKeyRepo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &domain.CreateAPIKeyResponse{
		ID:     key.ID.String(),
		Name:   key.Name,
		Key:    rawKey,
		Prefix: prefix,
		Scopes: scopes,
	}, nil
}

// List returns all API keys for a user
func (s *APIKeyService) List(ctx context.Context, userID uuid.UUID) ([]*domain.APIKey, error) {
	return s.apiKeyRepo.ListByUser(ctx, userID)
}

// Revoke deactivates an API key
func (s *APIKeyService) Revoke(ctx context.Context, keyID uuid.UUID, userID uuid.UUID) error {
	keys, err := s.apiKeyRepo.ListByUser(ctx, userID)
	if err != nil {
		return err
	}

	for _, k := range keys {
		if k.ID == keyID {
			return s.apiKeyRepo.Revoke(ctx, keyID)
		}
	}

	return domain.ErrForbidden
}

// Delete removes an API key
func (s *APIKeyService) Delete(ctx context.Context, keyID uuid.UUID, userID uuid.UUID) error {
	keys, err := s.apiKeyRepo.ListByUser(ctx, userID)
	if err != nil {
		return err
	}

	for _, k := range keys {
		if k.ID == keyID {
			return s.apiKeyRepo.Delete(ctx, keyID)
		}
	}

	return domain.ErrForbidden
}

func generateAPIKey() (key, prefix, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("failed to generate API key: %w", err)
	}

	key = "fg_" + base64.RawURLEncoding.EncodeToString(raw)
	prefix = key[:11]
	hash = HashAPIKey(key)

	return key, prefix, hash, nil
}
