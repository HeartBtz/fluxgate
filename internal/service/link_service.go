package service

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/HeartBtz/fluxgate/internal/config"
	fluxcrypto "github.com/HeartBtz/fluxgate/internal/crypto"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/HeartBtz/fluxgate/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// LinkService gère les liens de téléchargement : création (public/privé/signé),
// validation (expiration, quotas, mot de passe, signature HMAC),
// incrémentation du compteur de DL et révocation.
type LinkService struct {
	linkRepo *repository.LinkRepository
	fileRepo *repository.FileRepository
	signer   *fluxcrypto.URLSigner
	cfg      *config.Config
}

// NewLinkService crée un nouveau service de gestion de liens.
func NewLinkService(
	linkRepo *repository.LinkRepository,
	fileRepo *repository.FileRepository,
	signer *fluxcrypto.URLSigner,
	cfg *config.Config,
) *LinkService {
	return &LinkService{
		linkRepo: linkRepo,
		fileRepo: fileRepo,
		signer:   signer,
		cfg:      cfg,
	}
}

// CreateLink generates a download link for a file
func (s *LinkService) CreateLink(ctx context.Context, userID uuid.UUID, req domain.CreateLinkRequest) (*domain.CreateLinkResponse, error) {
	fileID, err := uuid.Parse(req.FileID)
	if err != nil {
		return nil, domain.ErrInvalidInput
	}

	// Verify file exists and belongs to user
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, domain.ErrForbidden
	}

	if file.IsDeleted {
		return nil, domain.ErrFileDeleted
	}

	if !file.UploadComplete {
		return nil, domain.ErrUploadIncomplete
	}

	// Generate token
	token, err := fluxcrypto.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	linkType := "public"
	if req.LinkType != "" {
		linkType = req.LinkType
	}
	if linkType != "public" && linkType != "private" && linkType != "signed" {
		return nil, domain.ErrInvalidLinkType
	}
	if linkType == "private" && req.Password == "" {
		return nil, domain.ErrPasswordRequired
	}
	if req.Password != "" && (len(req.Password) < 8 || len(req.Password) > 72) {
		return nil, domain.ErrPasswordWeak
	}
	if req.MaxDownloads != nil && (*req.MaxDownloads <= 0 || *req.MaxDownloads > math.MaxInt32) {
		return nil, domain.ErrInvalidInput
	}

	link := &domain.DownloadLink{
		ID:       uuid.New(),
		FileID:   fileID,
		UserID:   userID,
		Token:    token,
		LinkType: linkType,
		IsActive: true,
	}

	// Password protection
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashStr := string(hash)
		link.PasswordHash = &hashStr
	}

	// Max downloads
	if req.MaxDownloads != nil && *req.MaxDownloads > 0 {
		link.MaxDownloads = req.MaxDownloads
	}

	// IP restrictions
	if len(req.AllowedIPs) > 0 {
		link.AllowedIPs = make([]string, 0, len(req.AllowedIPs))
		for _, rawIP := range req.AllowedIPs {
			parsed := net.ParseIP(strings.TrimSpace(rawIP))
			if parsed == nil {
				return nil, domain.ErrInvalidInput
			}
			link.AllowedIPs = append(link.AllowedIPs, parsed.String())
		}
	}

	// Forced filename
	if req.ForcedFilename != "" {
		fn := fluxcrypto.SanitizeFilename(req.ForcedFilename)
		link.ForcedFilename = &fn
	}

	// Expiration
	if req.ExpiresIn != "" {
		duration, err := parseDuration(req.ExpiresIn)
		if err != nil {
			return nil, domain.ErrInvalidExpiration
		}
		if duration <= 0 {
			return nil, domain.ErrInvalidExpiration
		}
		if duration > s.cfg.Signing.MaxExpiry {
			duration = s.cfg.Signing.MaxExpiry
		}
		expiresAt := time.Now().Add(duration)
		link.ExpiresAt = &expiresAt
	}
	if linkType == "signed" && link.ExpiresAt == nil {
		expiresAt := time.Now().Add(s.cfg.Signing.DefaultExpiry)
		link.ExpiresAt = &expiresAt
	}

	if err := s.linkRepo.Create(ctx, link); err != nil {
		return nil, fmt.Errorf("failed to create link: %w", err)
	}

	// Build URLs
	baseURL := strings.TrimRight(s.cfg.Server.BaseURL, "/")
	directURL := fmt.Sprintf("%s/d/%s/%s", baseURL, token, url.PathEscape(file.OriginalName))

	response := &domain.CreateLinkResponse{
		ID:        link.ID.String(),
		URL:       directURL,
		DirectURL: directURL,
		Token:     token,
		LinkType:  linkType,
	}

	if link.ExpiresAt != nil {
		expiresStr := link.ExpiresAt.Format(time.RFC3339)
		response.ExpiresAt = &expiresStr
	}

	// Generate signed URL if requested
	if linkType == "signed" {
		expiresAt := time.Now().Add(s.cfg.Signing.DefaultExpiry)
		if link.ExpiresAt != nil {
			expiresAt = *link.ExpiresAt
		}

		maxDL := 0
		if link.MaxDownloads != nil {
			maxDL = *link.MaxDownloads
		}

		signedURL, err := s.signer.Sign(directURL, fluxcrypto.SignedURLParams{
			Token:     token,
			ExpiresAt: expiresAt,
			MaxDL:     maxDL,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to sign URL: %w", err)
		}
		response.SignedURL = signedURL
		response.DirectURL = signedURL
	}

	return response, nil
}

// ValidateDownload validates a download request against the link
func (s *LinkService) ValidateDownload(ctx context.Context, token string, clientIP string, password string, rawURL string) (*domain.DownloadLink, *domain.File, error) {
	link, err := s.linkRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	// Check link usability
	if !link.IsActive {
		return nil, nil, domain.ErrLinkInactive
	}

	if link.IsExpired() {
		return nil, nil, domain.ErrLinkExpired
	}

	if link.IsExhausted() {
		return nil, nil, domain.ErrLinkExhausted
	}

	if link.IsRevoked() {
		return nil, nil, domain.ErrLinkRevoked
	}
	if link.LinkType == "signed" {
		params, err := s.signer.Verify(rawURL, clientIP)
		if err != nil || params.Token != token {
			return nil, nil, domain.ErrInvalidSignature
		}
	}

	// Check IP restriction
	if len(link.AllowedIPs) > 0 {
		allowed := false
		cleanIP := extractIP(clientIP)
		for _, ip := range link.AllowedIPs {
			if net.ParseIP(ip) != nil && net.ParseIP(ip).Equal(net.ParseIP(cleanIP)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil, domain.ErrIPNotAllowed
		}
	}

	// Check password
	if link.PasswordHash != nil {
		if password == "" {
			return nil, nil, domain.ErrPasswordRequired
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*link.PasswordHash), []byte(password)); err != nil {
			return nil, nil, domain.ErrPasswordInvalid
		}
	}

	// Get file
	file, err := s.fileRepo.GetByID(ctx, link.FileID)
	if err != nil {
		return nil, nil, err
	}

	if file.IsDeleted {
		return nil, nil, domain.ErrFileDeleted
	}

	if !file.UploadComplete {
		return nil, nil, domain.ErrUploadIncomplete
	}

	// Check file expiration
	if file.ExpiresAt != nil && time.Now().After(*file.ExpiresAt) {
		return nil, nil, domain.ErrFileExpired
	}

	return link, file, nil
}

// RecordDownload increments counters
func (s *LinkService) ReserveDownload(ctx context.Context, linkID uuid.UUID) error {
	ok, err := s.linkRepo.ReserveDownload(ctx, linkID)
	if err != nil {
		return err
	}
	if !ok {
		return domain.ErrLinkExhausted
	}
	return nil
}

func (s *LinkService) RecordFileDownload(ctx context.Context, fileID uuid.UUID) {
	_ = s.fileRepo.IncrementDownloads(ctx, fileID)
}

func (s *LinkService) ReleaseDownload(ctx context.Context, linkID uuid.UUID) error {
	return s.linkRepo.ReleaseDownload(ctx, linkID)
}

// RevokeLink revokes a download link
func (s *LinkService) RevokeLink(ctx context.Context, linkID uuid.UUID, userID uuid.UUID) error {
	link, err := s.linkRepo.GetByID(ctx, linkID)
	if err != nil {
		return err
	}

	if link.UserID != userID {
		return domain.ErrForbidden
	}

	return s.linkRepo.Revoke(ctx, linkID)
}

// DeleteLink deletes a link
func (s *LinkService) DeleteLink(ctx context.Context, linkID uuid.UUID, userID uuid.UUID) error {
	link, err := s.linkRepo.GetByID(ctx, linkID)
	if err != nil {
		return err
	}

	if link.UserID != userID {
		return domain.ErrForbidden
	}

	return s.linkRepo.Delete(ctx, linkID)
}

// ListLinks returns links for a file
func (s *LinkService) ListLinks(ctx context.Context, fileID uuid.UUID, userID uuid.UUID) ([]*domain.DownloadLink, error) {
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, domain.ErrForbidden
	}

	return s.linkRepo.ListByFile(ctx, fileID)
}

// GetLinkCount returns the number of active links for a file
func (s *LinkService) GetLinkCount(ctx context.Context, fileID uuid.UUID) (int, error) {
	return s.linkRepo.CountByFile(ctx, fileID)
}

func (s *LinkService) GetLinkCounts(ctx context.Context, fileIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	return s.linkRepo.CountByFiles(ctx, fileIDs)
}

// --- helpers ---

func parseDuration(s string) (time.Duration, error) {
	// Support "7d" format in addition to standard durations
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		d, err := strconv.ParseInt(days, 10, 64)
		if err != nil || d <= 0 || d > math.MaxInt64/int64(24*time.Hour) {
			return 0, domain.ErrInvalidExpiration
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

func extractIP(addr string) string {
	if net.ParseIP(addr) != nil {
		return addr
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
