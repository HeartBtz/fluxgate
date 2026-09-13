// Package domain contient les modèles métier, les DTOs (Data Transfer Objects)
// et les erreurs sentinelle de FluxGate.
//
// Les modèles définissent la structure des entités persistées en base de données :
// User, File, DownloadLink, DownloadLog, UploadSession, APIKey, AuditLog, SigningKey.
//
// Les DTOs définissent les structures de requête/réponse de l'API REST.
// Les erreurs sentinelle permettent une gestion d'erreurs typée dans toutes les couches.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// User représente un utilisateur de la plateforme.
// Chaque utilisateur possède un quota de stockage et peut être admin.
type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Role         string    `json:"role" db:"role"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	QuotaBytes   int64     `json:"quota_bytes" db:"quota_bytes"`
	UsedBytes    int64     `json:"used_bytes" db:"used_bytes"`
	MaxFileSize  int64     `json:"max_file_size" db:"max_file_size"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

func (u *User) QuotaRemaining() int64 {
	return u.QuotaBytes - u.UsedBytes
}

func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// File représente un fichier uploadé et stocké.
// Contient les métadonnées, le chemin de stockage et le hash SHA-256.
// Les champs de chiffrement sont conservés pour la compatibilité du schéma ;
// FluxGate ne chiffre pas les fichiers au niveau applicatif.
type File struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	OriginalName    string     `json:"original_name" db:"original_name"`
	StoredName      string     `json:"-" db:"stored_name"`
	StoragePath     string     `json:"-" db:"storage_path"`
	StorageBackend  string     `json:"storage_backend" db:"storage_backend"`
	MIMEType        string     `json:"mime_type" db:"mime_type"`
	SizeBytes       int64      `json:"size_bytes" db:"size_bytes"`
	SHA256          string     `json:"sha256" db:"sha256"`
	IsEncrypted     bool       `json:"is_encrypted" db:"is_encrypted"`
	EncryptionKeyID *string    `json:"-" db:"encryption_key_id"`
	UploadComplete  bool       `json:"upload_complete" db:"upload_complete"`
	DownloadCount   int64      `json:"download_count" db:"download_count"`
	IsDeleted       bool       `json:"is_deleted" db:"is_deleted"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	Metadata        JSONMap    `json:"metadata" db:"metadata"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// JSONMap is a helper type for JSONB columns
type JSONMap map[string]interface{}

// DownloadLink représente un lien de téléchargement pour un fichier.
// Trois types : public (libre), private (mot de passe), signed (HMAC).
// Chaque lien a un token unique, une expiration optionnelle et un compteur de DL.
type DownloadLink struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	FileID           uuid.UUID  `json:"file_id" db:"file_id"`
	UserID           uuid.UUID  `json:"user_id" db:"user_id"`
	Token            string     `json:"-" db:"token"`
	LinkType         string     `json:"link_type" db:"link_type"` // public, private, signed
	IsActive         bool       `json:"is_active" db:"is_active"`
	PasswordHash     *string    `json:"-" db:"password_hash"`
	MaxDownloads     *int       `json:"max_downloads,omitempty" db:"max_downloads"`
	CurrentDownloads int        `json:"current_downloads" db:"current_downloads"`
	AllowedIPs       []string   `json:"allowed_ips,omitempty" db:"allowed_ips"`
	ForcedFilename   *string    `json:"forced_filename,omitempty" db:"forced_filename"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// IsExpired checks if the link has expired
func (dl *DownloadLink) IsExpired() bool {
	if dl.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*dl.ExpiresAt)
}

// IsExhausted checks if download limit is reached
func (dl *DownloadLink) IsExhausted() bool {
	if dl.MaxDownloads == nil {
		return false
	}
	return dl.CurrentDownloads >= *dl.MaxDownloads
}

// IsRevoked checks if the link was revoked
func (dl *DownloadLink) IsRevoked() bool {
	return dl.RevokedAt != nil
}

// IsUsable checks if the link can be used for download
func (dl *DownloadLink) IsUsable() bool {
	return dl.IsActive && !dl.IsExpired() && !dl.IsExhausted() && !dl.IsRevoked()
}

// DownloadLog représente une entrée de log d'audit de téléchargement.
// Enregistre l'IP, le user agent, les octets envoyés et si le DL est complet.
type DownloadLog struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	FileID      uuid.UUID  `json:"file_id" db:"file_id"`
	LinkID      *uuid.UUID `json:"link_id,omitempty" db:"link_id"`
	IPAddress   string     `json:"ip_address" db:"ip_address"`
	UserAgent   string     `json:"user_agent" db:"user_agent"`
	Referer     string     `json:"referer" db:"referer"`
	BytesSent   int64      `json:"bytes_sent" db:"bytes_sent"`
	IsComplete  bool       `json:"is_complete" db:"is_complete"`
	IsResumed   bool       `json:"is_resumed" db:"is_resumed"`
	StartedAt   time.Time  `json:"started_at" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// UploadSession représente une session d'upload par morceaux (chunked/resumable).
// Permet de reprendre un upload interrompu et de suivre sa progression.
type UploadSession struct {
	ID            uuid.UUID `json:"id" db:"id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`
	Filename      string    `json:"filename" db:"filename"`
	TotalSize     int64     `json:"total_size" db:"total_size"`
	UploadedBytes int64     `json:"uploaded_bytes" db:"uploaded_bytes"`
	ChunkSize     int       `json:"chunk_size" db:"chunk_size"`
	MIMEType      string    `json:"mime_type" db:"mime_type"`
	StoragePath   string    `json:"-" db:"storage_path"`
	Status        string    `json:"status" db:"status"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	ExpiresAt     time.Time `json:"expires_at" db:"expires_at"`
}

// APIKey représente une clé API utilisateur.
// La clé brute n'est jamais stockée — seul son hash SHA-256 est persisté.
// Le préfixe (ex: "fg_abc12...") permet l'identification sans révéler la clé.
type APIKey struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	Name       string     `json:"name" db:"name"`
	KeyHash    string     `json:"-" db:"key_hash"`
	KeyPrefix  string     `json:"key_prefix" db:"key_prefix"`
	Scopes     []string   `json:"scopes" db:"scopes"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Action       string     `json:"action" db:"action"`
	ResourceType string     `json:"resource_type" db:"resource_type"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty" db:"resource_id"`
	IPAddress    string     `json:"ip_address" db:"ip_address"`
	UserAgent    string     `json:"user_agent" db:"user_agent"`
	Details      JSONMap    `json:"details" db:"details"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// SigningKey for URL signature verification
type SigningKey struct {
	ID          string     `json:"id" db:"id"`
	Algorithm   string     `json:"algorithm" db:"algorithm"`
	KeyMaterial []byte     `json:"-" db:"key_material"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty" db:"rotated_at"`
}
