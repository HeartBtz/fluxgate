package domain

// --- Request / Response DTOs ---

// AuthLoginRequest for user login
type AuthLoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// AuthLoginResponse after successful login
type AuthLoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
	User         *User  `json:"user"`
}

// CreateUserRequest for user registration
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role,omitempty"`
}

// CreateAPIKeyRequest for creating a new API key
type CreateAPIKeyRequest struct {
	Name   string   `json:"name" validate:"required"`
	Scopes []string `json:"scopes,omitempty"`
}

// CreateAPIKeyResponse returned after key creation (only time raw key is shown)
type CreateAPIKeyResponse struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Key    string   `json:"key"` // Raw key, shown only once
	Prefix string   `json:"prefix"`
	Scopes []string `json:"scopes"`
}

// CreateLinkRequest for generating a download link
type CreateLinkRequest struct {
	FileID         string   `json:"file_id" validate:"required,uuid"`
	LinkType       string   `json:"link_type,omitempty"` // public, private, signed
	Password       string   `json:"password,omitempty"`
	MaxDownloads   *int     `json:"max_downloads,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	ForcedFilename string   `json:"forced_filename,omitempty"`
	ExpiresIn      string   `json:"expires_in,omitempty"` // duration string: "24h", "7d"
}

// CreateLinkResponse after link creation
type CreateLinkResponse struct {
	ID        string  `json:"id"`
	URL       string  `json:"url"`
	DirectURL string  `json:"direct_url"`
	SignedURL string  `json:"signed_url,omitempty"`
	Token     string  `json:"token"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	LinkType  string  `json:"link_type"`
}

// FileInfoResponse for file details
type FileInfoResponse struct {
	ID            string  `json:"id"`
	OriginalName  string  `json:"original_name"`
	MIMEType      string  `json:"mime_type"`
	SizeBytes     int64   `json:"size_bytes"`
	SHA256        string  `json:"sha256"`
	DownloadCount int64   `json:"download_count"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	Links         int     `json:"links_count"`
}

// FileListResponse for paginated file listing
type FileListResponse struct {
	Files      []FileInfoResponse `json:"files"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PerPage    int                `json:"per_page"`
	TotalPages int                `json:"total_pages"`
}

// QuotaResponse for user quota info
type QuotaResponse struct {
	QuotaBytes     int64   `json:"quota_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	RemainingBytes int64   `json:"remaining_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	MaxFileSize    int64   `json:"max_file_size"`
	FileCount      int64   `json:"file_count"`
}

// UploadInitRequest to start a resumable upload
type UploadInitRequest struct {
	Filename  string `json:"filename" validate:"required"`
	TotalSize int64  `json:"total_size" validate:"required,gt=0"`
	ChunkSize int    `json:"chunk_size,omitempty"`
	MIMEType  string `json:"mime_type,omitempty"`
}

// UploadInitResponse after starting resumable upload
type UploadInitResponse struct {
	SessionID string `json:"session_id"`
	ChunkSize int    `json:"chunk_size"`
	UploadURL string `json:"upload_url"`
}

// UploadStatusResponse for checking upload progress
type UploadStatusResponse struct {
	SessionID     string  `json:"session_id"`
	Filename      string  `json:"filename"`
	UploadedBytes int64   `json:"uploaded_bytes"`
	TotalSize     int64   `json:"total_size"`
	ChunkSize     int     `json:"chunk_size"`
	Status        string  `json:"status"`
	Progress      float64 `json:"progress"`
}

// ErrorResponse for API errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}
