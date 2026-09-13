-- FluxGate: Initial database schema
-- PostgreSQL 16+

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(255) NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            VARCHAR(50) NOT NULL DEFAULT 'user',  -- 'admin', 'user'
    is_active       BOOLEAN NOT NULL DEFAULT true,
    quota_bytes     BIGINT NOT NULL DEFAULT 10737418240,   -- 10 GB default
    used_bytes      BIGINT NOT NULL DEFAULT 0,
    max_file_size   BIGINT NOT NULL DEFAULT 5368709120,    -- 5 GB default
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- ============================================================
-- API KEYS
-- ============================================================
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    key_hash        TEXT NOT NULL,           -- SHA256 of the key
    key_prefix      VARCHAR(12) NOT NULL,    -- First 8 chars for identification
    scopes          TEXT[] NOT NULL DEFAULT '{"upload","download","manage"}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- ============================================================
-- FILES
-- ============================================================
CREATE TABLE files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name   VARCHAR(1024) NOT NULL,
    stored_name     VARCHAR(512) NOT NULL,        -- Internal storage name
    storage_path    TEXT NOT NULL,                 -- Full path in storage backend
    storage_backend VARCHAR(50) NOT NULL DEFAULT 'local',  -- 'local', 's3'
    mime_type       VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
    size_bytes      BIGINT NOT NULL,
    sha256          VARCHAR(64) NOT NULL,
    is_encrypted    BOOLEAN NOT NULL DEFAULT false,
    encryption_key_id VARCHAR(255),               -- Reference to key for decryption
    upload_complete BOOLEAN NOT NULL DEFAULT false,
    download_count  BIGINT NOT NULL DEFAULT 0,
    is_deleted      BOOLEAN NOT NULL DEFAULT false, -- Soft delete
    deleted_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,                    -- Auto-expiration
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_user_id ON files(user_id);
CREATE INDEX idx_files_sha256 ON files(sha256);
CREATE INDEX idx_files_storage_path ON files(storage_path);
CREATE INDEX idx_files_expires_at ON files(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_files_is_deleted ON files(is_deleted) WHERE is_deleted = false;
CREATE INDEX idx_files_created_at ON files(created_at);

-- ============================================================
-- DOWNLOAD LINKS
-- ============================================================
CREATE TABLE download_links (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id             UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token               VARCHAR(128) NOT NULL UNIQUE,  -- Unique download token
    link_type           VARCHAR(20) NOT NULL DEFAULT 'public',  -- 'public', 'private', 'signed'
    is_active           BOOLEAN NOT NULL DEFAULT true,
    password_hash       TEXT,                           -- Optional password protection
    max_downloads       INTEGER,                        -- NULL = unlimited
    current_downloads   INTEGER NOT NULL DEFAULT 0,
    allowed_ips         INET[],                         -- IP restriction
    forced_filename     VARCHAR(1024),                  -- Override download filename
    expires_at          TIMESTAMPTZ,                    -- Link expiration
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX idx_download_links_token ON download_links(token);
CREATE INDEX idx_download_links_file_id ON download_links(file_id);
CREATE INDEX idx_download_links_user_id ON download_links(user_id);
CREATE INDEX idx_download_links_expires ON download_links(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================
-- DOWNLOAD LOG (AUDIT)
-- ============================================================
CREATE TABLE download_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    link_id         UUID REFERENCES download_links(id) ON DELETE SET NULL,
    ip_address      INET NOT NULL,
    user_agent      TEXT,
    referer         TEXT,
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    is_complete     BOOLEAN NOT NULL DEFAULT false,
    is_resumed      BOOLEAN NOT NULL DEFAULT false,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_download_logs_file_id ON download_logs(file_id);
CREATE INDEX idx_download_logs_started_at ON download_logs(started_at);

-- ============================================================
-- UPLOAD SESSIONS (resumable uploads)
-- ============================================================
CREATE TABLE upload_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename        VARCHAR(1024) NOT NULL,
    total_size      BIGINT NOT NULL,
    uploaded_bytes  BIGINT NOT NULL DEFAULT 0,
    chunk_size      INTEGER NOT NULL DEFAULT 5242880,    -- 5 MB
    mime_type       VARCHAR(255),
    storage_path    TEXT NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'uploading', 'complete', 'failed'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE INDEX idx_upload_sessions_user_id ON upload_sessions(user_id);
CREATE INDEX idx_upload_sessions_status ON upload_sessions(status);

-- ============================================================
-- AUDIT LOG
-- ============================================================
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     UUID,
    ip_address      INET,
    user_agent      TEXT,
    details         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- ============================================================
-- SIGNING KEYS (for URL signing key rotation)
-- ============================================================
CREATE TABLE signing_keys (
    id              VARCHAR(255) PRIMARY KEY,
    algorithm       VARCHAR(50) NOT NULL DEFAULT 'hmac-sha256',
    key_material    BYTEA NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at      TIMESTAMPTZ
);

-- ============================================================
-- DEFAULT ADMIN USER (password: changeme)
-- The hash will be generated by the application on first run
-- ============================================================

-- ============================================================
-- FUNCTIONS
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_files_updated_at BEFORE UPDATE ON files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_upload_sessions_updated_at BEFORE UPDATE ON upload_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
