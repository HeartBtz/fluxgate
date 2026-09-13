-- Indexes for the hot dashboard, link-validation and cleanup paths.
CREATE INDEX IF NOT EXISTS idx_files_user_active_created
    ON files (user_id, created_at DESC) WHERE is_deleted = false;

CREATE INDEX IF NOT EXISTS idx_download_links_file_active
    ON download_links (file_id) WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_upload_sessions_expired_active
    ON upload_sessions (expires_at) WHERE status <> 'complete';
