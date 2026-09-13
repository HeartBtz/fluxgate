-- Download tokens are bearer credentials. Store only a prefixed digest; the
-- raw token returned at link creation continues to resolve through hashing.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
UPDATE download_links
SET token = 'sha256:' || encode(digest(token, 'sha256'), 'hex')
WHERE token NOT LIKE 'sha256:%';
