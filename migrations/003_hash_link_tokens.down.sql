-- Irreversible by design: plaintext bearer tokens cannot be recovered from
-- their digest. Restore the pre-migration database backup for a full rollback.
SELECT 1;
