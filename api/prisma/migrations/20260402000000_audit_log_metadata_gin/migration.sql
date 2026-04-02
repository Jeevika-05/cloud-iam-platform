CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_metadata_gin
ON "AuditLog" USING gin (metadata);
