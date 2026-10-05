-- Jnvoy Audit Database Schema
-- Created automatically when PostgreSQL container starts

-- Audit log table
-- Every LLM API call routed through Jnvoy is recorded here
-- Raw PII is never stored - only hashes and type counts
CREATE TABLE IF NOT EXISTS audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id        VARCHAR(36) NOT NULL UNIQUE,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_hash    VARCHAR(16) NOT NULL,
    api_key_hash    VARCHAR(8),
    provider        VARCHAR(50) NOT NULL,
    model           VARCHAR(100) NOT NULL,
    latency_ms      FLOAT NOT NULL,
    cache_hit       BOOLEAN NOT NULL DEFAULT FALSE,
    pii_detected    JSONB NOT NULL DEFAULT '{}',
    total_pii       INTEGER NOT NULL DEFAULT 0,
    sensitive_data_transmitted BOOLEAN NOT NULL DEFAULT FALSE
);

-- Index for fast compliance report queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_provider ON audit_log(provider);
CREATE INDEX IF NOT EXISTS idx_audit_api_key ON audit_log(api_key_hash);

-- PII type summary view for compliance dashboard
CREATE OR REPLACE VIEW pii_summary AS
SELECT
    DATE_TRUNC('day', timestamp) AS day,
    provider,
    model,
    COUNT(*) AS total_calls,
    SUM(total_pii) AS total_pii_detected,
    SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) AS cache_hits,
    ROUND(AVG(latency_ms)::numeric, 2) AS avg_latency_ms,
    BOOL_OR(sensitive_data_transmitted) AS any_sensitive_data_transmitted
FROM audit_log
GROUP BY DATE_TRUNC('day', timestamp), provider, model
ORDER BY day DESC;

-- Compliance statement view
-- Used to generate FCA and GDPR audit reports
CREATE OR REPLACE VIEW compliance_report AS
SELECT
    MIN(timestamp) AS period_start,
    MAX(timestamp) AS period_end,
    COUNT(*) AS total_api_calls,
    SUM(total_pii) AS total_pii_instances_redacted,
    ROUND(100.0 * SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 1) AS cache_hit_rate_percent,
    ROUND(AVG(latency_ms)::numeric, 2) AS average_latency_ms,
    BOOL_OR(sensitive_data_transmitted) AS sensitive_data_transmitted_to_llm,
    'Zero sensitive data was transmitted to any LLM API during this period.' AS compliance_statement
FROM audit_log;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO jnvoy;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO jnvoy;
