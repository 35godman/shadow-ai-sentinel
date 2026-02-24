-- ============================================================
-- Shadow AI Sentinel — Database Schema
-- PostgreSQL 16+
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ORGANIZATIONS
-- ============================================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'professional', 'enterprise')),
    api_key VARCHAR(64) NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'hex'),
    settings JSONB NOT NULL DEFAULT '{
        "defaultAction": "WARN",
        "learningMode": true,
        "enabledDetectors": [],
        "allowedAiTools": [],
        "blockedAiTools": [],
        "emailAlerts": []
    }'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- USERS
-- ============================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    department VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user', 'viewer')),
    password_hash VARCHAR(255), -- NULL for SSO users
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, email)
);

CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- ============================================================
-- POLICY RULES
-- ============================================================

CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
    action VARCHAR(50) NOT NULL CHECK (action IN ('LOG', 'WARN', 'REDACT', 'BLOCK')),
    notify_admin BOOLEAN NOT NULL DEFAULT false,
    notify_user BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_rules_org_id ON policy_rules(org_id);
CREATE INDEX idx_policy_rules_priority ON policy_rules(org_id, priority);

-- ============================================================
-- AUDIT EVENTS
-- Core audit log — append-only, never modified
-- Sensitive data is NEVER stored here, only metadata
-- ============================================================

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('scan', 'block', 'redact', 'warn', 'shadow_ai', 'policy_change', 'login')),
    ai_tool VARCHAR(255),
    entity_types_detected TEXT[] NOT NULL DEFAULT '{}',
    sensitivity_level VARCHAR(50) NOT NULL DEFAULT 'LOW' CHECK (sensitivity_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    action_taken VARCHAR(50) NOT NULL CHECK (action_taken IN ('LOG', 'WARN', 'REDACT', 'BLOCK')),
    policy_id UUID REFERENCES policy_rules(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition by month for performance (audit events grow fast)
-- In production, convert to partitioned table

CREATE INDEX idx_audit_events_org_time ON audit_events(org_id, created_at DESC);
CREATE INDEX idx_audit_events_user ON audit_events(user_id, created_at DESC);
CREATE INDEX idx_audit_events_type ON audit_events(event_type, created_at DESC);
CREATE INDEX idx_audit_events_sensitivity ON audit_events(org_id, sensitivity_level, created_at DESC);
CREATE INDEX idx_audit_events_ai_tool ON audit_events(org_id, ai_tool, created_at DESC);

-- ============================================================
-- SHADOW AI EVENTS
-- Tracks visits to AI tools (separate from audit for performance)
-- ============================================================

CREATE TABLE shadow_ai_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    domain VARCHAR(255) NOT NULL,
    ai_tool_name VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    risk_level VARCHAR(50) CHECK (risk_level IN ('SAFE', 'CAUTION', 'RISKY', 'BLOCKED')),
    action VARCHAR(50) NOT NULL CHECK (action IN ('visited', 'prompted', 'uploaded', 'api_call')),
    duration_seconds INTEGER,
    estimated_tokens INTEGER,
    browser_meta JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shadow_ai_org_time ON shadow_ai_events(org_id, created_at DESC);
CREATE INDEX idx_shadow_ai_domain ON shadow_ai_events(org_id, domain, created_at DESC);
CREATE INDEX idx_shadow_ai_user ON shadow_ai_events(user_id, created_at DESC);

-- ============================================================
-- SESSION REDACTION MAPPING
-- Stores PII <-> Placeholder mappings for re-identification
-- Auto-expires after session ends (TTL managed by Redis, this is backup)
-- ============================================================

CREATE TABLE redaction_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    request_id UUID NOT NULL UNIQUE,
    mappings JSONB NOT NULL, -- Encrypted: {"[PERSON_1]": "John Doe", "[SSN_REDACTED]": "078-05-1120"}
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_redaction_sessions_request ON redaction_sessions(request_id);
CREATE INDEX idx_redaction_sessions_expires ON redaction_sessions(expires_at);

-- Auto-cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM redaction_sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- DASHBOARD ANALYTICS MATERIALIZED VIEWS
-- Refreshed periodically for dashboard performance
-- ============================================================

-- User risk scores
CREATE MATERIALIZED VIEW mv_user_risk_scores AS
SELECT
    u.id AS user_id,
    u.email,
    u.department,
    u.org_id,
    COUNT(ae.id) AS total_events,
    COUNT(CASE WHEN ae.sensitivity_level = 'CRITICAL' THEN 1 END) AS critical_events,
    COUNT(CASE WHEN ae.sensitivity_level = 'HIGH' THEN 1 END) AS high_events,
    COUNT(CASE WHEN ae.sensitivity_level = 'MEDIUM' THEN 1 END) AS medium_events,
    -- Composite risk score: weighted sum
    COALESCE(
        (COUNT(CASE WHEN ae.sensitivity_level = 'CRITICAL' THEN 1 END) * 40 +
         COUNT(CASE WHEN ae.sensitivity_level = 'HIGH' THEN 1 END) * 20 +
         COUNT(CASE WHEN ae.sensitivity_level = 'MEDIUM' THEN 1 END) * 5 +
         COUNT(CASE WHEN ae.sensitivity_level = 'LOW' THEN 1 END) * 1)::numeric /
        GREATEST(1, EXTRACT(EPOCH FROM (NOW() - MIN(ae.created_at))) / 86400)::numeric, -- Normalize by days active
    0) AS composite_risk_score,
    MAX(ae.created_at) AS last_event_at
FROM users u
LEFT JOIN audit_events ae ON ae.user_id = u.id
    AND ae.created_at > NOW() - INTERVAL '30 days'
GROUP BY u.id, u.email, u.department, u.org_id;

CREATE UNIQUE INDEX idx_mv_user_risk ON mv_user_risk_scores(user_id);

-- Department summaries
CREATE MATERIALIZED VIEW mv_department_risk AS
SELECT
    u.org_id,
    COALESCE(u.department, 'Unknown') AS department,
    COUNT(DISTINCT u.id) AS user_count,
    COUNT(ae.id) AS total_events,
    COUNT(CASE WHEN ae.sensitivity_level = 'CRITICAL' THEN 1 END) AS critical_count,
    COUNT(CASE WHEN ae.sensitivity_level = 'HIGH' THEN 1 END) AS high_count,
    COUNT(CASE WHEN ae.sensitivity_level = 'MEDIUM' THEN 1 END) AS medium_count,
    COUNT(CASE WHEN ae.sensitivity_level = 'LOW' THEN 1 END) AS low_count
FROM users u
LEFT JOIN audit_events ae ON ae.user_id = u.id
    AND ae.created_at > NOW() - INTERVAL '30 days'
GROUP BY u.org_id, COALESCE(u.department, 'Unknown');

CREATE UNIQUE INDEX idx_mv_dept_risk ON mv_department_risk(org_id, department);

-- ============================================================
-- SEED DATA (Development only)
-- ============================================================

-- Default organization for local development
INSERT INTO organizations (id, name, plan, api_key, settings) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Development Org',
    'professional',
    'dev-api-key-12345678901234567890123456789012',
    '{
        "defaultAction": "WARN",
        "learningMode": true,
        "enabledDetectors": ["SSN", "CREDIT_CARD", "API_KEY", "AWS_KEY", "EMAIL", "PHONE", "MEDICAL_ID", "CREDENTIALS", "SOURCE_CODE"],
        "allowedAiTools": [],
        "blockedAiTools": [],
        "emailAlerts": ["admin@example.com"]
    }'::jsonb
);

-- Default admin user
INSERT INTO users (id, org_id, email, name, department, role) VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'admin@example.com',
    'Admin User',
    'Engineering',
    'admin'
);
