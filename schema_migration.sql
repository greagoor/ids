-- ============================================================
-- IDS → Agentic Defense Platform — Schema Migration
-- Run this ONCE in Supabase SQL Editor before starting backend.
-- Safe to re-run (uses IF NOT EXISTS / DO blocks for idempotency).
-- ============================================================

-- ── 2.1 ALTER existing `alerts` table ────────────────────────
-- Rename columns (only if the old name still exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'src_ip'
    ) THEN
        ALTER TABLE alerts RENAME COLUMN src_ip TO ip;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'uri'
    ) THEN
        ALTER TABLE alerts RENAME COLUMN uri TO url;
    END IF;
END $$;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_match TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ml_score FLOAT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS suspicion_score FLOAT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS shap_features JSONB;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS verdict TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS payload TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS payload_attack_type TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS alert_uuid UUID DEFAULT gen_random_uuid();

-- ── 2.2 ALTER existing `incidents` table ─────────────────────
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'incidents' AND column_name = 'src_ip'
    ) THEN
        ALTER TABLE incidents RENAME COLUMN src_ip TO ip;
    END IF;
END $$;

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_tags JSONB;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS kill_chain_phase TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS threat_score FLOAT;

-- ── 2.3 CREATE new tables ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    alert_id UUID,
    payload JSONB NOT NULL,
    priority TEXT DEFAULT 'MEDIUM',
    status TEXT DEFAULT 'PENDING',
    retry_count INT DEFAULT 0,
    failure_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_status (
    agent_name TEXT PRIMARY KEY,
    status TEXT DEFAULT 'IDLE',
    current_alert_id UUID,
    last_heartbeat TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    reasoning TEXT,
    metadata JSONB,
    timestamp TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID,
    analyst TEXT DEFAULT 'anonymous',
    verdict TEXT,
    notes TEXT,
    timestamp TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS blocklist_cache (
    ip TEXT PRIMARY KEY,
    source TEXT,
    score FLOAT,
    blocked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS model_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT now(),
    accuracy FLOAT,
    precision_score FLOAT,
    recall_score FLOAT,
    f1_score FLOAT,
    drift_detected BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS honeypot_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    headers JSONB,
    payload TEXT,
    timestamp TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS session_activity (
    ip TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ DEFAULT now(),
    req_count INT DEFAULT 0,
    endpoints_hit JSONB DEFAULT '[]',
    attack_types JSONB DEFAULT '[]',
    escalation_score FLOAT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS system_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component TEXT NOT NULL,
    status TEXT,
    details JSONB,
    timestamp TIMESTAMPTZ DEFAULT now()
);

-- ── 2.4 Enable Realtime ───────────────────────────────────────
-- NOTE: Also enable these tables in Supabase Dashboard →
--       Database → Replication → supabase_realtime publication.
-- The ALTER PUBLICATION command is shown here for reference but
-- may need to be run as superuser (paste in SQL Editor):

ALTER PUBLICATION supabase_realtime ADD TABLE alerts;
ALTER PUBLICATION supabase_realtime ADD TABLE incidents;
ALTER PUBLICATION supabase_realtime ADD TABLE agent_queue;
ALTER PUBLICATION supabase_realtime ADD TABLE agent_status;
ALTER PUBLICATION supabase_realtime ADD TABLE audit_log;
ALTER PUBLICATION supabase_realtime ADD TABLE honeypot_logs;

-- ── Done ─────────────────────────────────────────────────────
SELECT 'Schema migration complete' AS result;
