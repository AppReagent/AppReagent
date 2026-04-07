CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS llm_calls (
    id          BIGSERIAL PRIMARY KEY,
    run_id      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    file_hash   TEXT NOT NULL DEFAULT '',
    node_name   TEXT NOT NULL,
    tier        INTEGER NOT NULL DEFAULT 0,
    prompt      TEXT NOT NULL DEFAULT '',
    prompt_hash TEXT NOT NULL DEFAULT '',
    response    TEXT NOT NULL DEFAULT '',
    latency_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_llm_calls_run ON llm_calls (run_id);
CREATE INDEX IF NOT EXISTS idx_llm_calls_prompt_hash ON llm_calls (run_id, prompt_hash);

CREATE TABLE IF NOT EXISTS scan_results (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_hash       TEXT NOT NULL DEFAULT '',
    risk_profile    JSONB NOT NULL DEFAULT '{}',
    recommendation  TEXT NOT NULL DEFAULT '',
    risk_score      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_results_run ON scan_results (run_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_hash ON scan_results (run_id, file_hash);

CREATE TABLE IF NOT EXISTS method_embeddings (
    id          BIGSERIAL PRIMARY KEY,
    run_id      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    file_hash   TEXT NOT NULL DEFAULT '',
    class_name  TEXT NOT NULL DEFAULT '',
    method_name TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    embedding   vector(1536),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_method_embeddings_run ON method_embeddings (run_id);
CREATE INDEX IF NOT EXISTS idx_method_embeddings_hash ON method_embeddings (run_id, file_hash);

CREATE TABLE IF NOT EXISTS method_calls (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_hash       TEXT NOT NULL DEFAULT '',
    caller_class    TEXT NOT NULL DEFAULT '',
    caller_method   TEXT NOT NULL DEFAULT '',
    callee_class    TEXT NOT NULL DEFAULT '',
    callee_method   TEXT NOT NULL DEFAULT '',
    invoke_type     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_method_calls_run ON method_calls (run_id);
CREATE INDEX IF NOT EXISTS idx_method_calls_caller ON method_calls (run_id, caller_class, caller_method);
CREATE INDEX IF NOT EXISTS idx_method_calls_callee ON method_calls (run_id, callee_class, callee_method);

CREATE TABLE IF NOT EXISTS method_findings (
    id               BIGSERIAL PRIMARY KEY,
    run_id           TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    file_hash        TEXT NOT NULL DEFAULT '',
    class_name       TEXT NOT NULL DEFAULT '',
    method_name      TEXT NOT NULL DEFAULT '',
    api_calls        TEXT NOT NULL DEFAULT '',
    findings         TEXT NOT NULL DEFAULT '',
    reasoning        TEXT NOT NULL DEFAULT '',
    relevant         BOOLEAN NOT NULL DEFAULT false,
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 0,
    threat_category  TEXT NOT NULL DEFAULT 'none',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_method_findings_run ON method_findings (run_id);
CREATE INDEX IF NOT EXISTS idx_method_findings_class ON method_findings (run_id, class_name);

CREATE TABLE IF NOT EXISTS scan_files (
    id          BIGSERIAL PRIMARY KEY,
    run_id      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    file_hash   TEXT NOT NULL,
    file_size   BIGINT NOT NULL DEFAULT 0,
    contents    BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_files_run ON scan_files (run_id);
CREATE INDEX IF NOT EXISTS idx_scan_files_hash ON scan_files (run_id, file_hash);

-- Deduplicate: one copy of content per (run_id, file_hash)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_scan_files_unique'
    ) THEN
        CREATE UNIQUE INDEX idx_scan_files_unique ON scan_files (run_id, file_hash);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS analyze_results (
    id           BIGSERIAL PRIMARY KEY,
    run_id       TEXT NOT NULL,
    threat_level TEXT NOT NULL DEFAULT 'unknown',
    confidence   INTEGER NOT NULL DEFAULT 0,
    risk_score   INTEGER NOT NULL DEFAULT 0,
    summary      TEXT NOT NULL DEFAULT '',
    full_json    JSONB NOT NULL DEFAULT '{}',
    findings_count INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_analyze_results_run ON analyze_results (run_id);

-- Migration: add threat_category column for existing databases
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'method_findings' AND column_name = 'threat_category'
    ) THEN
        ALTER TABLE method_findings ADD COLUMN threat_category TEXT NOT NULL DEFAULT 'none';
    END IF;
END $$;
