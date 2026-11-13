CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_decisions (
    request_id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    request_fingerprint BYTEA NOT NULL,
    decision JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS decision_outbox (
    event_id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE REFERENCES risk_decisions(request_id) ON DELETE RESTRICT,
    schema_version TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS decision_outbox_pending_idx
    ON decision_outbox (created_at) WHERE published_at IS NULL;

INSERT INTO schema_migrations (version) VALUES ('001_decision_outbox') ON CONFLICT (version) DO NOTHING;
