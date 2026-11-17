CREATE TABLE IF NOT EXISTS decision_consumer_inbox (
    consumer_name TEXT NOT NULL CHECK (length(consumer_name) BETWEEN 1 AND 120),
    event_id UUID NOT NULL,
    request_id UUID NOT NULL,
    schema_version TEXT NOT NULL,
    payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer_name, event_id)
);
