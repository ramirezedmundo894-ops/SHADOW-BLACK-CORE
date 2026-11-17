CREATE TABLE IF NOT EXISTS decision_event_projection (
    consumer_name TEXT NOT NULL CHECK (length(consumer_name) BETWEEN 1 AND 120),
    event_id UUID NOT NULL,
    request_id UUID NOT NULL,
    schema_version TEXT NOT NULL,
    payload JSONB NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer_name, event_id)
);
