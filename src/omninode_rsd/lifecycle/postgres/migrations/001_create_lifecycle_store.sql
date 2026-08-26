CREATE SCHEMA rsd_canary;

CREATE TABLE rsd_canary.schema_migrations (
    version BIGINT PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9_]*$'),
    checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE rsd_canary.lifecycle_events (
    event_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL CHECK (
        event_type IN ('RUN_CREATED', 'WORK_STARTED', 'WORK_COMPLETED', 'WORK_FAILED')
    ),
    detail TEXT NOT NULL CHECK (char_length(detail) BETWEEN 1 AND 1000),
    prior_event_hash TEXT NOT NULL CHECK (prior_event_hash ~ '^[0-9a-f]{64}$'),
    event_hash TEXT NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    event_json JSONB NOT NULL CHECK (
        (jsonb_typeof(event_json) = 'object') IS TRUE
        AND event_json ?& ARRAY[
            'schema_version', 'event_id', 'run_id', 'sequence', 'occurred_at',
            'event_type', 'detail', 'prior_event_hash', 'event_hash'
        ]
        AND event_json - ARRAY[
            'schema_version', 'event_id', 'run_id', 'sequence', 'occurred_at',
            'event_type', 'detail', 'prior_event_hash', 'event_hash'
        ] = '{}'::JSONB
        AND (jsonb_typeof(event_json -> 'schema_version') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'event_id') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'run_id') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'sequence') = 'number') IS TRUE
        AND (jsonb_typeof(event_json -> 'occurred_at') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'event_type') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'detail') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'prior_event_hash') = 'string') IS TRUE
        AND (jsonb_typeof(event_json -> 'event_hash') = 'string') IS TRUE
        AND (event_json ->> 'schema_version' = 'rsd.lifecycle-event.v1') IS TRUE
        AND (event_json ->> 'event_id' = event_id::TEXT) IS TRUE
        AND (event_json ->> 'run_id' = run_id::TEXT) IS TRUE
        AND (event_json ->> 'sequence' = sequence::TEXT) IS TRUE
        AND (
            event_json ->> 'occurred_at' = to_char(
                occurred_at AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'
            )
        ) IS TRUE
        AND (event_json ->> 'event_type' = event_type) IS TRUE
        AND (event_json ->> 'detail' = detail) IS TRUE
        AND (event_json ->> 'prior_event_hash' = prior_event_hash) IS TRUE
        AND (event_json ->> 'event_hash' = event_hash) IS TRUE
    ),
    CONSTRAINT lifecycle_events_run_sequence_key UNIQUE (run_id, sequence),
    CONSTRAINT lifecycle_events_run_sequence_hash_key UNIQUE (run_id, sequence, event_hash)
);

CREATE TABLE rsd_canary.lifecycle_run_heads (
    run_id UUID PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('INITIAL', 'CREATED', 'ACTIVE', 'COMPLETED', 'FAILED')),
    last_sequence BIGINT NOT NULL CHECK (last_sequence >= 0),
    last_event_hash TEXT NOT NULL CHECK (last_event_hash ~ '^[0-9a-f]{64}$'),
    event_stream_hash TEXT NOT NULL CHECK (event_stream_hash ~ '^[0-9a-f]{64}$'),
    projection_checksum TEXT NOT NULL CHECK (projection_checksum ~ '^[0-9a-f]{64}$'),
    projection_json JSONB NOT NULL CHECK (
        (jsonb_typeof(projection_json) = 'object') IS TRUE
        AND projection_json ?& ARRAY[
            'schema_version', 'run_id', 'state', 'last_sequence', 'last_event_hash',
            'event_stream_hash', 'projection_checksum'
        ]
        AND projection_json - ARRAY[
            'schema_version', 'run_id', 'state', 'last_sequence', 'last_event_hash',
            'event_stream_hash', 'projection_checksum'
        ] = '{}'::JSONB
        AND (jsonb_typeof(projection_json -> 'schema_version') = 'string') IS TRUE
        AND (jsonb_typeof(projection_json -> 'run_id') = 'string') IS TRUE
        AND (jsonb_typeof(projection_json -> 'state') = 'string') IS TRUE
        AND (jsonb_typeof(projection_json -> 'last_sequence') = 'number') IS TRUE
        AND (jsonb_typeof(projection_json -> 'last_event_hash') = 'string') IS TRUE
        AND (jsonb_typeof(projection_json -> 'event_stream_hash') = 'string') IS TRUE
        AND (jsonb_typeof(projection_json -> 'projection_checksum') = 'string') IS TRUE
        AND (projection_json ->> 'schema_version' = 'rsd.lifecycle-projection.v1') IS TRUE
        AND (projection_json ->> 'run_id' = run_id::TEXT) IS TRUE
        AND (projection_json ->> 'state' = state) IS TRUE
        AND (projection_json ->> 'last_sequence' = last_sequence::TEXT) IS TRUE
        AND (projection_json ->> 'last_event_hash' = last_event_hash) IS TRUE
        AND (projection_json ->> 'event_stream_hash' = event_stream_hash) IS TRUE
        AND (projection_json ->> 'projection_checksum' = projection_checksum) IS TRUE
    ),
    CONSTRAINT lifecycle_run_heads_last_event_key FOREIGN KEY (
        run_id, last_sequence, last_event_hash
    ) REFERENCES rsd_canary.lifecycle_events (run_id, sequence, event_hash)
);

CREATE INDEX lifecycle_events_run_sequence_order_idx
    ON rsd_canary.lifecycle_events (run_id, sequence ASC);

CREATE FUNCTION rsd_canary.reject_lifecycle_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'lifecycle events are append-only';
END;
$$;

CREATE TRIGGER lifecycle_events_append_only
BEFORE UPDATE OR DELETE ON rsd_canary.lifecycle_events
FOR EACH ROW
EXECUTE FUNCTION rsd_canary.reject_lifecycle_event_mutation();

CREATE TRIGGER lifecycle_events_no_truncate
BEFORE TRUNCATE ON rsd_canary.lifecycle_events
FOR EACH STATEMENT
EXECUTE FUNCTION rsd_canary.reject_lifecycle_event_mutation();

REVOKE ALL ON SCHEMA rsd_canary FROM PUBLIC;
REVOKE ALL ON TABLE rsd_canary.schema_migrations FROM PUBLIC;
REVOKE ALL ON TABLE rsd_canary.lifecycle_events FROM PUBLIC;
REVOKE ALL ON TABLE rsd_canary.lifecycle_run_heads FROM PUBLIC;
REVOKE ALL ON FUNCTION rsd_canary.reject_lifecycle_event_mutation() FROM PUBLIC;
