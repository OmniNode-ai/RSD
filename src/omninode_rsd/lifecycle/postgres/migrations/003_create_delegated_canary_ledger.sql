CREATE TABLE rsd_canary.delegated_canary_attempts (
    run_id UUID PRIMARY KEY REFERENCES rsd_canary.lifecycle_run_heads (run_id),
    authorization_digest VARCHAR(64) NOT NULL UNIQUE REFERENCES rsd_canary.delegation_claims (authorization_digest),
    claim_binding_sha256 VARCHAR(64) NOT NULL CHECK (claim_binding_sha256 ~ '^[0-9a-f]{64}$'),
    attestation_id UUID NOT NULL,
    activation_id UUID NOT NULL,
    activation_schema_version VARCHAR(64) NOT NULL CHECK (activation_schema_version = 'rsd.delegation-execution-activation.v2'),
    activation_version SMALLINT NOT NULL CHECK (activation_version = 1),
    activation_sha256 VARCHAR(64) NOT NULL CHECK (activation_sha256 ~ '^[0-9a-f]{64}$'),
    activation_issued_at TIMESTAMPTZ NOT NULL,
    activation_expires_at TIMESTAMPTZ NOT NULL CHECK (activation_expires_at > activation_issued_at),
    request_envelope_sha256 VARCHAR(64) NOT NULL CHECK (request_envelope_sha256 ~ '^[0-9a-f]{64}$'),
    disabled_overlay_sha256 VARCHAR(64) NOT NULL CHECK (disabled_overlay_sha256 ~ '^[0-9a-f]{64}$'),
    backend_id VARCHAR(64) NOT NULL CHECK (backend_id ~ '^[a-z][a-z0-9-]{1,63}$'),
    model_id VARCHAR(128) NOT NULL CHECK (model_id ~ '^[a-z][a-z0-9._/-]{2,127}$'),
    route_ref_sha256 VARCHAR(64) NOT NULL CHECK (route_ref_sha256 ~ '^[0-9a-f]{64}$'),
    route_authority_sha256 VARCHAR(64) NOT NULL CHECK (route_authority_sha256 ~ '^[0-9a-f]{64}$'),
    route_policy_digest VARCHAR(64) NOT NULL CHECK (route_policy_digest ~ '^[0-9a-f]{64}$'),
    target_configuration_sha256 VARCHAR(64) NOT NULL CHECK (target_configuration_sha256 ~ '^[0-9a-f]{64}$'),
    endpoint_ref_sha256 VARCHAR(64) NOT NULL CHECK (endpoint_ref_sha256 ~ '^[0-9a-f]{64}$'),
    credential_ref_sha256 VARCHAR(64) NOT NULL CHECK (credential_ref_sha256 ~ '^[0-9a-f]{64}$'),
    activation_trust_anchor_fingerprint_sha256 VARCHAR(64) NOT NULL CHECK (activation_trust_anchor_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    route_authority_trust_anchor_fingerprint_sha256 VARCHAR(64) NOT NULL CHECK (route_authority_trust_anchor_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    credential_provider_id VARCHAR(64) NOT NULL CHECK (credential_provider_id ~ '^[a-z][a-z0-9-]{1,63}$'),
    credential_provider_fingerprint_sha256 VARCHAR(64) NOT NULL CHECK (credential_provider_fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    state VARCHAR(16) NOT NULL CHECK (state = 'prepared'),
    prepared_at TIMESTAMPTZ NOT NULL,
    UNIQUE (authorization_digest, attestation_id)
);

CREATE TABLE rsd_canary.delegated_canary_dispatches (
    authorization_digest VARCHAR(64) PRIMARY KEY,
    attestation_id UUID NOT NULL,
    state VARCHAR(32) NOT NULL CHECK (state = 'dispatch_started'),
    dispatch_started_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (authorization_digest, attestation_id)
        REFERENCES rsd_canary.delegated_canary_attempts (authorization_digest, attestation_id)
);

CREATE TABLE rsd_canary.delegated_canary_terminal_receipts (
    authorization_digest VARCHAR(64) PRIMARY KEY,
    attestation_id UUID NOT NULL,
    terminal_state VARCHAR(16) NOT NULL CHECK (terminal_state IN ('completed', 'failed')),
    response_sha256 VARCHAR(64) NOT NULL CHECK (response_sha256 ~ '^[0-9a-f]{64}$'),
    output_payload_sha256 VARCHAR(64) NOT NULL CHECK (output_payload_sha256 ~ '^[0-9a-f]{64}$'),
    attestation_sha256 VARCHAR(64) NOT NULL UNIQUE CHECK (attestation_sha256 ~ '^[0-9a-f]{64}$'),
    outcome_issued_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (authorization_digest, attestation_id)
        REFERENCES rsd_canary.delegated_canary_attempts (authorization_digest, attestation_id)
);

CREATE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'delegated canary ledger is append-only';
END;
$$;

CREATE TRIGGER delegated_canary_attempts_append_only
BEFORE UPDATE OR DELETE ON rsd_canary.delegated_canary_attempts
FOR EACH ROW EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();
CREATE TRIGGER delegated_canary_dispatches_append_only
BEFORE UPDATE OR DELETE ON rsd_canary.delegated_canary_dispatches
FOR EACH ROW EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();
CREATE TRIGGER delegated_canary_terminal_receipts_append_only
BEFORE UPDATE OR DELETE ON rsd_canary.delegated_canary_terminal_receipts
FOR EACH ROW EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();
CREATE TRIGGER delegated_canary_attempts_no_truncate
BEFORE TRUNCATE ON rsd_canary.delegated_canary_attempts
FOR EACH STATEMENT EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();
CREATE TRIGGER delegated_canary_dispatches_no_truncate
BEFORE TRUNCATE ON rsd_canary.delegated_canary_dispatches
FOR EACH STATEMENT EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();
CREATE TRIGGER delegated_canary_terminal_receipts_no_truncate
BEFORE TRUNCATE ON rsd_canary.delegated_canary_terminal_receipts
FOR EACH STATEMENT EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();

REVOKE ALL ON TABLE rsd_canary.delegated_canary_attempts FROM PUBLIC;
REVOKE ALL ON TABLE rsd_canary.delegated_canary_dispatches FROM PUBLIC;
REVOKE ALL ON TABLE rsd_canary.delegated_canary_terminal_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation() FROM PUBLIC;
