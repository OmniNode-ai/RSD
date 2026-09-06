CREATE TABLE rsd_canary.delegated_canary_reconciliations (
    reconciliation_id UUID PRIMARY KEY,
    attempt_id_v2 UUID NOT NULL,
    authorization_digest VARCHAR(64) NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    attestation_id UUID NOT NULL,
    grant_not_before TIMESTAMPTZ NOT NULL,
    grant_expires_at TIMESTAMPTZ NOT NULL CHECK (grant_expires_at > grant_not_before),
    reconciliation_state VARCHAR(32) NOT NULL CHECK (
        reconciliation_state IN ('unknown_commit', 'prepared', 'dispatch_started', 'terminal')
    ),
    observation_sha256 VARCHAR(64) NOT NULL CHECK (observation_sha256 ~ '^[0-9a-f]{64}$'),
    observed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (attempt_id_v2, observation_sha256)
);

CREATE TRIGGER delegated_canary_reconciliations_append_only
BEFORE UPDATE OR DELETE ON rsd_canary.delegated_canary_reconciliations
FOR EACH ROW EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();
CREATE TRIGGER delegated_canary_reconciliations_no_truncate
BEFORE TRUNCATE ON rsd_canary.delegated_canary_reconciliations
FOR EACH STATEMENT EXECUTE FUNCTION rsd_canary.reject_delegated_canary_ledger_mutation();

REVOKE ALL ON TABLE rsd_canary.delegated_canary_reconciliations FROM PUBLIC;
