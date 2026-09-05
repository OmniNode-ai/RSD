-- Add the V2 carrier without rewriting any existing ledger row.
-- Every new column is nullable and has no default: migration 003 remains the
-- complete legacy representation, while a V2 row must be complete as one
-- atomic append.  The append-only triggers from migration 003 continue to
-- govern these tables; this migration deliberately does not recreate them.

ALTER TABLE rsd_canary.delegated_canary_attempts
    ADD COLUMN attempt_schema_version VARCHAR(64),
    ADD COLUMN attempt_id_v2 UUID,
    ADD COLUMN grant_not_before TIMESTAMPTZ,
    ADD COLUMN grant_expires_at TIMESTAMPTZ;

ALTER TABLE rsd_canary.delegated_canary_attempts
    ADD CONSTRAINT delegated_canary_attempts_v2_carrier_complete
    CHECK (
        (attempt_schema_version IS NULL AND attempt_id_v2 IS NULL
         AND grant_not_before IS NULL AND grant_expires_at IS NULL)
        OR
        (attempt_schema_version = 'rsd.delegated-canary-attempt.v2'
         AND attempt_id_v2 IS NOT NULL AND grant_not_before IS NOT NULL AND grant_expires_at IS NOT NULL
         AND grant_expires_at > grant_not_before
         AND activation_issued_at >= grant_not_before
         AND activation_expires_at <= grant_expires_at)
    ),
    ADD CONSTRAINT delegated_canary_attempts_v2_identity_unique
    UNIQUE (attempt_id_v2);

ALTER TABLE rsd_canary.delegated_canary_dispatches
    ADD COLUMN attempt_id_v2 UUID,
    ADD COLUMN grant_not_before TIMESTAMPTZ,
    ADD COLUMN grant_expires_at TIMESTAMPTZ;

ALTER TABLE rsd_canary.delegated_canary_dispatches
    ADD CONSTRAINT delegated_canary_dispatches_v2_carrier_complete
    CHECK (
        (attempt_id_v2 IS NULL AND grant_not_before IS NULL AND grant_expires_at IS NULL)
        OR
        (attempt_id_v2 IS NOT NULL AND grant_not_before IS NOT NULL AND grant_expires_at IS NOT NULL
         AND grant_expires_at > grant_not_before)
    ),
    ADD CONSTRAINT delegated_canary_dispatches_v2_carrier_fk
    FOREIGN KEY (attempt_id_v2)
    REFERENCES rsd_canary.delegated_canary_attempts (attempt_id_v2);

ALTER TABLE rsd_canary.delegated_canary_terminal_receipts
    ADD COLUMN attempt_id_v2 UUID,
    ADD COLUMN grant_not_before TIMESTAMPTZ,
    ADD COLUMN grant_expires_at TIMESTAMPTZ,
    ADD COLUMN outcome_attestation_id_v2 UUID,
    ADD COLUMN outcome_attestation_schema_version VARCHAR(64),
    ADD COLUMN outcome_attestation_sha256 VARCHAR(64),
    ADD COLUMN outcome_trust_anchor_sha256 VARCHAR(64),
    ADD COLUMN outcome_trust_anchor_key_id VARCHAR(64),
    ADD COLUMN outcome_trust_anchor_key_fingerprint_sha256 VARCHAR(64),
    ADD COLUMN outcome_issued_at_v2 TIMESTAMPTZ;

ALTER TABLE rsd_canary.delegated_canary_terminal_receipts
    ADD CONSTRAINT delegated_canary_terminal_receipts_v2_carrier_complete
    CHECK (
        (
            attempt_id_v2 IS NULL
            AND grant_not_before IS NULL
            AND grant_expires_at IS NULL
            AND outcome_attestation_id_v2 IS NULL
            AND outcome_attestation_schema_version IS NULL
            AND outcome_attestation_sha256 IS NULL
            AND outcome_trust_anchor_sha256 IS NULL
            AND outcome_trust_anchor_key_id IS NULL
            AND outcome_trust_anchor_key_fingerprint_sha256 IS NULL
            AND outcome_issued_at_v2 IS NULL
        )
        OR
        (
            attempt_id_v2 IS NOT NULL
            AND grant_not_before IS NOT NULL
            AND grant_expires_at IS NOT NULL
            AND outcome_attestation_id_v2 IS NOT NULL
            AND outcome_attestation_schema_version = 'rsd.dispatch-outcome-attestation.v2'
            AND outcome_attestation_sha256 ~ '^[0-9a-f]{64}$'
            AND outcome_trust_anchor_sha256 ~ '^[0-9a-f]{64}$'
            AND outcome_trust_anchor_key_id ~ '^[a-z][a-z0-9-]{1,63}$'
            AND outcome_trust_anchor_key_fingerprint_sha256 ~ '^[0-9a-f]{64}$'
            AND outcome_issued_at_v2 IS NOT NULL
            AND grant_expires_at > grant_not_before
            AND outcome_issued_at_v2 >= grant_not_before
            AND outcome_issued_at_v2 < grant_expires_at
        )
    ),
    ADD CONSTRAINT delegated_canary_terminal_receipts_v2_carrier_fk
    FOREIGN KEY (attempt_id_v2)
    REFERENCES rsd_canary.delegated_canary_attempts (attempt_id_v2),
    ADD CONSTRAINT delegated_canary_terminal_receipts_v2_outcome_attestation_unique
    UNIQUE (outcome_attestation_id_v2);
