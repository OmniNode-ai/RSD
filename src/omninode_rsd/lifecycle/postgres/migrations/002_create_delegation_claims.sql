CREATE TABLE rsd_canary.delegation_claims (
    authorization_digest TEXT PRIMARY KEY CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    claim_binding_sha256 TEXT NOT NULL CHECK (claim_binding_sha256 ~ '^[0-9a-f]{64}$'),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE FUNCTION rsd_canary.reject_delegation_claim_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'delegation claims are append-only';
END;
$$;

CREATE TRIGGER delegation_claims_append_only
BEFORE UPDATE OR DELETE ON rsd_canary.delegation_claims
FOR EACH ROW
EXECUTE FUNCTION rsd_canary.reject_delegation_claim_mutation();

CREATE TRIGGER delegation_claims_no_truncate
BEFORE TRUNCATE ON rsd_canary.delegation_claims
FOR EACH STATEMENT
EXECUTE FUNCTION rsd_canary.reject_delegation_claim_mutation();

REVOKE ALL ON TABLE rsd_canary.delegation_claims FROM PUBLIC;
REVOKE ALL ON FUNCTION rsd_canary.reject_delegation_claim_mutation() FROM PUBLIC;
