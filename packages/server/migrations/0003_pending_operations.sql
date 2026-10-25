-- Asynchronous signature collection for a multi-signer operation
-- (guardian_add, policy_update, or any other threshold needing more than
-- one party's signature) -- the real gap underneath "an op needs a
-- committee, collected over each signer's own schedule, not all at once."
-- See packages/server/src/pendingOps.ts for the state machine this backs.

CREATE TABLE pending_operations (
  id TEXT PRIMARY KEY,
  ward_did TEXT NOT NULL REFERENCES wards(did),
  op_type TEXT NOT NULL,
  partial_op TEXT NOT NULL,        -- the operation as proposed, JSON-encoded, sigs included so far
  required_signers TEXT NOT NULL,  -- JSON array of DIDs this proposal is notifying/expecting -- advisory (rules.ts's own isSatisfied is the real gate), not itself authoritative
  collected_sigs TEXT NOT NULL,    -- JSON object, signer DID -> sig, mirrors partial_op's own sigs map
  state TEXT NOT NULL,             -- "proposed" | "collecting" | "satisfied" | "finalized" | "declined" | "expired"
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_pending_operations_ward ON pending_operations(ward_did);
