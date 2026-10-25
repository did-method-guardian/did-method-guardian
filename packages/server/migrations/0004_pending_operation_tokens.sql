-- One-click email links for withdraw/decline (task #113): a per-(proposal,
-- signer) unguessable token, same trust model as this registrar's own
-- existing email-verification-link flow (email_forwarding.verification_token)
-- -- possession of the verified email is the proof, no signature needed.
-- Generated the first time a given signer is ever notified about a
-- proposal, reused for every later email about that same proposal so the
-- same links keep working until the proposal is no longer pending.
--
-- last_notified_at is per-signer, not per-proposal -- different signers can
-- be notified at different times (one just got a "you voted" follow-up,
-- another has been waiting since propose time), so the daily reminder cron
-- (task #113) needs its own per-signer clock to only re-notify once a day.

CREATE TABLE pending_operation_tokens (
  pending_op_id TEXT NOT NULL REFERENCES pending_operations(id),
  signer_did TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_notified_at TEXT NOT NULL,
  PRIMARY KEY (pending_op_id, signer_did)
);
CREATE INDEX idx_pending_operation_tokens_token ON pending_operation_tokens(token);
