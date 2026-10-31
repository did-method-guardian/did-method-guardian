-- Persistent inbox for incoming cross-registrar signature requests
-- (registrar API spec §13's own documented v1 gap): relay-notify's email
-- was previously the *only* record a request ever existed -- if it never
-- landed (spam filter, stale forwarding address, relay-notify itself
-- failing, which it's designed to do silently), the signer had no way to
-- discover the request at all. This gives the receiving registrar its own
-- durable record, independent of whether any notification succeeded.
--
-- One row per (signer, pending operation) -- handleRelayNotify can fire
-- more than once for the same request as an operation progresses (propose,
-- then each other signer's own contribution), so this is an upsert, not a
-- plain insert; the primary key enforces that directly.
--
-- status isn't kept in sync with the real operation state on the ward's
-- registrar (that would mean polling every open row on some schedule) --
-- it only ever means "resolved through this registrar's own /relay-sign
-- flow" (signed or declined here). Visiting /relay-sign for any entry
-- always re-fetches the real, live status first, same as it always has;
-- this table is an index to discover requests, never a cache of their
-- truth.

CREATE TABLE relay_inbox (
  signer_did TEXT NOT NULL,
  pending_operation_id TEXT NOT NULL,
  ward_did TEXT NOT NULL,
  op_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  PRIMARY KEY (signer_did, pending_operation_id)
);
CREATE INDEX idx_relay_inbox_signer_status ON relay_inbox(signer_did, status);
