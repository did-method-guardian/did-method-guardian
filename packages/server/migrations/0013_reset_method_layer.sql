-- Reset (2026-11-22): the did:guardian method itself changed completely
-- (snapshot guardian entries, did:key-only proofs, no CID chain). The
-- live data is reset at deploy time, so this replaces the method-specific
-- tables outright rather than migrating them. OIDC, login sessions and
-- email forwarding are untouched.

DROP TABLE IF EXISTS wards;
DROP TABLE IF EXISTS operations;
DROP TABLE IF EXISTS ward_custody;
DROP TABLE IF EXISTS pending_operations;
DROP TABLE IF EXISTS pending_operation_tokens;
DROP TABLE IF EXISTS relay_inbox;

-- The operation log for a DID, one row per operation, oldest first by
-- `seq`. `prev` is the operation hash this row's own `prev` member names,
-- or '' for seq 0 (a create has no `prev` member at all) -- never NULL,
-- so the unique index below gives REQ-10-8 (at most one accepted
-- operation per prev) as an atomic, race-free DB constraint: a second
-- concurrent insert naming the same (did, prev) fails outright, rather
-- than needing a read-then-write.
CREATE TABLE logs (
  did TEXT NOT NULL,
  seq INTEGER NOT NULL,
  prev TEXT NOT NULL,
  operation TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (did, seq)
);
CREATE UNIQUE INDEX logs_did_prev ON logs (did, prev);

-- A fast index from (domain, name) to DID, maintained alongside `logs`
-- (which stays authoritative) -- REQ-10-12's name non-reuse is enforced
-- by this table's own primary key never being deleted from.
CREATE TABLE names (
  domain TEXT NOT NULL,
  name TEXT NOT NULL,
  did TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (domain, name)
);

-- A private key this registrar custodies for an identity (REQ-10-13/
-- REQ-10-14) -- a row exists only while this registrar holds the key;
-- take-custody deletes it. login_secret_hash is only meaningful for an
-- identity that logs in through this registrar's own password flow.
CREATE TABLE held_keys (
  did TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key_enc TEXT NOT NULL,
  login_secret_hash TEXT,
  created_at TEXT NOT NULL
);

-- A proposed operation collecting proofs from several signers before
-- submission. `operation` is the fixed candidate (without `proof`);
-- `proofs` is a JSON array each signer's own call appends to -- every
-- proof signs over the same secured document independently (REQ-5-12),
-- so signers never need to coordinate or see each other's proofs first.
CREATE TABLE pending_proofs (
  id TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  operation TEXT NOT NULL,
  proofs TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX pending_proofs_did ON pending_proofs (did);
