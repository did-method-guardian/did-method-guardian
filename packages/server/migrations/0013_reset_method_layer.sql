-- Reset (2026-11-22): the did:guardian method itself changed completely
-- (snapshot guardian entries, did:key-only proofs, no CID chain). The
-- live data is reset at deploy time, so this replaces the method-specific
-- tables outright rather than migrating them. OIDC, login sessions and
-- email forwarding are untouched.
--
-- Ordering note (audit r4, fix D follow-up): `operations`,
-- `email_forwarding`, `pending_operations`, `pending_operation_tokens`,
-- and `ward_custody` (0001/0003/0004/0011) all declare a `REFERENCES
-- wards(did)` or `REFERENCES pending_operations(id)` foreign key.
-- D1's remote engine refuses to drop a table another table's FK still
-- points to; local dev's own sqlite emulation doesn't enforce this at
-- all, which is why this went unnoticed through every local test until
-- the first real remote apply. Every child has to be dropped (or, for
-- email_forwarding, re-keyed) before its parent goes away -- never the
-- other way around.

DROP TABLE IF EXISTS operations;
DROP TABLE IF EXISTS ward_custody;
DROP TABLE IF EXISTS pending_operation_tokens;
DROP TABLE IF EXISTS pending_operations;
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
-- by this table's own primary key never being deleted from. Created
-- here, before `wards` is dropped below, so email_forwarding has
-- something to re-key onto in the same migration.
CREATE TABLE names (
  domain TEXT NOT NULL,
  name TEXT NOT NULL,
  did TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (domain, name)
);

-- F4 (audit r3), folded in here rather than left for 0014 (see that
-- file): email_forwarding's own FK has to move off `wards` before
-- `wards` is dropped below, in this same migration, not a later one --
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this rebuilds the
-- table the standard way (create, copy, drop, rename), re-keyed onto
-- `names(did)` (UNIQUE, and populated for every identity including the
-- root -- see registrar.ts's own insertNameEntry calls) instead of the
-- about-to-be-dropped `wards`.
CREATE TABLE email_forwarding_new (
  did TEXT PRIMARY KEY REFERENCES names(did),
  forward_to TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verification_token TEXT,
  created_at TEXT NOT NULL
);
INSERT INTO email_forwarding_new SELECT * FROM email_forwarding;
DROP TABLE email_forwarding;
ALTER TABLE email_forwarding_new RENAME TO email_forwarding;

DROP TABLE IF EXISTS wards;

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
