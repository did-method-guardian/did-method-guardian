-- Lets a ward take custody of its own operational key (REQ-7.2-1b's
-- counterpart in the other direction -- a guardian recovers a lost key;
-- this lets a ward stop trusting the registrar with a working one).
--
-- A separate table, not a new `wards` column: `wards` is referenced by
-- foreign keys from several other tables (pending_operations, oidc_consents,
-- relay_inbox), and SQLite's only way to loosen private_key_enc's NOT NULL
-- constraint in place is the rename-recreate-copy-drop rebuild, which
-- D1 rejects outright here (SQLITE_CONSTRAINT_FOREIGNKEY on DROP TABLE
-- wards) since those tables still reference it. This table is additive --
-- no rebuild, no FK conflict. Absence of a row here means "registrar",
-- the default and by far the common case; a row only exists once a ward
-- actually takes custody.
CREATE TABLE ward_custody (
  did TEXT PRIMARY KEY REFERENCES wards(did),
  custody_mode TEXT NOT NULL DEFAULT 'self' CHECK (custody_mode IN ('registrar', 'self')),
  taken_custody_at TEXT NOT NULL
);
