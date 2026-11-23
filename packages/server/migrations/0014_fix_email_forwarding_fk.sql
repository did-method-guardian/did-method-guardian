-- F4 (audit r3): 0013 dropped `wards` but left email_forwarding's own FK
-- to it in place, so every INSERT/UPDATE against email_forwarding failed
-- with "no such table: main.wards" -- email forwarding was dead for every
-- account, deployment-wide, since there was no way to ever set it up.
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this rebuilds the
-- table the standard way (create, copy, drop, rename), re-keyed onto
-- `names(did)` (UNIQUE, and populated for every identity including the
-- root -- see registrar.ts's own insertNameEntry calls) instead of the
-- now-nonexistent `wards`.
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
