-- Core registrar state: one row per identity this instance custodies the
-- operational key for, plus the append-only operation log itself.

CREATE TABLE wards (
  name TEXT PRIMARY KEY,                    -- the DID-safe local name, e.g. "alice"
  did TEXT NOT NULL UNIQUE,                 -- "did:guardian:<name>:<domain-labels>"
  public_key TEXT NOT NULL,                 -- base64url SPKI
  private_key_enc TEXT NOT NULL,            -- AES-GCM ciphertext, base64url, KEY_ENCRYPTION_KEY secret
  created_at TEXT NOT NULL
);

CREATE TABLE operations (
  cid TEXT PRIMARY KEY,
  did TEXT NOT NULL REFERENCES wards(did),
  prev_cid TEXT,
  op_type TEXT NOT NULL,
  payload TEXT NOT NULL,                    -- the full operation, JSON-encoded, sigs included
  created_at TEXT NOT NULL
);
CREATE INDEX idx_operations_did ON operations(did);

CREATE TABLE email_forwarding (
  did TEXT PRIMARY KEY REFERENCES wards(did),
  forward_to TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verification_token TEXT,
  created_at TEXT NOT NULL
);
