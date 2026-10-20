-- Minimal but real OIDC provider state: pre-registered clients only (no
-- dynamic registration in v1), authorization codes, and this instance's own
-- OIDC signing key. A ward's own login to THIS registrar (distinct from any
-- relying-party's OIDC flow) uses a separate login secret issued at
-- registration time -- the custodial model here means the ward's own
-- operational key is held by the server, not provable client-side, so
-- login needs its own credential, hashed at rest like any password.

ALTER TABLE wards ADD COLUMN login_secret_hash TEXT;

CREATE TABLE oidc_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,  -- JSON array of exact-match allowed redirect URIs
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE oidc_auth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  ward_did TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT,
  code_challenge_method TEXT,
  scope TEXT NOT NULL,
  nonce TEXT,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE oidc_signing_key (
  id INTEGER PRIMARY KEY CHECK (id = 1), -- single row, one active signing key per deployment
  kid TEXT NOT NULL,
  public_key TEXT NOT NULL,
  private_key_enc TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE login_sessions (
  session_id TEXT PRIMARY KEY,
  ward_did TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
