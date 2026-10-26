-- Refresh tokens (so a session doesn't just die after ID_TOKEN_TTL_S, the
-- normal consumer-IdP expectation) and revocation (RFC 7009) for otherwise-
-- stateless JWT access/id tokens.
--
-- Refresh tokens rotate on every use (the old one is marked revoked, a new
-- one issued with the same family_id) -- reuse of an already-revoked token
-- is the standard signal that one has been stolen, so the whole family
-- gets revoked in response, not just the reused token.

CREATE TABLE oidc_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  ward_did TEXT NOT NULL,
  scope TEXT NOT NULL,
  family_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_oidc_refresh_tokens_family ON oidc_refresh_tokens(family_id);

-- A small blocklist for revoking an otherwise-stateless access/id token
-- before its own natural expiry -- every newly issued token now carries a
-- jti claim, checked here at verification time (handleUserinfo today; any
-- future resource-server check reuses the same table).
CREATE TABLE oidc_revoked_jti (
  jti TEXT PRIMARY KEY,
  revoked_at TEXT NOT NULL
);
