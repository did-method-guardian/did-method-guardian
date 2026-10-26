-- Consent screen (OAuth best practice, and often an app-store/conformance
-- requirement) -- handleAuthorize previously went straight from login to
-- issuing a code with no "App X wants access to Y -- Allow/Deny" step at
-- all. Remembered per (ward, client) so a returning user isn't re-asked
-- unless the requested scope actually grows.

CREATE TABLE oidc_consents (
  ward_did TEXT NOT NULL,
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  scope TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (ward_did, client_id)
);
