-- Dynamic client registration (RFC 7591) -- v1 only supported pre-registered
-- clients (0002_oidc.sql's own comment said so explicitly), meaning a new
-- relying party needed someone to hand-insert an oidc_clients row. A real
-- "Login with Guardian" button needs self-service registration like every
-- other IdP already offers.

ALTER TABLE oidc_clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic';
ALTER TABLE oidc_clients ADD COLUMN registration_access_token_hash TEXT;
