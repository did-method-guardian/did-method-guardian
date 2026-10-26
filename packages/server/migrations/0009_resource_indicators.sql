-- RFC 8707 Resource Indicators (registrar API spec §12): a client may
-- name the specific resource server it wants a token scoped to, at
-- /authorize and again at refresh time. Nullable, plain ADD COLUMN --
-- no CHECK constraint involved, unlike zz's own agent_identities.provider
-- widening, so no rename-recreate-copy-drop needed here.
ALTER TABLE oidc_auth_codes ADD COLUMN resource TEXT;
ALTER TABLE oidc_refresh_tokens ADD COLUMN resource TEXT;
