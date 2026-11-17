---
layout: docs-sidebar
title: "Sign in via custom OIDC (e.g. Tailscale)"
description: "Register an OAuth client against any registrar's standard OpenID Connect provider, and use a Guardian ID to sign in anywhere that accepts a custom OIDC identity provider."
---
# Sign in via custom OIDC (e.g. Tailscale)

Any did:guardian registrar also runs as a standard OpenID Connect provider. A relying party that accepts a custom OIDC identity provider -- Tailscale's own "Custom OIDC" option is one example -- works against it the same way it would against any other provider.

## Register an OAuth client

Dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) needs no prior account on the registrar:

```
curl -X POST https://guardianspec.org/oauth/register-client \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["https://login.tailscale.com/a/oauth_response"], "client_name": "Tailscale"}'
```

```json
{
  "client_id": "...",
  "client_secret": "...",
  "redirect_uris": ["https://login.tailscale.com/a/oauth_response"],
  "client_name": "Tailscale",
  "token_endpoint_auth_method": "client_secret_basic",
  "registration_access_token": "...",
  "registration_client_uri": "https://guardianspec.org/oauth/register-client/..."
}
```

Use `client_id` and `client_secret` wherever the relying party asks for them. The issuer is the registrar's own origin (`https://guardianspec.org`); its discovery document is at the standard `/.well-known/openid-configuration` path.

## Prompt behavior

If the relying party asks which `prompt` values to request (Tailscale's own setup screen does, as checkboxes): `consent` alone is enough for an ordinary sign-in. `login` forces re-authentication even if a session already exists; `select_account` is only meaningful for a provider showing a multi-account picker, which this one doesn't -- one Guardian ID signs in as itself, nothing to pick between. `none` suppresses any interactive prompt entirely and fails if one turns out to be required.

## Signing in with the root identity specifically

Some relying parties force a `name@domain` shape on their own login field (Tailscale's does) and never give you a way to type a bare domain. If you're signing in as a registrar's own bare-domain root identity rather than a named ward, `_@<your-domain>` is the one form that still gets through a form like that -- `_` is root's own reserved local part everywhere a named ward would use its own name.

## If the relying party validates claims strictly

A registrar's `id_token`/`userinfo` claims intentionally stay minimal and privacy-preserving: `email` (when the ward has verified forwarding set up) always asserts the ward's own Guardian-ID-based address, never wherever that mail actually forwards to. If a relying party's own validation expects something this registrar doesn't assert by default, check the [registrar API doc](/docs/registrar/)'s own section on `/userinfo` and the id_token for exactly what's included.
