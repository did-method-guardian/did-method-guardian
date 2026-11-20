---
layout: docs-sidebar
title: "Sign in via custom OIDC"
description: "Register an OAuth client against a registrar's standard OpenID Connect provider, and use a Guardian ID to sign in anywhere that accepts a custom OIDC identity provider."
---
# Sign in via custom OIDC

Any did:guardian registrar runs as a standard OpenID Connect provider. A relying party that accepts a custom or generic OIDC identity provider -- Tailscale, Grafana, and many self-hosted tools all have an option like this -- works against it the same way it would against any other provider.

## Register an OAuth client

Dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) needs no prior account on the registrar:

```text {linenos=false}
curl -X POST https://guardianspec.org/oauth/register-client \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["https://your-app.example.com/oauth/callback"], "client_name": "My App"}'
```

```json {linenos=false}
{
  "client_id": "...",
  "client_secret": "...",
  "redirect_uris": ["https://your-app.example.com/oauth/callback"],
  "client_name": "My App",
  "token_endpoint_auth_method": "client_secret_basic",
  "registration_access_token": "...",
  "registration_client_uri": "https://guardianspec.org/oauth/register-client/..."
}
```

Use `client_id` and `client_secret` wherever the relying party asks for them. The issuer is the registrar's domain (`https://guardianspec.org`); its discovery document is at the standard `/.well-known/openid-configuration` path.

## Prompt behavior

If the relying party asks which `prompt` values to request (some expose this as checkboxes in their setup screen): `consent` alone is enough for an ordinary sign-in. `login` forces re-authentication even if a session already exists; `select_account` is only meaningful for a provider showing a multi-account picker, which a registrar doesn't -- one Guardian ID signs in, with nothing to pick between. `none` suppresses any interactive prompt entirely and fails if one turns out to be required.

## Signing in as the root identity

Some relying parties force a `name@domain` shape on their login field and never give a way to type a bare domain. If you're signing in as a registrar's bare-domain root identity rather than a named ward, `_@<your-domain>` is the one form that still gets through a form like that -- `_` is root's reserved local part everywhere a named ward would use its name.

## If the relying party validates claims strictly

A registrar's `id_token`/`userinfo` claims stay minimal and privacy-preserving: `email` (when the ward has verified forwarding set up) always asserts the ward's canonical Guardian-ID-based address, never wherever that mail actually forwards to. If a relying party's validation expects something a registrar doesn't assert by default, check the [registrar API doc](/docs/registrar/)'s section on `/userinfo` and the id_token for exactly what's included.
