# @did-guardian/server

The reference, self-hostable registrar + OIDC provider + email proxy for the [`did:guardian`](../../website/content/spec/v1/index.md) method. Anyone can run their own instance on their own domain; this package doesn't assume it's zz's or any other specific deployment.

## What this is

A single Cloudflare Worker implementing:
- **The registrar**: `GET /.well-known/guardian/:name[/log]`, `POST /.well-known/guardian/:name/operations`, `POST /register` -- the actual did:guardian protocol.
- **An OIDC provider**: authorization code + mandatory PKCE, refresh tokens, revocation, JWT ID tokens, JWKS, discovery, and self-service dynamic client registration (`POST /oauth/register-client`, RFC 7591) -- "Sign in with did:guardian" for any relying party.
- **An account dashboard** (`GET /account`): a real page for a person to log in and manage their own identity directly -- activity, guardians, connected apps, key rotation, deactivation.
- **Email proxying**: receive-and-forward (not mailbox hosting) for `name@your-domain`, plus outbound transactional send (verification links, pending-operation notifications) via a configurable provider -- never locked to one vendor (see §5 below).

## Setting up your own instance

### 1. D1 database

```
npx wrangler d1 create guardian-server
```

Copy the resulting `database_id` into `wrangler.jsonc`'s `d1_databases[0].database_id` (replacing the `REPLACE_ME` placeholder), then apply migrations:

```
npm run db:migrate:remote
```

### 2. Secrets and config

```
npx wrangler secret put KEY_ENCRYPTION_KEY   # 32 random bytes, base64 -- e.g. `openssl rand -base64 32`
```

Set `REGISTRAR_DOMAIN` in `wrangler.jsonc`'s `vars` to your actual domain (e.g. `acme.com`). Every identity this instance creates will be `did:guardian:<name>:<your>:<domain>`.

### 3. Route the Worker to your domain

Add a route in `wrangler.jsonc` (or the Cloudflare dashboard) binding your domain to this Worker, then `npm run deploy`.

### 4. Register OIDC clients

Self-service: `POST /oauth/register-client` (RFC 7591) -- see the registrar API spec's own §5.1. No manual D1 insert needed any more.

### 5. Email proxying (optional)

Two separate things to set up, matching the two separate things this does:

- **Receiving** (`name@your-domain` -> forwarded to a real inbox): enable Cloudflare Email Routing for your zone, and add a route sending incoming mail to this Worker (Cloudflare dashboard: Email > Email Routing > Email Workers). No code or binding changes needed on this side -- the `email()` handler already exported here is what Cloudflare Email Routing invokes.
- **Sending** (verification links, pending-operation notifications, from `postmaster@your-domain`): pick a provider and set `EMAIL_PROVIDER` (in `wrangler.jsonc`'s own `vars`) to one of `cloudflare-native` | `mailchannels` | `resend`. Never locked to one vendor -- see `emailProviders.ts` for the full list and how to add another (one small function, same shape, registered in `EMAIL_PROVIDERS`).

  **Easiest if you're already on Cloudflare: `cloudflare-native`.** No external account, no API key -- Cloudflare's own native Email Sending binding (public beta). One-time setup per domain:

  ```
  npx wrangler email sending enable your-domain.com   # Cloudflare then manages SPF/DKIM itself
  ```

  Uncomment the `send_email` binding and `EMAIL_PROVIDER` line already provided (commented out) in `wrangler.jsonc`. Needs the Workers Paid plan. `wrangler email sending list` confirms which domains are already enabled.

  **Not on Cloudflare, or would rather not depend on this one Workers-specific option: `mailchannels` or `resend`.** Both need an API key set as a secret, matching the provider name:

  ```
  npx wrangler secret put MAILCHANNELS_API_KEY   # or RESEND_API_KEY, matching EMAIL_PROVIDER
  ```

  Note on MailChannels specifically: their own free, keyless integration for Cloudflare Workers (DNS "domain lockdown" TXT record, no API key) was shut down in mid-2024 -- the current MailChannels option here is their paid Email API (100/day free tier), authenticated with a real API key, not a DNS record.

  Without `EMAIL_PROVIDER` configured at all, outbound sends fail with a clear "no email provider configured" error rather than a vendor-specific HTTP status.

## Local development

```
npm run db:migrate:local
npm run dev
```

`.dev.vars` (gitignored) needs at minimum:

```
KEY_ENCRYPTION_KEY="<base64, 32 bytes>"
EMAIL_PROVIDER="log"
```

`EMAIL_PROVIDER="log"` prints every outbound email to this Worker's own console instead of actually sending it -- real local testing of the email-verification and pending-operation-notification flows, without needing a real provider account. Never set this in a real deployment; there's no delivery behind it.

## Tests

```
npm test
```

Covers the email-proxying decision logic (reject unknown/unverified recipients, forward verified ones) against mocked D1/message objects. The registrar and OIDC layers are verified live against a real local `wrangler dev` + D1 instance rather than mocked -- see the project's own commit history for the exact manual verification each pass went through.
