# @did-guardian/server

The reference, self-hostable registrar + OIDC provider + email proxy for the [`did:guardian`](../../website/content/spec/v1/index.md) method. Anyone can run their own instance on their own domain; this package doesn't assume it's zz's or any other specific deployment.

## What this is

A single Cloudflare Worker implementing:
- **The registrar**: `GET /.well-known/guardian/:name[/log]`, `POST /.well-known/guardian/:name/operations`, `POST /register` -- the actual did:guardian protocol.
- **An OIDC provider**: authorization code + PKCE, JWT ID tokens, JWKS, discovery -- "Sign in with did:guardian" for any relying party, against pre-registered clients (no dynamic client registration in v1).
- **Email proxying**: receive-and-forward (not mailbox hosting) for `name@your-domain`, plus outbound transactional send (verification links, etc.) via MailChannels.

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

No API for this yet (deliberately -- no dynamic client registration in v1). Insert directly:

```sql
INSERT INTO oidc_clients (client_id, client_secret_hash, redirect_uris, name, created_at)
VALUES ('my-app', '<sha256 hex of a real secret>', '["https://my-app.example/callback"]', 'My App', '<iso timestamp>');
```

### 5. Email proxying (optional)

Two separate things to set up, matching the two separate things this does:

- **Receiving** (`name@your-domain` -> forwarded to a real inbox): enable Cloudflare Email Routing for your zone, and add a route sending incoming mail to this Worker (Cloudflare dashboard: Email > Email Routing > Email Workers). No code or binding changes needed on this side -- the `email()` handler already exported here is what Cloudflare Email Routing invokes.
- **Sending** (verification links, etc., from `postmaster@your-domain`): this uses [MailChannels](https://mailchannels.net)' transactional API, which is free for Cloudflare Workers but requires your domain to prove it's actually hosted on Workers via a DNS TXT record (`_mailchannels` domain lockdown) -- see MailChannels' own Workers integration docs for the exact record. Without this, outbound sends will fail with a 401, same as they do in local dev (expected -- this step is real, per-domain setup, not something this code can do for you).

## Local development

```
npm run db:migrate:local
npm run dev
```

`.dev.vars` (gitignored) needs at minimum:

```
KEY_ENCRYPTION_KEY="<base64, 32 bytes>"
```

Email sending will fail locally (no real domain to authenticate as) -- that's expected; the verification-request flow still writes its row and returns a clear error rather than silently succeeding.

## Tests

```
npm test
```

Covers the email-proxying decision logic (reject unknown/unverified recipients, forward verified ones) against mocked D1/message objects. The registrar and OIDC layers are verified live against a real local `wrangler dev` + D1 instance rather than mocked -- see the project's own commit history for the exact manual verification each pass went through.
