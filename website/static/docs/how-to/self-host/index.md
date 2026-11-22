---
layout: docs-sidebar
title: "Self-host a registrar"
description: "Deploy packages/server -- the reference registrar -- on your own domain: a D1 database, two secrets, and a wrangler deploy."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Self-host a registrar",
  "description": "Deploy packages/server -- the reference registrar -- on your own domain: a D1 database, two secrets, and a wrangler deploy.",
  "url": "https://guardianspec.org/docs/how-to/self-host/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Self-host a registrar

`packages/server` is a self-hostable registrar: `packages/lib` plus an HTTP surface, an OIDC/OAuth2.1 identity provider, an account dashboard, an admin console, and an agent-identity API. This project's public registrar, guardianspec.org, is exactly this code, deployed to Cloudflare Workers.

## Deploy

```bash {linenos=false}
git clone https://github.com/did-method-guardian/did-method-guardian
cd did-method-guardian/packages/server
npm install

# Create a D1 database, then fill its id into wrangler.jsonc's
# "database_id" (it ships as a placeholder, "REPLACE_ME").
npx wrangler d1 create guardian-server

npx wrangler d1 migrations apply guardian-server --remote

# AES-GCM key, base64, 32 bytes -- encrypts custodied private keys at rest.
npx wrangler secret put KEY_ENCRYPTION_KEY

# Set REGISTRAR_DOMAIN in wrangler.jsonc's "vars" to your domain,
# then deploy.
npx wrangler deploy
```

That's a working registrar: anyone can `POST /register` and create an identity, OIDC endpoints are live, resolution works. A few things are opt-in from there, each documented inline in `wrangler.jsonc`'s comments:

- **Rate limiting** on `/register` and `/guardian-login` (a KV namespace -- without it, these endpoints simply have no rate limiting, rather than failing).
- **Outbound email** for forwarding and verification, either Cloudflare's native Email Sending binding or an external provider (MailChannels, Resend) via `EMAIL_PROVIDER` and an API key secret.
- **Federated trust** (`FEDERATED_TRUSTED_ISSUERS`) if you want this registrar to also accept another registrar's access tokens at bearer-token-gated endpoints.

## The bare-domain root identity

Every deployment auto-provisions one identity with no name at all -- `did:guardian:<your-domain>` -- the first time anything resolves it. It attests every other ward's genesis operation and, once given a login credential, is a fully usable identity like any other.

```bash {linenos=false}
npx wrangler secret put ROOT_WARD_LOGIN_SECRET
```

Sign in with the name field left as `_`, your bare domain, `@your-domain`, or `_@your-domain` -- all four mean the same thing. There's no self-service recovery path for this one credential if you lose it; see [README.md](https://github.com/did-method-guardian/did-method-guardian/blob/main/README.md#self-hosting-the-bare-domain-root-identity) for the direct-database reset procedure.

## Open vs. closed registration

**Open** (the default, and how guardianspec.org runs): anyone can register. **Closed** (`REGISTRATION_MODE: "closed"` in `wrangler.jsonc`'s `vars`): public self-service is blocked, and the root identity creates accounts for specific people or agents instead, through the admin console (`/admin`, `/admin/create-account`) -- available on every deployment regardless of this setting, gated to a session authenticated as the root identity. This is the shape for an operator who controls the whole domain -- personally, or as a business -- and wants named accounts for their team or the agents they run, without an open door to the public.

Full environment-variable reference: [`packages/server/src/env.ts`](https://github.com/did-method-guardian/did-method-guardian/blob/main/packages/server/src/env.ts).
