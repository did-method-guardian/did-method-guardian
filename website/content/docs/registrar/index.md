---
layout: docs-sidebar
title: "did:guardian Registrar API, v1 (the reference registrar)"
description: "This reference registrar implementation's HTTP surface -- the three method-required endpoints plus every convenience endpoint and signature-collection mechanism this specific implementation adds on top."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "did:guardian Registrar API, v1",
  "description": "This reference registrar implementation's HTTP surface -- the three method-required endpoints plus every convenience endpoint and signature-collection mechanism this specific implementation adds on top.",
  "url": "https://guardianspec.org/docs/registrar/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Registrar API (the reference registrar's own)

**Version 1.** This document is a registrar profile, not the method: exactly one registrar implementation's HTTP surface -- `packages/server` in this repository, deployed as guardianspec.org's registrar. It is versioned and evolves independently of [the formal method specification](/docs/did-guardian-spec-v0.2.0/) -- adding, removing, or reshaping anything here never changes method conformance, and a different registrar implementation is free to expose none of it. Only [§1](#1-method-required-endpoints) restates an actual method requirement (§10 of the formal spec); everything else is this registrar's operational choice.

Most endpoints below are rooted at `/.well-known/guardian/<name>` (or `/.well-known/guardian/_` for the bare-domain identity) -- §1 through §4 and §13. Registration, login, OIDC, the account dashboard, the admin console, and the pending-operation browser page live at their own top-level paths instead (§2, §5, §8, §9, §14, and `/.well-known/guardian/pending/<id>`, not name-scoped). All request/response bodies are JSON unless noted.

## 1. Method-required endpoints

Required by the formal spec's [REQ-10-1](/docs/did-guardian-spec-v0.2.0/#req-10-1); this registrar's implementation of them.

| Method | Path | |
|---|---|---|
| `GET` | `/.well-known/guardian/<name>` | current derived DID Document |
| `GET` | `/.well-known/guardian/<name>/log` | full operation log, in order |
| `POST` | `/.well-known/guardian/<name>/operations` | submit one fully-proofed operation |

Both `GET` endpoints are plain reads -- neither one ever creates anything, including the bare-domain root identity itself ([REQ-10-2](/docs/did-guardian-spec-v0.2.0/#req-10-2)).

`POST .../operations` accepts any operation type from the formal spec's §7 with every required proof already attached and appends it if valid, rejecting with a reason string otherwise. This is the only path by which an *externally* pre-proofed operation (e.g. two guardians who coordinated their own signatures out-of-band) reaches the log directly, without going through §3's collection machinery. On success, the response is `{accepted: true, operation}` -- the accepted operation, with its attestation attached if it's a `create`; on rejection, `{error: <reason>}` with HTTP 400 ([REQ-10-4](/docs/did-guardian-spec-v0.2.0/#req-10-4)). A `create` submitted here for a named identity gets exactly `/register`'s gate (§2): no session or bearer token can exist yet for a DID that doesn't exist yet, so it's anonymous self-service -- rate-limited to 5 attempts per 10 minutes per client IP (HTTP 429 past that), and rejected outright with HTTP 403 when this deployment has closed public registration (`REGISTRATION_MODE`, below). Every other operation type is ungated here beyond its approval requirement -- the proofs already attached are the authorization.

## 2. Self-contained convenience endpoints

`/register` and `.../adopt` also live at this level, but this page doesn't yet describe their own mechanics in detail -- a change to how registration names an initial guardian is under discussion. §9 has what's settled.

Each of these corresponds to an operation whose own required approvals a single call from one authenticated party can satisfy, with this registrar producing every proof it needs to from keys it already holds -- no new authority is ever granted to a third party by any of these. `.../remove` is the one row here whose safety isn't just "no new authority granted": it also depends on the acceptance-time check (REQ-10-7) actually verifying the caller's claimed evidence names a genuine `deactivate` or `releaseWard`, not merely trusting that it does -- a caller can name any evidence hash it wants, and a bogus one is rejected there, not here. Auth model for all of them: either an active `gw_session` cookie, or a trusted OIDC client credential (Basic auth) acting on an already-verified decision made by its caller -- always for *whichever identity this operation actually needs a proof from*, never assumed from the identity named in the path. `.../remove-self` in particular authenticates the departing guardian, not the ward in the URL -- a held key signs only on a request already authenticated as that exact identity ([REQ-10-13](/docs/did-guardian-spec-v0.2.0/#req-10-13)).

**What makes an OIDC client "trusted."** `client_id`/`client_secret` (Basic auth) alone is never enough -- a client row also carries its `trusted` flag, checked explicitly. Every client created through `POST /oauth/register-client` (RFC 7591's open, unauthenticated dynamic registration) starts `trusted = false`, with no field in that request able to change it; there is no endpoint, anywhere on this registrar, that sets it to `true`. The only way a client becomes trusted is a direct operator database write -- an out-of-band, deployment-level decision this registrar's HTTP surface has no way to grant itself. This is why dynamic client registration staying unauthenticated is safe at all: a self-registered client can authenticate its OIDC flows, but gets nothing from this section's endpoints regardless of what credentials it presents.

| Method | Path | Operation produced | Why it's self-contained |
|---|---|---|---|
| `POST` | `.../rotate` | `update`, both approvals self-produced | this registrar holds both the identity's current key and the fresh one it just generated, so it signs with both itself |
| `POST` | `.../take-custody` | `update` to a caller-supplied key | the caller's proof of possession for the new key, combined with this registrar's proof using the key it's about to stop holding |
| `POST` | `.../remove-self` | `removeGuardian`, the departing guardian itself | needs only the departing guardian's approval -- the "removed guardian itself, if there are at least two" path |
| `POST` | `.../remove` | `removeGuardian`, with evidence | the *ward's own* key, naming evidence (a `deactivate` or `releaseWard` already in the departing guardian's log) that the guardian already lost standing |

A forced removal by vote of the *other* guardians, with no evidence, or a deactivation needing guardian cooperation too, needs more than this registrar can produce from one call -- see §3.

**`.../take-custody` is irreversible in a way nothing else on this page is.** Every other row above produces an operation and nothing changes about who's custodied going forward. This one ends it: body `{operation, proof}`, where `operation` is an `update` naming the caller's new key (with its current `services`/`alsoKnownAs` carried over) and `proof` is that same key's [Data Integrity proof](/docs/did-guardian-spec-v0.2.0/#req-5-11) of possession, built by the caller before this call. This registrar can never produce that proof itself, since it will never hold the new key's private half. A stale `prev` by the time the request arrives just fails the way any other `prev` mismatch does. Afterward, this registrar has deleted its held key for that identity outright -- not set it aside, not kept it for a future rotation, gone. Every row on this page that needs a held key stops working for that identity from then on, with a clear error pointing at submitting pre-proofed operations through §1 directly instead.

Nothing here stops the bare-domain root identity from calling `.../take-custody` -- it has no special protection -- but doing so deletes this registrar's ability to sign any further create attestation on its domain ([REQ-7-9](/docs/did-guardian-spec-v0.2.0/#req-7-9)); it has to keep a key this registrar can read for that.

**Rotating or taking custody of a key breaks that identity's entries in anything it guards, not just its log.** `.../rotate` and `.../take-custody` both replace the identity's `keys` -- but every ward whose `guardians` already names this identity recorded its keys as they were at that moment ([REQ-6-2](/docs/did-guardian-spec-v0.2.0/#req-6-2)), and REQ-10-6/10-7's standing check compares against that snapshot. Neither endpoint touches any other identity's log, so the guardian loses standing to approve anything for every ward it guards the moment either one succeeds. `updateGuardian` ([REQ-7-15](/docs/did-guardian-spec-v0.2.0/#req-7-15)) is how a ward re-seats a stale entry with the guardian's current keys -- approvable with the guardian's old and new keys together, no other guardian needed -- but only while the OLD key can still sign, which means re-seating every guarded ward has to happen *before* rotating or taking custody, not after. `.../rotate`'s new key is generated server-side and only revealed once rotation has already completed, so there's no way to pre-sign anything with it in advance; `.../take-custody`'s new key is the caller's own, known ahead of time, so re-seating first (signing each ward's `updateGuardian` with the old key via `.../pending/<id>/sign-as-self` and the new key locally) is the only order that actually works.

## 3. Asynchronous signature collection (`pending_proofs`)

For anything needing more than one proof collected over more than one request -- `addGuardian` (it always needs both the ward's own key and the incoming guardian's, two different parties, even for the very first guardian), `removeGuardian` against a guardian set that already has more than one member, `setPolicy`, `updateGuardian`, or a recovery/deactivation whose required guardians aren't all held by (or available in the same call to) this registrar.

There's no state machine. A proposal is a candidate operation (its `prev` already fixed against the current log) plus a growing array of proofs. Each proof secures the operation independently ([REQ-5-10](/docs/did-guardian-spec-v0.2.0/#req-5-10)), so signers never need to see each other's proofs or coordinate at all -- they just add their own, in any order, whenever they get to it. After every addition, this registrar checks whether the proofs collected so far are now enough (exactly [REQ-10-5](/docs/did-guardian-spec-v0.2.0/#req-10-5), the same check `.../operations` runs); if so, it submits the operation itself and the proposal is gone. If not, it keeps collecting.

| Method | Path | |
|---|---|---|
| `POST` | `.../propose` | starts a proposal -- body `{operation, proof}`, where `operation` is the candidate without its `proof` member and `proof` is the proposer's own, over that same content. Returns `{status: "finalized", operation}` if that one proof was already enough, or `{status: "collecting", id, reason}` (the id to collect more against) otherwise |
| `POST` | `.../pending/<id>/sign` | a required signer adds their own proof -- body `{proof}`, over the same operation `GET .../pending/<id>` returns. Same two possible outcomes as `.../propose` |
| `POST` | `.../pending/<id>/sign-as-self` | `gw_session`-gated: signs server-side with the key this registrar already holds for the logged-in identity, same model as `.../rotate` |
| `POST` | `.../pending/<id>/withdraw` | cancels the proposal outright -- only the identity the proposal's log belongs to may do this, `gw_session`-gated |
| `GET` | `.../pending/<id>` | content-negotiated: `Accept: text/html` renders the browser page below; anything else returns `{did, operation, proofs, expiresAt}` |
| `GET` | `/api/me/pending-signatures` | every proposal currently collecting on the caller's log -- not proposals elsewhere the caller is a required signer for (e.g. as a guardian on a different identity); nothing yet surfaces those anywhere, the account dashboard (§8) included |

A proposal not satisfied within 7 days is removed by a daily sweep -- always a failure, never an automatic pass. There's no decline: a guardian who disagrees with a proposal simply never contributes a proof, which lets it expire on its own; nothing short of the proposal's target identity can remove it early.

**The browser page** (`GET .../pending/<id>` with `Accept: text/html`) shows the operation and how many proofs it's collected, with a **Sign** button shown only when the viewer is authenticated (§5's `gw_session`) as an identity this registrar holds a key for -- a logged-out viewer instead sees a link to §5's login page. A page that performed an action on a bare `GET` could be triggered by an email client's link-prefetching scanner before a person ever reads a message linking here, so every action here is a real `POST` from a button click, never a link. A required signer still has to be told a proposal exists by some other channel -- there's no notification of any kind yet, email included.

## 4. Orphan handling

Entirely the method's rule now, not this registrar's policy choice. When a `removeGuardian` empties a ward's `guardians` ([REQ-6-10](/docs/did-guardian-spec-v0.2.0/#req-6-10)), its `policy.orphan` says what happens next, applied automatically by every verifier the same way, as part of replaying the operation itself -- never a separate action this registrar takes afterward:

- **`"deactivate"`** (the default) -- the ward deactivates itself, right there, with no further operation needed.
- **`"independent"`** -- nothing happens; the ward simply has no guardians from then on.
- **`"successor"`** -- its `successor` entry is promoted to its sole guardian, and `successor` is cleared. [REQ-10-7](/docs/did-guardian-spec-v0.2.0/#req-10-7) requires this registrar to check that the successor's entry still has standing before accepting the `removeGuardian` that triggers this -- the one piece of this that's actually a registrar-side check, not purely a replay rule.

A ward whose policy names `"successor"` but has no `successor` entry set, or the reverse, is invalid at the operation that would create that mismatch ([REQ-6-14](/docs/did-guardian-spec-v0.2.0/#req-6-14)) -- this registrar never needs to reconcile the two separately.

An absent policy member takes the default in [REQ-6-11](/docs/did-guardian-spec-v0.2.0/#req-6-11) -- this registrar has no separate configured default to fall back to instead, so two verifiers resolving the same unset field never disagree depending on which registrar they asked.

## 5. Login / OIDC

Two independent flows share the same underlying credential (`login_secret`) and the same `gw_session` cookie, for two different purposes:

- `/authorize`, `/token`, `/userinfo`, `/revoke`, `/oauth/register-client`, `/.well-known/openid-configuration`, `/.well-known/jwks.json` -- the OIDC relying-party flow, for a third-party application that wants to let someone sign in with their Guardian ID. See `packages/server/src/oidc.ts`.
- `GET`/`POST /guardian-login?return_to=<path>` -- this registrar's first-party login, for this registrar's own pages: §3's browser voting page, the account dashboard (§8), and the admin console (§14), each redirecting here when there's no active session. No client registration: it's just "sign in, then take me back to the same-origin path that sent me here" (`return_to` is restricted to a relative path -- no open redirect to an external target). See `votingPage.ts`.
- `POST /guardian-logout?return_to=<path>` -- ends the session: deletes the `login_sessions` row server-side (not just the cookie client-side, so the old session id can't be replayed) and clears the cookie. POST only, same reasoning as every other state-changing action here -- never a bare link a scanner could trigger. Linked from the account dashboard (§8).

Named `/guardian-login`/`/guardian-logout`, not the shorter `/login`/`/logout`, because a registrar is commonly deployed on a domain that already has its own, unrelated human-facing `/login` and `/logout`. Each still needs its wrangler route entry -- worth checking your own host application's routes before adding any new top-level path here, not just these two.

**A relying party's `login_hint` always takes precedence over an already-active session.** `/authorize` compares a normalized `login_hint` against the current session's name (the same normalization a login attempt itself goes through), and falls through to a login prompt -- pre-filled with the hint, same as having no session at all -- whenever they don't match, rather than silently proceeding as whoever happens to still be logged in.

**The bare-domain root identity logs in like any other identity**, once an operator has given it a credential (`ROOT_WARD_LOGIN_SECRET`, see the top-level README's self-hosting section) -- the name field on either login form accepts `_`, the bare registrar domain, `@<domain>`, or `_@<domain>`, all four resolving to the same identity. The last form matters in practice, not just for completeness: a relying party that forces a `name@domain` shape on its login form (Tailscale's custom-OIDC login does) leaves `_@<domain>` as the only way to reach the root identity through that form at all, since neither bare `_` nor bare `@<domain>` fits what the form demands. `normalizeLoginIdentifier` (login.ts) checks the *extracted* name against `"_"` rather than the raw, untrimmed input, so `_` survives having `@domain` sliced off after it, the same way any other identity's name does. No self-service recovery if this password is lost -- see the README's section on resetting it directly against `held_keys.login_secret_hash`.

**`login_secret` can be either generated or user-chosen.** `POST /register` and this registrar's registration page both offer a choice: let the registrar generate a high-entropy secret, or set a password instead (`{"name": "...", "password": "..."}` in the JSON body; a minimum length is enforced, no further composition rules). A generated secret is returned once, in the response, and never again; a chosen password is never echoed back, since the caller already knows it. `.../login-secret` (reissuing) takes the same optional `password` either way -- changing your own credential later works identically to setting it at registration.

### 5.1 Dynamic client registration (RFC 7591)

A relying party no longer needs this registrar's operator to hand-insert an `oidc_clients` row -- `POST /oauth/register-client` is open, unauthenticated self-service, the same posture every other registration endpoint here already has:

```json {linenos=false}
{ "redirect_uris": ["https://app.example.com/callback"], "client_name": "Example App", "token_endpoint_auth_method": "client_secret_basic" }
```

Returns `client_id` (and `client_secret`, unless `token_endpoint_auth_method` was `"none"` -- a public client, e.g. a mobile app or SPA, which authenticates with PKCE alone), plus a `registration_access_token` for `GET /oauth/register-client/<client_id>` (RFC 7592's read operation; update/delete aren't implemented yet). Both the issued `client_secret` and `registration_access_token` are shown exactly once, at registration time, the same convention every other one-time secret in this registrar already follows.

### 5.2 Consent

`/authorize` shows an "*App X* wants access to -- Allow/Deny" screen before issuing a code, remembered per `(ward, client_id)` so a returning user isn't re-asked unless the requested `scope` actually grows. Denying redirects back with `?error=access_denied` and no code, per RFC 6749 §4.1.2.1.

### 5.3 PKCE

Mandatory for every client, confidential or public -- the OAuth 2.1 baseline. `/authorize` refuses to issue a code at all without a `code_challenge` (`S256` only); `/token` treats a stored code somehow missing one as a bug, not a legitimate case to fall back on.

### 5.4 Tokens, refresh, and revocation

The `authorization_code` grant now always returns a `refresh_token` alongside the access/id tokens (`id`/`access` tokens: 1 hour; refresh tokens: 30 days). `grant_type=refresh_token` rotates on every use -- the presented token is marked spent and a new one issued in its place, sharing the same underlying "family." Presenting an already-rotated-away token again (something a legitimate client never does) is treated as evidence of theft: the entire family is revoked, not just the one request denied.

`POST /revoke` (RFC 7009) takes `{ token, token_type_hint? }`. A refresh token is revoked directly; an access/id token (otherwise a stateless, unrevokable JWT) has its `jti` added to a small blocklist that `/userinfo` checks going forward. Revocation is idempotent and always returns `200` regardless of whether the token was recognized, per RFC 7009 §2.2 -- never a way to probe which tokens exist.

Client authentication (where a client has a secret at all) accepts either `Authorization: Basic` or a `client_secret` body parameter, at both `/token` grant types.

### 5.5 `/userinfo` claims, and what's in the `id_token` itself

`/userinfo` always returns `sub`/`name`. `name` falls back to the bare registrar domain for the bare-domain root identity specifically, since its name is `""` (a sentinel, not a display name) and a literal empty string can fail a relying party's validation -- the same fallback `agentCard.ts` already uses for this identity's display name elsewhere. `email`/`email_verified` are included only when the access token's granted `scope` includes `email` *and* this identity has a verified forwarding address on file (§6) -- never invented, never returned for a scope that didn't ask for it. The root identity isn't excluded from this -- see §6's note on how it gets a verifiable email address despite having no name-shaped local part.

**`email`'s value is this ward's canonical `name@domain` -- never the forwarding address it happens to point mail at**, using `_` in place of a name for the bare-domain root specifically (§6). Those are two different facts: forwarding is where mail for this identity currently lands (an arbitrary, changeable third-party mailbox, never itself a second identity), while OIDC's `email` claim is supposed to assert something about *who the user is*. A relying party expecting its `login_hint` and the returned `email` to agree will otherwise see what looks like an identity mismatch, since the two addresses can differ by design. `email_verified: true` means this ward has confirmed, working forwarding configured (proof the identity is reachable by mail at all), not that the asserted `name@domain` address is itself a separately-verified mailbox. This also keeps a ward's actual forwarding destination private: it's this registrar's notification system's business alone, and a relying party asking for the `email` scope learns the Guardian ID being signed in with, never where that identity's mail happens to land today. No `email` claim at all when forwarding isn't configured.

**`email`/`email_verified`, when present, are also duplicated directly into the `id_token`**, not only reachable via a separate `/userinfo` call. This is a deliberate compatibility choice, not spec-mandated (OIDC allows claims to live in either place) -- plenty of real-world relying parties, especially simpler "generic OIDC" integrations, only ever decode the `id_token` and never make a second `/userinfo` round trip. Same exact condition and same shared helper as `/userinfo`'s check, not a duplicated logic path. Beyond those two claims, `id_token` stays minimal: `iss`, `sub` (the DID, not an email), `aud`, `iat`, `exp`, `nonce`, `jti` -- a relying party that auto-matches incoming SSO identities against existing user records by email or username, rather than accepting a bare DID as the subject, may still need that identity invited/mapped manually on its side.

### 5.6 Finding the right registrar (discovery)

This is a client-side problem, not a missing endpoint -- a Guardian identifier already names its registrar (`domain:name`), so an RP's "Login with Guardian" button just needs to turn a person's `alice@acme.com`-shaped input into that domain's `/.well-known/openid-configuration`, then redirect through the ordinary flow above. A minimal reference implementation:

```js {linenos=false}
async function loginWithGuardian(identifier, redirectUri) {
  const [name, domain] = identifier.split("@");
  const discovery = await fetch(`https://${domain}/.well-known/openid-configuration`).then((r) => r.json());
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  sessionStorage.setItem("guardian_code_verifier", verifier); // survives the redirect round-trip
  const url = new URL(discovery.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: MY_CLIENT_ID, redirect_uri: redirectUri, response_type: "code",
    scope: "openid", code_challenge: challenge, code_challenge_method: "S256", login_hint: name,
  });
  location.href = url.toString();
}
```

`login_hint` (the standard OIDC authentication request parameter, already handled by `/authorize`) carries just the name part through to the registrar's login form -- the person never has to type the domain part twice in two different shapes.

## 6. Email forwarding

`POST .../email` (set up forwarding), `GET /verify-email` (confirm a forwarding address). See `packages/server/src/email.ts`.

**The bare-domain root identity uses `_` as its reserved local part** (the same convention §5's login already uses) -- `_@<domain>` both addresses mail to it and is the value `email.ts` writes into `email_forwarding`, so inbound routing (name-keyed at the local part, per `handleEmail`) can find it the same way it finds any named identity. This section's `.../email` endpoint still rejects root outright, though (no name to put in the path) -- root sets up forwarding through `/account/email` instead (§8), the one difference from how a named identity does it. Once set up, its OIDC `email` claim becomes `_@<domain>`, verifiable like any other -- which also means root can now satisfy a relying party that hard-requires an `email` claim (§5.5), something it had no way to do before this existed.

Outbound sending (the verification link itself) goes through `emailProviders.ts`. This registrar's choice of provider is a deployment config, not a protocol or method detail: `EMAIL_PROVIDER` (a `wrangler.jsonc` var) names one of `mailchannels` | `resend` | `cloudflare-native` | `log` (dev-only -- prints instead of sending). Nothing here is specific to this provider list -- adding another is one more small function, never a reason to touch any caller. Unconfigured, outbound sending fails with a clear configuration error rather than a vendor-specific HTTP status.

Every provider except one is a plain `(apiKey, opts) -> Response` function using only `fetch`, no Workers-specific API, and that provider's API key is set as a matching secret (`MAILCHANNELS_API_KEY`/`RESEND_API_KEY`) -- a self-hoster not on Cloudflare, or who'd rather not depend on a Workers-specific feature, picks one of these. `cloudflare-native` is the deliberate exception: Cloudflare's native Email Sending binding (`send_email` in `wrangler.jsonc`), needing no external account or API key at all, just `wrangler email sending enable <domain>` once per domain (Cloudflare then manages the SPF/DKIM records itself) and the Workers Paid plan. guardianspec.org, the live instance this spec documents, uses it.

## 7. Login secret

`POST .../login-secret` (reissue a lost or leaked one). See `packages/server/src/profile.ts`'s `reissueLoginSecret`.

## 8. Account dashboard

Everything above this point is an API, consumed by a relying party's code or an email client's link -- `GET /account` (after `/guardian-login`) is the one page where a person looks at and manages their own identity directly, the same first-party-HTML-page pattern §3's browser page already established. See `packages/server/src/accountPage.ts`.

Shows identity status, current guardians and successor with the identity's policy, the full activity log, anything still waiting on this identity's signature (its proposals collecting against its log, linked to §3's browser page), and every connected OAuth app (§5.2's consent records) with a "Revoke access" button that also kills any live refresh tokens for that app, not just the consent record -- revoking actually revokes, not just "stop remembering." A "Log out" button (§5's `POST /guardian-logout`) sits at the top.

| Method | Path | |
|---|---|---|
| `GET` | `/account` | the dashboard itself |
| `POST` | `/account/rotate` | rotate the identity's key |
| `POST` | `/account/login-secret/reissue` | reissue the login secret (a generated one, shown once, same convention every other one-time secret here follows) -- or, given `password`/`password_confirm` fields instead, set your own password |
| `POST` | `/account/email` | set up forwarding (§6) |
| `GET`/`POST` | `/account/tombstone` | a confirmation page -- requires typing the account's name, not a bare button -- then deactivates |
| `POST` | `/account/consents/revoke` | revoke a connected app's access |

A guardian steps down under its authority, not the ward's -- see `.../remove-self` (§2) or the generic multi-signer path (§3), not this dashboard, for that.

Every action here, including email forwarding, works for the domain's bare-domain root identity too, the same as any named identity, once an operator has given it a login credential (see the top-level README's self-hosting section) -- root uses `_` as its reserved local part for forwarding (§6), the same convention §5's login already established for it.

## 9. Managed Identity API

This section is under revision -- a possible change to how `POST /register` names an initial guardian is awaiting a decision. **What's settled**: the guardian is derived from a validated access token's `sub`, never a client-supplied field -- `POST /register` with `Authorization: Bearer <access_token>` and a token whose own granted `scope` includes `create:managed-identity` identifies who's consenting to become a guardian. A request with no bearer token at all gets the ordinary case: self-service, no guardian. A bearer token present but missing the scope is rejected outright (`403`). **What's under revision**: how the guardian relationship from that consent actually gets established in the new identity's log.

A platform wanting to use this needs its OIDC client (§5.1) and a token for the acting human carrying `create:managed-identity` -- normally obtained the same way any other scope is, through that human's `/authorize` consent. A client that only ever needs this occasionally can request it alongside `openid` at ordinary login time, store the resulting refresh token (§5.4), and mint a fresh access token on demand rather than redirecting through a fresh interactive consent on every single creation.

**The guardian's identity doesn't have to live on this same registrar.** A platform may legitimately onboard a human whose did:guardian identity is hosted elsewhere entirely -- their access token is then issued by *that* registrar, not this one, and a registrar can only verify a JWT signed with a key it actually holds. `FEDERATED_TRUSTED_ISSUERS` (an operator-configured, comma-separated allowlist of other registrar domains) opts this in explicitly: an access token whose `iss` matches a trusted peer is verified against *that peer's* `/.well-known/jwks.json` (fetched fresh, matched by `kid`), never assumed valid just because it claims a trusted domain. An issuer that's neither this registrar itself nor an explicitly trusted peer is rejected outright -- closed by default, the same posture every other access-control decision in this spec takes. `jti`-based revocation (§5.4) is only checked for this registrar's tokens; a federated peer's revocation state isn't visible here, the same limitation any JWT-based federation has without a shared introspection endpoint, bounded by the token's short TTL.

## 10. Delegation-chain tokens (token exchange)

A managed identity (§9) often needs to be *acted as* later, not just created once -- a platform letting its user operate an agent it guards, say. `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) mints a token whose `sub` is a target identity (`resource`, a DID this registrar custodies), given a `subject_token` (the caller's existing access token) proving who's actually asking:

```text {linenos=false}
POST /token
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<the caller's access token>",
  "resource": "did:guardian:acme.com:some-agent",
  "client_id": "...", "client_secret": "..."
}
```

**Authorization checks `resource`'s current state directly.** The caller (the `subject_token`'s `sub`) must be `resource` itself, or named in `resource`'s current `guardians` or `successor`, resolved fresh from `resource`'s log every time -- never a cross-log liveness check, since verifying a log depends only on that log ([REQ-8-2](/docs/did-guardian-spec-v0.2.0/#req-8-2)). Not a guardian, or not the identity itself: `403`. `resource` naming an identity this registrar doesn't hold a key for fails too -- there's no key material to issue a token for it.

**The issued token carries `sub` = the target, and `act: { sub: <the caller's DID> }`** -- the emerging OpenID on-behalf-of shape (`sub`/`act`), not a one-off: anything already built against that draft recognizes a token from this registrar unmodified. No `id_token` -- this isn't a fresh authentication event, just a scoped delegation of an already-authenticated caller's own, separately-proven authority. No refresh token either; the original `subject_token`'s session is what covers re-exchange later.

## 11. A2A (Agent2Agent) interop

A2A's Agent Card -- a JSON manifest advertising an identity's capabilities and how to authenticate with it -- is conventionally served at one fixed path per origin (`/.well-known/agent-card.json`), which doesn't fit this registrar's multi-tenant shape: many identities under one domain. The fixed path stays correct for a single-agent origin; a still-individual-draft WebFinger discovery profile (`draft-zhao-a2a-webfinger-00`) covers exactly the multi-tenant case -- WebFinger is the discovery layer that resolves a *named* identity to wherever its card actually lives, which doesn't have to be that fixed path.

- `GET /.well-known/agent-card.json` -- this domain's bare-domain root identity (its path segment is `_`, per the formal spec's [§4](/docs/did-guardian-spec-v0.2.0/#4-identifier)), satisfying A2A's fixed-path convention for the one identity it actually fits here.
- `GET /.well-known/guardian/<name>/agent-card.json` -- a named identity's card, at a path consistent with every other resolution this registrar already does.
- `GET /.well-known/webfinger?resource=acct:<name>@<domain>` -- resolves a named identity to its card's URL (the JRD shape `draft-zhao-a2a-webfinger-00` itself specifies: `rel: "self"`, `type: "application/a2a+json"`).

Every card here declares `securitySchemes.oidc` (an `OpenIdConnectSecurityScheme` pointing at this registrar's `/.well-known/openid-configuration`) -- how an A2A client authenticates with this identity is just this registrar's OIDC flow, already documented in full above.

**The same WebFinger endpoint also serves OpenID Connect Discovery 1.0's unrelated WebFinger usage** -- `rel=http://openid.net/specs/connect/1.0/issuer` -- which is what a relying party that only has a user's identifier calls first, before ever fetching `/.well-known/openid-configuration` (e.g. a "log in with your identity provider" flow that takes `alice@guardianspec.org` directly, which is how Tailscale's custom-OIDC login discovers an issuer). The `href` returned is always the registrar's bare domain -- there's one OIDC issuer per registrar, not one per ward, so this step only ever confirms the identifier exists here at all. `rel` is a filter per RFC 7033: pass it zero or more times to get only matching links, or omit it to get every link this registrar knows for that resource (both the A2A one and the OIDC one, together).

**Deliberately unsigned in this pass.** A2A's `AgentCardSignature` (JWS, canonicalized) is optional, not required -- plain HTTPS already gives a verifier a weaker binding to this domain. Signing with a ward's own key (already custodied here, already published in its DID Document) is a natural fit for later, not something this first pass needed to block on.

## 12. Resource Indicators (planned MCP interop)

MCP's authorization spec is OAuth 2.1 plus mandatory Resource Indicators (RFC 8707) -- an MCP client treats the tool server it's calling as a *resource*, discovers who issues tokens for it, and asks for a token scoped to that one resource specifically, not a generic token good for anything the OAuth client happens to be. This registrar implements the two RFCs that mechanism needs, below -- but there is no MCP-specific integration yet (no tool-server registration, nothing validated against a real MCP client), so treat this section as what's needed for MCP interop, not MCP interop itself.

**`GET /.well-known/oauth-protected-resource`** (RFC 9728, Protected Resource Metadata): this registrar is both its own authorization server and, for endpoints like `/userinfo`, a protected resource in its own right. The document names itself as both:

```json {linenos=false}
{
  "resource": "https://acme.com",
  "authorization_servers": ["https://acme.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["openid", "email", "create:managed-identity"]
}
```

A `401` from `/userinfo` (missing, invalid, expired, or revoked token) carries a `WWW-Authenticate: Bearer resource_metadata="https://acme.com/.well-known/oauth-protected-resource"` header (RFC 9728 §5.1) -- a generic client discovers the authorization server from the 401 alone, with nothing hardcoded out of band.

**`resource` at `/authorize` and `/token`** (RFC 8707 Resource Indicators): a client naming a `resource` (an absolute URI, no fragment -- e.g. the MCP tool server's URL) at `/authorize` gets an access token whose `aud` is that URI instead of the OAuth client's `client_id` -- the resource server checks a token meant for *it*, not evidence that *some* client authenticated. A refresh request may narrow which resource a fresh token is scoped to, but never introduce one that wasn't already established at the original `/authorize` -- a client that never asked for resource scoping can't add it later through refresh alone.

## 13. Cross-registrar signature relay

A guardian whose key is held by a *different* registrar than the one collecting a proposal can't produce a raw signature themselves -- their private key lives server-side on their own registrar and is never exposed to them. `GET`/`POST /relay-sign` lets them review and sign anyway, from their own registrar, using the key it holds for them.

`GET /relay-sign?domain=<proposal's registrar domain>&op=<pending id>`, `gw_session`-gated: fetches the operation's current status live from `GET https://<domain>/.well-known/guardian/pending/<op>` (the same no-auth, read-only endpoint §3 already documents) and shows it for review -- the operation type, how many proofs it's collected, and the full operation content.

`POST /relay-sign` (same `domain`/`op`, as form fields), re-fetches the same status fresh -- nothing from the `GET` is trusted -- then signs with the key this registrar holds for the logged-in identity and submits the result (`{proof}`) to `POST https://<domain>/.well-known/guardian/pending/<op>/sign`. That endpoint's proof check is unchanged: a stale or buggy relay page can fail a submission, never cause a wrongly-accepted operation.

There's no notification of a cross-registrar signature being needed, and no local record of one once it's been signed -- the same "nothing proactive yet" state §3 is in. Whoever's collecting the proposal has to tell the required signer where to go by some other channel.

## 14. Registration modes and the admin console

This registrar's public instance (guardianspec.org) runs **open**: anyone can `POST /register` and create an account. A different operator -- someone who controls the whole domain, personally or as a business, and wants their own root identity usable everywhere did:guardian is accepted, without exposing that same open door publicly -- instead runs **closed** (`REGISTRATION_MODE=closed`, a `vars` entry in `wrangler.jsonc`, not a secret).

Closed mode blocks only *anonymous* self-service at `/register` -- a bare name with no prior authorization, at all three of its branches (the browser form, the JSON API without a bearer token, and the registration page itself, which shows a plain "registration is closed" message instead of the form). A Managed Identity API bearer token (§9, `create:managed-identity` scope) still works either way, since that caller is already authenticated by a scope-checked token -- in a closed deployment such a token could only ever have come from someone who already has an account there, i.e. one the operator created.

**The admin console** (`GET /admin`, `GET`/`POST /admin/create-account`) is how a closed deployment's operator creates those accounts -- for other people or for agents they manage. Available on every deployment regardless of `REGISTRATION_MODE`; gated to a `gw_session` resolved to the root identity specifically (the identity with no name at all), and `ROOT_WARD_LOGIN_SECRET` (README.md) -- no separate role or permission system.

| Method | Path | |
|---|---|---|
| `GET` | `/admin` | lists every account on this registrar (name, DID, created-at) |
| `GET`/`POST` | `/admin/create-account` | the same generated-secret-or-set-your-own-password choice `/register` offers, no initial guardian -- add one afterward the same way a self-service registration would |
| `GET` | `/admin/apps` | lists every OAuth/OIDC client ("app") dynamically registered against this registrar's provider (§5) |
| `GET`/`POST` | `/admin/apps/new` | register a new OAuth client by hand, as an alternative to dynamic client registration (`POST /oauth/register-client`) -- name plus one or more redirect URIs |
| `POST` | `/admin/apps/<client_id>/delete` | revokes that client's registration entirely |

**v1 scope.** The admin console lists and creates; it doesn't let the root identity view, rotate, or deactivate *someone else's* account -- a bigger question (impersonation/management scope) left for its future discussion. No claim-link credential flow -- an admin-created account's owner changes their password any time afterward through the ordinary account dashboard (§8), the same action available to any self-registered account.

## Changelog

This draft replaces all earlier drafts of this document. Earlier drafts are in the repository history.

Fixes made while integrating this registrar with third-party OIDC relying parties (Tailscale's custom-OIDC login, specifically), kept here rather than narrated inline in the sections above:

- `/authorize` previously let an already-active session from a different login silently continue into a new relying-party flow, with no check against what that flow actually requested -- surfaced as a confusing identity-mismatch error on the relying party's side. Fixed by comparing `login_hint` against the current session (§5).
- `normalizeLoginIdentifier` checked the raw login input against `"_"` instead of the name extracted after slicing off `@domain`, so `_@<domain>` -- the only login form some relying parties' own forms allow for the root identity -- didn't resolve. Fixed (§5).
- `/userinfo`'s `name` claim returned a literal empty string for the root identity, which failed at least one relying party's validation. Fixed with the same domain fallback `agentCard.ts` already used elsewhere (§5.5).
- The `email` claim originally asserted a ward's forwarding destination instead of its canonical `name@domain` address, which both leaked where a ward's mail actually lands and caused a genuine identity-mismatch failure at a relying party that cross-checked `login_hint` against the returned `email`. Fixed (§5.5).
- WebFinger (§11) never applied the `_` -> `""` translation every other root-identity path already used, so `acct:_@<domain>` 404'd. Fixed.
