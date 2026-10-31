---
layout: docs-sidebar
title: "did:guardian Registrar API, v1 (zzmq.dev's own registrar)"
description: "This registrar implementation's own HTTP surface -- the three method-required endpoints plus every convenience endpoint and signature-collection mechanism this specific registrar adds on top."
---
# Registrar API (this registrar's own)

**Version 1.** This document describes exactly one registrar implementation's own HTTP surface (`packages/server` in this repository, deployed as zzmq.dev's registrar). It is versioned and evolves independently of [the formal method specification](/docs/did-guardian-spec-v0.2.0/) -- adding, removing, or reshaping anything here never changes method conformance, and a different registrar implementation is free to expose none of it. Only [§1](#1-method-required-endpoints) restates an actual method requirement; everything else is this registrar's own operational choice.

All endpoints are rooted at `/.well-known/guardian/<name>` (or `/.well-known/guardian/_` for the bare-domain identity). All request/response bodies are JSON unless noted.

## 1. Method-required endpoints

Required by the formal spec's REQ-8-2; this registrar's own implementation of them.

| Method | Path | |
|---|---|---|
| `GET` | `/.well-known/guardian/<name>` | current derived DID Document |
| `GET` | `/.well-known/guardian/<name>/log` | full operation log, timestamped |
| `POST` | `/.well-known/guardian/<name>/operations` | submit one fully-signed operation |

`POST .../operations` accepts any operation type from the formal spec's §7 with all required signatures already attached (per that operation's own REQ-7.x signer rules) and appends it if valid, rejecting with a reason string otherwise. This is the only path by which an *externally* pre-signed operation (e.g. two guardians who coordinated their own signatures out-of-band) reaches the log directly, without going through §3's collection machinery.

## 2. Self-contained convenience endpoints

Each of these corresponds to an operation whose formal signer requirement can be satisfied by a single call from one authenticated party, with this registrar producing every needed signature itself from keys it already custodies -- no new authority is ever granted to a third party by any of these, which is what makes a single bare call safe. Auth model, uniformly: either an active `gw_session` cookie for the target identity itself, or a trusted OIDC client credential (Basic auth) acting on an already-verified decision made by its own caller (e.g. zz, having already confirmed its own user is a current guardian, before ever calling here).

| Method | Path | Operation produced | Why it's self-contained |
|---|---|---|---|
| `POST` | `.../rotate` | `custodial_rotate`, ward-signed | self-rotation grants no new authority |
| `POST` | `.../remove-self` | `guardian_remove`, voluntary (`outgoing = [caller]`) | needs only the caller's own consent (REQ-7.2-7a) |
| `POST` | `.../remove` | `guardian_remove`, forced | self-contained **only** when the *other* current guardians (excluding the one being removed) are custodied entirely by this registrar **and** that custodied subset alone meets `removal_threshold` (REQ-7.2-7b); otherwise rejected, directing the caller to §3 |
| `POST` | `.../relinquish` | `guardian_relinquish` | self-contained **only** when the current guardian set is custodied entirely by this registrar **and** that custodied subset alone meets `removal_threshold` (e.g. a sole guardian, trivially); otherwise rejected with a clear reason directing the caller to §3 |
| `POST` | `.../tombstone` | `custodial_tombstone`, ward-signed | `tombstone_threshold` defaults to `any`; the ward's own key alone always suffices. If the identity is itself a current guardian of anything, see §4's own acceptance/cascade policy first |
| `POST` | `.../adopt` | `guardian_add`, zero-to-one case only | needs only the incoming party's own consent plus the ward's own key (REQ-7.2-5) -- rejected if the ward already has any current guardian; use §3 for a non-empty guardian set |

## 3. Asynchronous signature collection (`pending_operations`)

For anything needing more than one signature collected over more than one request -- `guardian_add` against a non-empty guardian set (REQ-7.2-4), a forced `guardian_remove` (REQ-7.2-7b), `policy_update` (REQ-7.2-9), or a `guardian_relinquish`/guardian-initiated `custodial_rotate` whose required signers aren't all custodied by (or available in the same call to) this registrar.

Modeled as a state machine per pending proposal: `proposed -> collecting -> satisfied -> finalized`, with `expired` and `declined` as terminal alternatives. `finalized` is entered automatically the instant `satisfied` is reached (the registrar submits the now-complete operation to §1's own `/operations` itself) -- a caller never finalizes by hand.

A proposal can stay `collecting` for up to 7 days, long enough that a signer might rotate their own, unrelated operational key before everyone else has signed. This registrar records when it collected each signature and, at finalize time, verifies each one against whichever key its own signer held *then* (REQ-4-2) -- never against whatever's current by the time the last signature finally arrives. A signer rotating their own key mid-vote never invalidates a signature they already gave.

`decline` and `withdraw` are two distinct operations with different authority, not one action with a policy-configurable effect:

- **`decline` is a veto.** Any current, live guardian of the ward -- checked live, not just whoever this registrar's own advisory "required signers" guess happened to list -- can kill the proposal outright by declining, whether or not they'd already signed. Unconditional: it doesn't matter how many others had already approved. Allowed from `collecting` *or* `satisfied` (nothing is actually irreversible until it's truly in the log -- `satisfied` can still be sitting there unfinalized in the rare case a prior finalize attempt failed and is awaiting retry). Rejected once `finalized`/`declined`/`expired` -- none of those have an undo. One deliberate exception to "must already be a current guardian": `guardian_add`'s own `incoming` party can always decline a proposal naming them, live or not -- `guardianAddRule` (packages/lib) requires their own consent unconditionally, genesis or not, so the operation can never be satisfied without it regardless; declining your own nomination is a refusal, not an exercise of governance power over someone else's proposal, and it's the same single verb rather than a different one for that one case.
- **`withdraw` is a non-binding opt-out.** "Don't wait on me" -- removes the withdrawing party's own signature from consideration if they'd already contributed one, but never blocks anyone else from still reaching the threshold through some other combination. Only valid from `collecting` (once satisfied, nobody's waiting on anyone). A signer who withdrew can still change their mind and sign later; withdrawing isn't a lockout.

Both accept two different kinds of proof, either is equally valid:

- A **signed request** (`POST`, body `{signer_did, sig}`) -- `sig` over the canonical payload `{action: "decline"|"withdraw", pending_operation_id: <id>}`. Works for anyone who can produce a signature, local or external to this registrar.
- A **token-based link** (`GET`, `?token=...`) -- the same trust model this registrar's own email-verification-link flow already uses: a random, unguessable token issued the first time a given signer is notified about a given proposal, usable by anyone who received it (possession of the verified email is the proof, not a signature). This is what makes the one-click links in the notification emails below work without needing real browser-side cryptography, and it works for an externally-hosted guardian too -- the limiting factor was always whether this registrar has a verified way to reach them, never who custodies their key.

| Method | Path | |
|---|---|---|
| `POST` | `.../propose` | create a pending proposal for one operation type + its intended content, with the proposer's own signature attached if they're a required signer |
| `POST` | `.../pending/<id>/sign` | a required signer not yet counted adds their own signature |
| `POST` | `.../pending/<id>/sign-as-self` | `gw_session`-gated: signs server-side with the key this registrar already custodies for the logged-in identity, same model as `.../adopt`/`.../rotate` |
| `POST` or `GET` | `.../pending/<id>/decline` | veto -- POST with a signed or form body, or GET with `?token=...` |
| `POST` or `GET` | `.../pending/<id>/withdraw` | opt-out -- same proof options |
| `GET` | `.../pending/<id>` | content-negotiated: `Accept: text/html` renders the browser voting page below; anything else returns the same status JSON as always (required signers, who has signed, state) |
| `GET` | `/api/me/pending-signatures` | every pending proposal naming the caller as a required signer who hasn't yet signed |

A proposal not reaching `satisfied` within 7 days moves to `expired` -- always a failure, never an automatic pass; nothing in this method or this registrar advances a proposal just because time ran out. A required signer discovers a pending proposal by polling `/api/me/pending-signatures` or by email (§6) -- every state-moving event (propose, each signature, decline, withdraw, finalize) sends one, plus a daily reminder for anyone who still hasn't acted on a `collecting` proposal, explaining that consequence in plain terms.

**The browser voting page.** Every notification email links here (with a token, if one was issued) rather than to an action endpoint directly -- deliberately: an email client's own link-prefetching security scanner (Microsoft Safe Links, a corporate proxy, antivirus) visits a link the instant a message arrives, long before a person reads it, so a link that performed the action itself could be "voted" by the scanner, never by the person it was addressed to. The page shows state, required signers (with who's signed), and expiry, and -- only while `collecting` -- real buttons that each `POST`:

- **Decline / Withdraw**, shown whenever a valid `?token=` is present in the URL -- the token itself is the proof, same as the API's own token path.
- **Sign**, shown only when the viewer is authenticated (§5's own `gw_session`) as a required signer who hasn't yet signed -- signing is held to a higher bar than decline/withdraw because it grants real authority (e.g. a new guardian), so the email token alone isn't treated as sufficient; a logged-out viewer instead sees a link to §5's own login page. Only ever available for a locally-custodied identity, same limit every session-gated convenience endpoint already has.

## 4. Guardian deactivation policy

Entirely this registrar's own operational choice -- the formal spec (REQ-4-4) only requires that a deactivated guardian stop counting toward any threshold once its own `custodial_tombstone` lands; it says nothing about whether this registrar *accepts* that submission in the first place, or what else it does in response. Reused across both `.../tombstone` and any `pending_operations`-collected `custodial_tombstone` for a current guardian.

- **Acceptance**: this registrar's own configuration determines whether a `custodial_tombstone` for an identity that is still a current guardian of one or more wards is accepted outright, or rejected (directing the caller to first issue `guardian_remove`/`guardian_relinquish` against each ward it guards) -- a referential-integrity-style block, same spirit as a SQL foreign key.
- **Proactive handling (recommended over reactive, when the outgoing guardian is cooperating)**: this registrar *SHOULD* prefer to resolve `on_orphan: {"transfer_to": ...}` *before* a sole guardian's own `custodial_tombstone` is even accepted, not after -- the same add-then-remove discipline §4.3's own ordinary transfer already uses. While the outgoing guardian is still the ward's sole guardian, `guardian_add`'s own non-empty-set rule (REQ-7.2-4) applies, not the harder zero-to-one one: `addition_threshold` evaluated at `N=1` is `majority = 1`, so the outgoing guardian's own signature alone satisfies it. Sequencing `guardian_add(fallback)` then `guardian_remove(outgoing, voluntary)` *before* accepting the outgoing guardian's own tombstone means the ward is never actually orphaned at any point, and the whole handoff only ever needs the *outgoing guardian's own key* (plus the fallback's, trivial when it's this registrar's own bare-domain root) -- the orphaned ward's own operational key is never touched, exactly as easy as the `"tombstone"` case below. This is only available while the outgoing guardian is cooperatively initiating its own tombstone request, not after the fact.
- **Reactive cascade, if offered**: when a ward's effective guardian set becomes empty with no opportunity for the proactive handling above to have run first -- a forced tombstone using a compromised key, or a sole guardian simply going unreachable without ever cooperating -- any automatic follow-up action this registrar takes on the affected ward's behalf *MUST* consult that ward's own `GuardianPolicy.min_guardian_count` and `on_orphan` (formal spec REQ-5-7/REQ-5-8) individually -- never one blanket behavior applied to every affected ward alike. If removing this guardian would leave a ward below its own `min_guardian_count`, that ward's own removal is refused even if the overall tombstone is otherwise accepted for the guardian's other wards. If it would leave a ward with zero guardians, that ward's own `on_orphan` states what this registrar should try to do next for it specifically, and the three values are not equally reachable in one call:
  - `"sovereign"` needs nothing further -- REQ-4-4's own exclusion already produces an empty guardian set from the existing log alone, no operation to construct.
  - `"tombstone"` needs a self-signed `custodial_tombstone` for the orphaned ward -- only ever needs *that ward's own* operational key (`tombstone_threshold` defaults to `any`, REQ-7.3-1), so this registrar can always do it unilaterally in the same call, provided it custodies that one ward's own key, with no dependency on any other party.
  - `{"transfer_to": ...}` now genuinely needs the harder zero-to-one `guardian_add` -- the proactive path above is no longer available, since the guardian set is already empty, so REQ-7.2-5 applies: *two* parties' keys together, the named DID's own consent and the orphaned ward's own key. Naming this registrar's own bare-domain root identity makes the first one trivial, but it still can't complete without the ward's own key too -- available in the same call only when the ward itself is also fully custodied here.

  Neither of the last two is ever something the library's own verification functions can produce on their own, regardless of policy -- both require this registrar to actually hold the signing key material behind at least one required signer. When any required signer's key isn't available in the same call, this registrar falls back to §3's own pending-operations collection instead of refusing outright -- proposing the operation with whichever signatures it can already supply, then waiting on the rest, same as any other multi-party operation; it may never complete if the missing signer is never reachable, same limitation §3 already has.
- **Creation-time policy defaults**: this registrar's own configured default `GuardianPolicy` (including its own default `on_orphan`/`min_guardian_count`) applies to any field a creator leaves unset in `custodial_create`'s own optional `policy` (formal spec REQ-7.1-7); unconfigured fields fall back to the formal spec's own stated defaults.

## 5. Login / OIDC

Two independent flows share the same underlying credential (`login_secret`) and the same `gw_session` cookie, for two different purposes:

- `/authorize`, `/token`, `/userinfo`, `/revoke`, `/oauth/register-client`, `/.well-known/openid-configuration`, `/.well-known/jwks.json` -- the OIDC relying-party flow, for a third-party application that wants to let someone sign in with their Guardian ID. See `packages/server/src/oidc.ts`.
- `GET`/`POST /guardian-login?return_to=<path>` -- this registrar's own first-party login, for this registrar's own pages (currently just §3's browser voting page). No client registration: it's just "sign in, then take me back to the same-origin path that sent me here" (`return_to` is restricted to a relative path -- no open redirect to an external target). See `votingPage.ts`.

Named `/guardian-login`, not the shorter `/login` -- a real collision, not a style choice: a registrar is commonly deployed on a domain that already has its own, unrelated human-facing `/login` (zz's own deployment on zzmq.dev does, for its own web app). Worth checking your own host application's routes before adding any new top-level path here, not just this one.

**The bare-domain root identity logs in like any other ward**, once an operator has given it a credential (`ROOT_WARD_LOGIN_SECRET`, see the top-level README's own self-hosting section) -- the name field on either login form accepts `_`, the bare registrar domain, or `@<domain>`, all three resolving to the same identity.

**`login_secret` can be either generated or user-chosen.** `POST /register` (§1) and this registrar's own registration page both offer a choice: let the registrar generate a high-entropy secret (the only option before this), or set a password instead (`{"name": "...", "password": "..."}` in the JSON body; a minimum length is enforced, no further composition rules). A generated secret is returned once, in the response, and never again; a chosen password is never echoed back, since the caller already knows it. Reissuing (`.../login-secret`, §2) takes the same optional `password` either way -- changing your own credential later works identically to setting it at registration.

### 5.1 Dynamic client registration (RFC 7591)

A relying party no longer needs this registrar's own operator to hand-insert an `oidc_clients` row -- `POST /oauth/register-client` is open, unauthenticated self-service, the same posture every other registration endpoint here already has:

```json
{ "redirect_uris": ["https://app.example.com/callback"], "client_name": "Example App", "token_endpoint_auth_method": "client_secret_basic" }
```

Returns `client_id` (and `client_secret`, unless `token_endpoint_auth_method` was `"none"` -- a public client, e.g. a mobile app or SPA, which authenticates with PKCE alone), plus a `registration_access_token` for `GET /oauth/register-client/<client_id>` (RFC 7592's read operation; update/delete aren't implemented yet). Both the issued `client_secret` and `registration_access_token` are shown exactly once, at registration time, the same convention every other one-time secret in this registrar already follows.

### 5.2 Consent

`/authorize` shows a real "*App X* wants access to -- Allow/Deny" screen before issuing a code, remembered per `(ward, client_id)` so a returning user isn't re-asked unless the requested `scope` actually grows. Denying redirects back with `?error=access_denied` and no code, per RFC 6749 §4.1.2.1.

### 5.3 PKCE

Mandatory for every client, confidential or public -- the OAuth 2.1 baseline. `/authorize` refuses to issue a code at all without a `code_challenge` (`S256` only); `/token` treats a stored code somehow missing one as a bug, not a legitimate case to fall back on.

### 5.4 Tokens, refresh, and revocation

The `authorization_code` grant now always returns a `refresh_token` alongside the access/id tokens (`id`/`access` tokens: 1 hour; refresh tokens: 30 days). `grant_type=refresh_token` rotates on every use -- the presented token is marked spent and a new one issued in its place, sharing the same underlying "family." Presenting an already-rotated-away token again (something a legitimate client never does) is treated as evidence of theft: the entire family is revoked, not just the one request denied.

`POST /revoke` (RFC 7009) takes `{ token, token_type_hint? }`. A refresh token is revoked directly; an access/id token (otherwise a stateless, unrevokable JWT) has its own `jti` added to a small blocklist that `/userinfo` checks going forward. Revocation is idempotent and always returns `200` regardless of whether the token was recognized, per RFC 7009 §2.2 -- never a way to probe which tokens exist.

Client authentication (where a client has a secret at all) accepts either `Authorization: Basic` or a `client_secret` body parameter, at both `/token` grant types.

### 5.5 `/userinfo` claims

Always `sub`/`name`. `email`/`email_verified` are included only when the access token's own granted `scope` includes `email` *and* this identity has a verified forwarding address on file (§6) -- never invented, never returned for a scope that didn't ask for it.

### 5.6 Finding the right registrar (discovery)

This is a client-side problem, not a missing endpoint -- a Guardian identifier already names its own registrar (`domain:name`), so an RP's own "Login with Guardian" button just needs to turn a person's `alice@acme.com`-shaped input into that domain's own `/.well-known/openid-configuration`, then redirect through the ordinary flow above. A minimal reference implementation:

```js
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

`login_hint` (the standard OIDC authentication request parameter, already handled by `/authorize`) carries just the name part through to the registrar's own login form -- the person never has to type the domain part twice in two different shapes.

## 6. Email forwarding

`POST .../email` (set up forwarding), `GET /verify-email` (confirm a forwarding address). See `packages/server/src/email.ts`. Reused, not modified, by §3's own signer-notification need.

Outbound sending (the verification link itself, and every §3 notification) goes through `emailProviders.ts`. This registrar's own choice of provider is a deployment config, not a protocol or method detail: `EMAIL_PROVIDER` (a `wrangler.jsonc` var) names one of `mailchannels` | `resend` | `cloudflare-native` | `log` (dev-only -- prints instead of sending). Nothing here is specific to this provider list -- adding another is one more small function, never a reason to touch any caller. Unconfigured, outbound sending fails with a clear configuration error rather than a vendor-specific HTTP status.

Every provider except one is a plain `(apiKey, opts) -> Response` function using only `fetch`, no Workers-specific API, and that provider's own API key is set as a matching secret (`MAILCHANNELS_API_KEY`/`RESEND_API_KEY`) -- a self-hoster not on Cloudflare, or who'd rather not depend on a Workers-specific feature, picks one of these. `cloudflare-native` is the deliberate exception: Cloudflare's own native Email Sending binding (`send_email` in `wrangler.jsonc`), needing no external account or API key at all, just `wrangler email sending enable <domain>` once per domain (Cloudflare then manages the SPF/DKIM records itself) and the Workers Paid plan. Both registrars this spec documents (zzmq.dev, guardianspec.org) use it.

## 7. Login secret

Unchanged -- `POST .../login-secret` (reissue a lost or leaked one). See `packages/server/src/registrar.ts`'s `reissueLoginSecret`.

## 8. Account dashboard

Everything above this point is an API, consumed by a relying party's own code or an email client's link -- `GET /account` (after `/guardian-login`) is the one page where a person looks at and manages their own identity directly, the same first-party-HTML-page pattern §3's own voting page already established. See `packages/server/src/accountPage.ts`.

Shows identity status, current guardians and the effective `GuardianPolicy` thresholds, the full activity log, anything still waiting on this identity's own signature (linked to §3's voting page), and every connected OAuth app (§5.2's own consent records) with a "Revoke access" button that also kills any live refresh tokens for that app, not just the consent record -- revoking actually revokes, not just "stop remembering."

| Method | Path | |
|---|---|---|
| `GET` | `/account` | the dashboard itself |
| `POST` | `/account/rotate` | rotate the operational key |
| `POST` | `/account/login-secret/reissue` | reissue the login secret (a generated one, shown once, same convention every other one-time secret here follows) -- or, given `password`/`password_confirm` fields instead, set your own password |
| `POST` | `/account/email` | set up forwarding (§6) |
| `POST` | `/account/relinquish` | relinquish all guardians |
| `GET`/`POST` | `/account/tombstone` | a real confirmation page -- requires typing the account's own name, not a bare button -- then deactivates |
| `POST` | `/account/consents/revoke` | revoke a connected app's own access |

Every action here works for the domain's own bare-domain root identity too, the same as any named ward, once an operator has given it a login credential (see the top-level README's own self-hosting section) -- **except email forwarding**, which stays unreachable for it specifically: inbound mail routing is name-keyed at the local-part level, and the root identity has no local part to receive mail at.

## 9. Managed Identity API

`POST /register` already exists for plain self-service (§1 restates the method's own requirements; registering a brand-new, guardian-less identity has always been part of that). This section is about the one case that's genuinely different: an agent-hosting platform (zz's own managed-identity feature is the motivating example, not the only one) wants to create a *new* identity with a real human as its real, signed guardian from the moment it exists -- never ownerless, and never guarded by the platform itself.

**The guardian is derived from a validated access token's own `sub`, never a client-supplied field.** `POST /register` with `Authorization: Bearer <access_token>` and a token whose own granted `scope` includes `create:managed-identity` creates the new ward with that token's own `sub` as its guardian. A request with no bearer token at all still gets the ordinary case: self-service, no guardian. A bearer token present but missing the scope is rejected outright (`403`), not silently downgraded to "no guardian."

This replaces an earlier, real gap: a `guardian_did` field in the request body, honored for any client that could authenticate with Basic auth (the same credential used at `/token`). Before dynamic client registration (§5.1) existed, that credential meant "a client the registrar operator hand-vetted" -- a real, if implicit, trust signal. Once registration became open and self-service, *any* caller could authenticate as *some* client and name *any other ward on this same registrar* as the guardian of a brand-new identity, with no verification that the named party ever consented -- a real way to falsely imply a trust relationship (e.g. a new identity that looks vouched-for by a well-known account) that was never actually granted. Deriving the guardian from a real access token closes this: the named guardian is always whoever the token proves is authenticated, and that person granted the scope explicitly, on the ordinary `/authorize` consent screen (§5.2) -- the same real, revocable consent every other scope already requires, not a client's own unverifiable say-so.

A platform wanting to use this needs its own OIDC client (§5.1) and a token for the acting human carrying `create:managed-identity` -- normally obtained the same way any other scope is, through that human's own `/authorize` consent. A client that only ever needs this occasionally can request it alongside `openid` at ordinary login time, store the resulting refresh token (§5.4), and mint a fresh access token on demand rather than redirecting through a fresh interactive consent on every single creation.

**The guardian's own identity doesn't have to live on this same registrar.** A platform may legitimately onboard a human whose did:guardian identity is hosted elsewhere entirely -- their own access token is then issued by *that* registrar, not this one, and a registrar can only verify a JWT signed with a key it actually holds. `FEDERATED_TRUSTED_ISSUERS` (an operator-configured, comma-separated allowlist of other registrar domains) opts this in explicitly: an access token whose `iss` matches a trusted peer is verified against *that peer's own* `/.well-known/jwks.json` (fetched fresh, matched by `kid`), never assumed valid just because it claims a trusted domain. An issuer that's neither this registrar itself nor an explicitly trusted peer is rejected outright -- closed by default, the same posture every other access-control decision in this spec takes. `jti`-based revocation (§4) is only checked for this registrar's own tokens; a federated peer's own revocation state isn't visible here, the same limitation any JWT-based federation has without a shared introspection endpoint, bounded by the token's own short TTL.

## 10. Delegation-chain tokens (token exchange)

A managed identity (§9) often needs to be *acted as* later, not just created once -- a platform letting its own user operate an agent it guards, say. `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) mints a token whose `sub` is a target identity (`resource`, a DID this registrar custodies), given a `subject_token` (the caller's own existing access token) proving who's actually asking:

```
POST /token
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<the caller's own access token>",
  "resource": "did:guardian:acme.com:some-agent",
  "client_id": "...", "client_secret": "..."
}
```

**Authorization is the same live-guardian check used everywhere else a guardian's own standing matters** -- never a reimplementation: the caller (the `subject_token`'s own `sub`) must be `resource` itself, or a current, live guardian of it, checked fresh against `resource`'s own operation log every time (`@did-guardian/lib`'s own `liveGuardians`). Not a guardian, or not the identity itself: `403`. `resource` naming an identity this registrar doesn't custody fails too -- there's no key material to issue a token for it.

**The issued token carries `sub` = the target, and `act: { sub: <the caller's own DID> }`** -- the emerging OpenID on-behalf-of shape (`sub`/`act`), not a one-off: anything already built against that draft recognizes a token from this registrar unmodified. No `id_token` -- this isn't a fresh authentication event, just a scoped delegation of an already-authenticated caller's own, separately-proven authority. No refresh token either; the original `subject_token`'s own session is what covers re-exchange later.

## 11. A2A (Agent2Agent) interop

A2A's own Agent Card -- a JSON manifest advertising an identity's capabilities and how to authenticate with it -- is conventionally served at one fixed path per origin (`/.well-known/agent-card.json`), which doesn't fit this registrar's own multi-tenant shape: many identities under one domain. Confirmed against both the current A2A spec and a very recent (August 2026), still individual-draft WebFinger discovery profile for exactly this problem (`draft-zhao-a2a-webfinger-00`) before writing any of this -- the fixed path remains correct for a single-agent origin and isn't deprecated, and WebFinger is the discovery layer that resolves a *named* identity to wherever its own card actually lives, which doesn't have to be that fixed path.

- `GET /.well-known/agent-card.json` -- this domain's own bare-domain root identity (spec §2.1), satisfying A2A's own fixed-path convention for the one identity it actually fits here.
- `GET /.well-known/guardian/<name>/agent-card.json` -- a named ward's own card, at a path consistent with every other resolution this registrar already does.
- `GET /.well-known/webfinger?resource=acct:<name>@<domain>` -- resolves a named identity to its own card's real URL (the JRD shape `draft-zhao-a2a-webfinger-00` itself specifies: `rel: "self"`, `type: "application/a2a+json"`).

Every card here declares `securitySchemes.oidc` (an `OpenIdConnectSecurityScheme` pointing at this registrar's own `/.well-known/openid-configuration`) -- how an A2A client authenticates with this identity is just this registrar's own OIDC flow, already documented in full above.

**Deliberately unsigned in this pass.** A2A's own `AgentCardSignature` (JWS, canonicalized) is optional, not required -- plain HTTPS already gives a verifier a real, if weaker, binding to this domain. Signing with a ward's own operational key (already custodied here, already published in its own DID Document) is a natural fit for later, not something this first pass needed to block on.

## 12. MCP interop

MCP's own authorization spec is OAuth 2.1 plus mandatory Resource Indicators (RFC 8707) -- an MCP client treats the tool server it's calling as a *resource*, discovers who issues tokens for it, and asks for a token scoped to that one resource specifically, not a generic token good for anything the OAuth client happens to be. Two additions, both strictly additive -- every existing client that never sends a `resource` keeps getting exactly the behavior it already had.

**`GET /.well-known/oauth-protected-resource`** (RFC 9728, Protected Resource Metadata): this registrar is both its own authorization server and, for endpoints like `/userinfo`, a protected resource in its own right. The document names itself as both:

```json
{
  "resource": "https://acme.com",
  "authorization_servers": ["https://acme.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["openid", "email", "create:managed-identity"]
}
```

A `401` from `/userinfo` (missing, invalid, expired, or revoked token) carries a `WWW-Authenticate: Bearer resource_metadata="https://acme.com/.well-known/oauth-protected-resource"` header (RFC 9728 §5.1) -- a generic client discovers the authorization server from the 401 alone, with nothing hardcoded out of band.

**`resource` at `/authorize` and `/token`** (RFC 8707 Resource Indicators): a client naming a `resource` (an absolute URI, no fragment -- e.g. the MCP tool server's own URL) at `/authorize` gets an access token whose `aud` is that URI instead of the OAuth client's own `client_id` -- the resource server checks a token meant for *it*, not evidence that *some* client authenticated. A refresh request may narrow which resource a fresh token is scoped to, but never introduce one that wasn't already established at the original `/authorize` -- a client that never asked for resource scoping can't add it later through refresh alone.

## 13. Cross-registrar signature relay

§3 noted in passing that for a foreign required signer, "the limiting factor was always whether this registrar has a verified way to reach them, never who custodies their key." This section closes that gap for a fully custodial guardian -- one whose private key lives server-side on their own registrar and is never exposed to them, so they can't produce a raw signature the way a self-held-key external guardian can via `.../pending/<id>/sign` directly.

**The problem this solves.** `guardian_add` against an empty guardian set, when `incoming` is hosted on a different registrar (REQ-7.2-5), already falls back to §3's own pending-operations collection -- the ward's registrar proposes the operation and waits correctly. But the guardian's own registrar previously had no way to know that proposal existed at all (its own notification email lookup finds nothing, since email forwarding is set up per-registrar and this guardian isn't a local ward here), and even if told by hand, had no mechanism to produce a signature on the guardian's behalf. Entirely additive: no change to any existing endpoint's own behavior, no new crypto, no new federation configuration.

**`POST /.well-known/guardian/relay-notify`** -- a best-effort, advisory push from a ward's registrar to a required signer's own registrar, sent alongside every ordinary `notifyAwaitingSignature`/`notifyProgress` email for a signer this registrar doesn't custody:

```json
{ "ward_did": "did:guardian:acme.com:alice", "pending_operation_id": "<id>", "signer_did": "did:guardian:otherdomain.com:bob" }
```

Never trusted blindly. The receiving registrar only ever uses this to independently re-fetch the real status from `GET .../pending/<id>` on the *ward's* own registrar (the same no-auth, read-only endpoint §3 already documents) before acting -- confirming the operation is real, still `collecting` or `satisfied`, and `signer_did` is genuinely a required signer who hasn't already signed. If `signer_did` isn't a local ward here, or the independent fetch fails or doesn't confirm, this silently no-ops. A caller whose peer doesn't implement this endpoint at all, or is simply unreachable, loses nothing beyond the proactive notification -- the ward can still share the pending-op link by hand, the same fallback that's always existed.

`GET .../pending/<id>`'s own JSON response (§3) now additionally carries `unsigned_payload`: the operation minus `sig`/`sigs`, exactly the bytes a signer needs to reproduce. Not new information in principle -- a pending operation's own existence and required signers were never secret -- just not previously exposed in machine-usable form.

**`GET`/`POST /relay-sign`** -- the guardian's own review page, on *their* registrar, `gw_session`-gated like every other session-scoped convenience endpoint. `GET /relay-sign?ward=<ward_did>&op=<id>` fetches the live status from the ward's registrar, confirms the logged-in identity is actually a required signer, and shows the operation type, ward, and full payload for review. Two real actions from there, `POST`ed back to the same page (same query parameters as form fields) and re-verified server-side on every one -- nothing from the `GET` is ever trusted:

- **Approve & sign** -- signs with `decryptWardPrivateKey` + `signPayload`, the identical pair `.../sign-as-self` (§2) already uses for same-registrar operations, and submits the result to the ward registrar's own `.../pending/<id>/sign`. That endpoint's own signature verification (§3, against the signer's real resolved key) is completely unchanged -- a forged or buggy relay notification can waste an email or fail a submission, never cause a wrongly-satisfied operation.
- **Decline** -- signs `{ action: "decline", pending_operation_id }` and submits it to the ward registrar's existing `.../pending/<id>/decline`, which already accepts a signed body from anyone who can produce a valid signature over it (§3's `resolveActor`) -- the exact mechanism a local guardian's own decline already uses. A real, authoritative decline, not a local dismiss: it always blocks the proposal, whether as a current guardian's veto or, per §3's own documented exception, as a `guardian_add`'s own `incoming` party refusing their own nomination -- one verb rather than a different one (withdraw) for a case that was already functionally equivalent to a veto for that op type.

Live-verified end to end on the real `zzmq.dev`/`guardianspec.org` pair, not simulated, twice: a real custodial ward on `guardianspec.org` proposing `guardian_add` naming a real custodial guardian on `zzmq.dev` (via a full OIDC dynamic-client-registration + PKCE + Managed Identity API flow, same as §9's own live test) -- first confirmed the relay-notify-triggered inbox entry appeared on `zzmq.dev` and that declining correctly reached a terminal `declined` state on `guardianspec.org`, not just `zzmq.dev`'s local view of it, after `declineOperation` (§3) was updated to allow this specific case.

**Persistent inbox for incoming relay requests**, closing what was v1's other real gap: a durable `relay_inbox` row (one per signer + pending operation, upserted on every `relay-notify`) now exists independently of whether the one-shot notification email ever lands. The account dashboard (§8) shows it as its own "Needs your signature (another registrar)" section, alongside the existing local one. This is an index for discovery only, never a cache of truth -- opening any entry still always re-fetches the real, live status from the ward's own registrar first, the same as it always has; the row is marked resolved once *this* registrar has actually signed or declined on the signer's behalf, not before.

## 14. Registration modes and the admin console

This registrar's own public instances (zzmq.dev, guardianspec.org) run **open**: anyone can `POST /register` and create an account, the behavior documented in §1. A different operator -- someone who controls the whole domain, personally or as a business, and wants their own root identity (§2.1 of the formal spec) usable everywhere did:guardian/did:web is accepted without exposing that same open door publicly -- instead runs **closed** (`REGISTRATION_MODE=closed`, a `vars` entry in `wrangler.jsonc`, not a secret).

Closed mode blocks only *anonymous* self-service at `/register` -- a bare name with no prior authorization, at all three of its branches (the browser form, the JSON API without a bearer token, and the registration page itself, which shows a plain "registration is closed" message instead of the form). A Managed Identity API bearer token (§9, `create:managed-identity` scope) still works either way, since that caller is already authenticated by a real, scope-checked token -- in a closed deployment such a token could only ever have come from someone who already has an account there, i.e. one the operator created.

**The admin console** (`GET /admin`, `GET`/`POST /admin/create-account`) is how a closed deployment's own operator creates those accounts -- for other people or for agents they manage. Available on every deployment regardless of `REGISTRATION_MODE`; gated to a `gw_session` resolved to the root identity specifically, the same `wards.name === ""` sentinel §2.1 and `ROOT_WARD_LOGIN_SECRET` (README.md) already establish -- no separate role or permission system.

| Method | Path | |
|---|---|---|
| `GET` | `/admin` | lists every account on this registrar (name, DID, created-at) |
| `GET`/`POST` | `/admin/create-account` | the same generated-secret-or-set-your-own-password choice `/register` offers (§1), plus an optional `guardian_did` -- `registerWard`'s own existing param, the same one the Managed Identity API already uses, so an admin can name an initial guardian (e.g. themselves) at creation time instead of adding one later |

**v1 scope.** The admin console lists and creates; it doesn't let the root identity view, rotate, or tombstone *someone else's* account -- a bigger question (impersonation/management scope) left for its own future discussion. No claim-link credential flow -- an admin-created account's own owner changes their password any time afterward through the ordinary account dashboard (§8), the same action available to any self-registered account.
