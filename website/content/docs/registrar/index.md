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

`decline` and `withdraw` are two distinct operations with different authority, not one action with a policy-configurable effect:

- **`decline` is a veto.** Any current, live guardian of the ward -- checked live, not just whoever this registrar's own advisory "required signers" guess happened to list -- can kill the proposal outright by declining, whether or not they'd already signed. Unconditional: it doesn't matter how many others had already approved. Allowed from `collecting` *or* `satisfied` (nothing is actually irreversible until it's truly in the log -- `satisfied` can still be sitting there unfinalized in the rare case a prior finalize attempt failed and is awaiting retry). Rejected once `finalized`/`declined`/`expired` -- none of those have an undo.
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

- `/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration`, `/.well-known/jwks.json` -- the OIDC relying-party flow, for a third-party application that wants to let someone sign in with their Guardian ID. Requires a pre-registered `client_id`/`redirect_uri`. See `packages/server/src/oidc.ts`.
- `GET`/`POST /guardian-login?return_to=<path>` -- this registrar's own first-party login, for this registrar's own pages (currently just §3's browser voting page). No client registration: it's just "sign in, then take me back to the same-origin path that sent me here" (`return_to` is restricted to a relative path -- no open redirect to an external target). See `votingPage.ts`.

Named `/guardian-login`, not the shorter `/login` -- a real collision, not a style choice: a registrar is commonly deployed on a domain that already has its own, unrelated human-facing `/login` (zz's own deployment on zzmq.dev does, for its own web app). Worth checking your own host application's routes before adding any new top-level path here, not just this one.

## 6. Email forwarding

Unchanged -- `POST .../email` (set up forwarding), `GET /verify-email` (confirm a forwarding address). See `packages/server/src/email.ts`. Reused, not modified, by §3's own signer-notification need.

## 7. Login secret

Unchanged -- `POST .../login-secret` (reissue a lost or leaked one). See `packages/server/src/registrar.ts`'s `reissueLoginSecret`.
