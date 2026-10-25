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
| `POST` | `.../tombstone` | `custodial_tombstone`, ward-signed | `tombstone_threshold` defaults to `any`; the ward's own key alone always suffices |
| `POST` | `.../adopt` | `guardian_add`, zero-to-one case only | needs only the incoming party's own consent plus the ward's own key (REQ-7.2-5) -- rejected if the ward already has any current guardian; use §3 for a non-empty guardian set |

## 3. Asynchronous signature collection (`pending_operations`)

For anything needing more than one signature collected over more than one request -- `guardian_add` against a non-empty guardian set (REQ-7.2-4), a forced `guardian_remove` (REQ-7.2-7b), `policy_update` (REQ-7.2-9), or a `guardian_relinquish`/guardian-initiated `custodial_rotate` whose required signers aren't all custodied by (or available in the same call to) this registrar.

Modeled as a state machine per pending proposal: `proposed -> collecting -> satisfied -> finalized`, with `expired` and `declined` as terminal alternatives from `collecting`. `finalized` is entered automatically the instant `satisfied` is reached (the registrar submits the now-complete operation to §1's own `/operations` itself) -- a caller never finalizes by hand.

| Method | Path | |
|---|---|---|
| `POST` | `.../propose` | create a pending proposal for one operation type + its intended content, with the proposer's own signature attached if they're a required signer |
| `POST` | `.../pending/<id>/sign` | a required signer not yet counted adds their own signature |
| `POST` | `.../pending/<id>/decline` | a required signer refuses; moves the proposal to `declined` |
| `GET` | `.../pending/<id>` | current status: required signers, who has signed, state |
| `GET` | `/api/me/pending-signatures` | every pending proposal naming the caller as a required signer who hasn't yet signed |

A proposal not reaching `satisfied` within 7 days moves to `expired`. A required signer discovers a pending proposal either by polling `/api/me/pending-signatures` or by the email notification in §5.

## 4. Login / OIDC

Unchanged by this plan -- `/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, plus this registrar's own `gw_session`-cookie login flow. See `packages/server/src/oidc.ts` and `login.ts`; not re-documented here since nothing in this plan touches it.

## 5. Email forwarding

Unchanged -- `POST .../email` (set up forwarding), `GET /verify-email` (confirm a forwarding address). See `packages/server/src/email.ts`. Reused, not modified, by §3's own signer-notification need.

## 6. Login secret

Unchanged -- `POST .../login-secret` (reissue a lost or leaked one). See `packages/server/src/registrar.ts`'s `reissueLoginSecret`.
