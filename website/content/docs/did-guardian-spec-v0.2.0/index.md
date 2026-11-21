---
layout: docs-sidebar
title: "DID Guardian Method Specification, v0.2.0"
description: "The did:guardian DID method: identifier syntax, DID document shape, the operation log, and every operation's exact signature requirements."
versionTag: true
canonical_url: 'https://guardianspec.org/docs/did-guardian-spec-v0.2.0/'
status: Draft
date: '2026-10-24'
editors:
  - Troy Howard
updated_at: '2026-11-19'
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "DID Guardian Method Specification, v0.2.0",
  "description": "The did:guardian DID method: identifier syntax, DID document shape, the operation log, and every operation's exact signature requirements.",
  "url": "https://guardianspec.org/docs/did-guardian-spec-v0.2.0/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# DID Guardian Method Specification

`did:guardian` merges [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s own operation log and key-rotation model with [`did:web`](https://w3c-ccg.github.io/did-method-web/)'s domain-scoped, directory-free resolution, adding group guardianship on top of both -- a configurable, cryptographically-enforced set of parties able to recover, revoke, or transfer an identity.

> The key words *MUST*, *MUST NOT*, *REQUIRED*, *SHALL*, *SHALL NOT*, *SHOULD*, *SHOULD NOT*, *RECOMMENDED*, *MAY*, and *OPTIONAL* in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).
>
> Each normative rule carries a stable requirement ID (`REQ-<section>-<n>`); an ID's meaning never changes once published, and neither does its number -- a rule added after a section's own IDs are already in use gets the next free number in that section regardless of where in the section it's placed, rather than renumbering anything already published. REQ-7.2-11, placed with `guardian_add`'s other rules despite sorting after REQ-7.2-10, is the one case in this document where that's visible.

## 1. Target system

A registrar: an HTTP server operating one or more `did:guardian` namespaces, one per domain it controls, resolved by domain ([§8](#8-resolution)) the same way `did:web` is -- unlike `did:plc`, there is no single central directory; each registrar operates independently.

## 2. Identifier syntax

```text {linenos=false}
did-guardian-identifier = "did:guardian:" domain [ ":" name ]
name         = 3*32(ALPHA / DIGIT / "-")
domain       = domain-label *( "." domain-label )
domain-label = 1*63(ALPHA / DIGIT / "-")
```

Domain-first, deliberately isomorphic to `did:web`'s own method-specific-id grammar (`did:web:<domain>:<path...>`) -- did:guardian is that same shape with at most one flat `name` segment, not a coincidence: it keeps a did:guardian identifier visually parallel to the equivalent `did:web:<domain>:<name>`, differing only in the method name, which matters if a future did:web-interop profile ever links the two.

- <a id="req-2-1"></a>**REQ-2-1**: `name`, if present, *MUST* be lowercase ALPHA/DIGIT/"-" only, 3 to 32 characters, *MUST* start and end with ALPHA/DIGIT, and *MUST NOT* contain two consecutive "-" characters.
- <a id="req-2-2"></a>**REQ-2-2**: `domain` *MUST* be written dot-joined, exactly as it appears in ordinary DNS usage (e.g. `acme.com`), never colon-joined.
- <a id="req-2-4"></a>**REQ-2-4**: Names are scoped per registrar (per `domain`), not globally -- the same `name` *MAY* exist, as a wholly separate identity with no relationship implied, under two different domains.

### 2.1 The bare-domain identity

- <a id="req-2-3"></a>**REQ-2-3**: An identifier with zero colons after the method name denotes the bare-domain identity for that domain (no `name`).
- <a id="req-2-5"></a>**REQ-2-5**: The bare-domain identity's reserved path segment, where a registrar's own resolution surface needs one, is the literal string `_`. A registrar *MUST* reject any attempt to register `_` as an ordinary `name`.

## 3. DID Document

Resolving an identifier *MUST* yield a document conformant to [W3C DID Core](https://www.w3.org/TR/did-core/), containing:

- <a id="req-3-1"></a>**REQ-3-1**: exactly one `verificationMethod` entry per entry in the ward's current `operationalKeys` ([§4](#4-key-material)), each of type `Multikey`.
- <a id="req-3-2"></a>**REQ-3-2**: `authentication`, `assertionMethod`, and `capabilityInvocation` arrays referencing every such `verificationMethod` -- an operational key is exactly what invokes the capability to update the document (REQ-6-2 through REQ-6-11), the semantic `capabilityInvocation` itself names.
- <a id="req-3-3"></a>**REQ-3-3**: The guardian tier, `GuardianPolicy`, and the full operation log *MUST NOT* appear in the presented document -- they are method-internal state used to derive it, resolvable separately ([§8](#8-resolution)).

## 4. Key material

- <a id="req-4-1"></a>**REQ-4-1**: `operationalKeys` is the ward's own, lowest-authority, self-rotatable tier. Any single current operational key suffices to authorize an ordinary rotation ([§7.2](#72-update)).
- <a id="req-4-2"></a>**REQ-4-2**: The guardian tier is, at any point in the log, exactly the current guardian set as derived by replay -- a live reference, never a value fixed at the moment guardianship was established. A signature from a guardian DID *MUST* be checked against a key that was valid for that guardian's own identity at the time the signing operation was created -- determined by replaying the guardian's own operation log up to that point, not necessarily its currently-resolved key. Every key a guardian has ever rotated away from remains permanently present in its own log ([§9](#9-deactivation-and-data-permanence)), so this check is always independently verifiable, even after that key is no longer current.
- <a id="req-4-3"></a>**REQ-4-3**: A guardian action *MUST* always be signed by the guardian's own distinct key, never the ward's.
- <a id="req-4-4"></a>**REQ-4-4**: A guardian whose own identity is currently deactivated (REQ-6-5) *MUST* be excluded from the current guardian set for every purpose this document defines -- threshold eligibility (§5), and "is this DID a current guardian" checks (e.g. REQ-7.2-6). Exclusion is automatic, live (re-evaluated at the time of each new signature, same as REQ-4-2), and takes effect the moment that guardian's own `custodial_tombstone` is accepted; it is not equivalent to, and does not require, an explicit `guardian_remove` naming that guardian on the ward's own log. If this exclusion reduces a ward's effective guardian set to empty, the ward becomes guardian-less in exactly the same sense as after `guardian_relinquish` -- re-entering guardianship afterward follows the ordinary zero-to-one `guardian_add` rule (REQ-7.2-5).

## 5. GuardianPolicy

```json {linenos=false}
{
  "recovery_threshold": "any",
  "tombstone_threshold": "any",
  "removal_threshold": "majority",
  "addition_threshold": "majority",
  "policy_threshold": "majority",
  "min_guardian_count": 0,
  "on_orphan": "sovereign"
}
```

- <a id="req-5-1"></a>**REQ-5-1**: A threshold value *MUST* be one of: `"any"` (`M = 1` if `N > 0`, else unsatisfiable), `"majority"` (`M = floor(N/2) + 1`), `"unanimous"` (`M = N`), or `{"at_least": k}` (`M = max(k, 0)`), where `N` is the size of the eligible set at evaluation time and `M` is the number of valid, distinct signatures required.
- <a id="req-5-2"></a>**REQ-5-2**: `recovery_threshold` governs a guardian-initiated `custodial_rotate` ([§7.2](#72-update)). Default `any`.
- <a id="req-5-3"></a>**REQ-5-3**: `tombstone_threshold` governs `custodial_tombstone` ([§7.3](#73-deactivate)). Default `any`.
- <a id="req-5-4"></a>**REQ-5-4**: `removal_threshold` governs both a forced `guardian_remove` and `guardian_relinquish` ([§7.2](#72-update)). Default `majority`.
- <a id="req-5-5"></a>**REQ-5-5**: `addition_threshold` governs `guardian_add` ([§7.2](#72-update)). Default `majority`.
- <a id="req-5-6"></a>**REQ-5-6**: `policy_threshold` governs `policy_update` itself, evaluated against its own currently-effective value, never the proposed new one. Default `majority`.
- <a id="req-5-7"></a>**REQ-5-7**: `min_guardian_count` (a non-negative integer, default `0` meaning no minimum) *MUST* be enforced on `guardian_remove` ([REQ-7.2-7a](#req-7.2-7a)/[REQ-7.2-7b](#req-7.2-7b)) only: a registrar *MUST* reject a `guardian_remove` that would leave the guardian set smaller than this value. It *MUST NOT* be enforced on `guardian_relinquish` -- full dissolution (REQ-7.2-8) remains available at any guardian-set size regardless of a stated minimum, since it is a deliberate choice by enough of the guardians to end the relationship entirely, not a departure the ward's own policy is positioned to second-guess.
- <a id="req-5-8"></a>**REQ-5-8**: `on_orphan` (one of `"sovereign"`, `"tombstone"`, or `{"transfer_to": <DID>}`, default `"sovereign"`) states the ward's own standing preference for what should happen if its effective guardian set becomes empty other than through an explicit `guardian_relinquish` -- e.g. via REQ-4-4's own cascading exclusion when a sole guardian is deactivated. This field is declarative state only -- part of `GuardianPolicy`, replayed and exposed exactly like any other policy field, and nothing more. The three values are not equally achievable by a pure verification function, and this document does not pretend otherwise:
  - `"sovereign"` needs no operation at all -- REQ-4-4's own exclusion rule already makes `replay()` compute an empty guardian set directly from the existing log. Nothing to construct, nothing to sign, no key material involved anywhere. This is the only one of the three that is actually library-level, in the same sense `min_guardian_count`'s own enforcement is: a pure function of already-replayed state.
  - `"tombstone"` needs a new, signed `custodial_tombstone`, which no pure verification function can produce -- but only ever needs *one* party's key: the orphaned ward's own, alone, since `tombstone_threshold` defaults to `any` (REQ-7.3-1).
  - `{"transfer_to": <DID>}` needs a new, signed `guardian_add`, which likewise no pure verification function can produce. Which signer set this falls under depends on *when* it happens, not just that it happens: once the guardian set has actually reached empty, REQ-7.2-5 applies and it needs *two* parties' keys together, the named DID's own consent and the orphaned ward's own. But a `guardian_add` naming the fallback submitted *before* a sole guardian's own tombstone is accepted -- while the guardian set is still the single outgoing guardian, non-empty -- falls under the ordinary addition rule (REQ-7.2-4) instead, where `addition_threshold` evaluated at `N=1` is `majority = 1`: the outgoing guardian's own signature alone satisfies it, with the orphaned ward's own key never needed at all. The same add-before-remove sequencing [§7.2](#72-update)'s own ordinary transfer already uses applies here for exactly the same reason.

  Only an application layer that actually holds the relevant keys can act on the latter two, and only for whichever it actually custodies (see the registrar API specification for one way this might be offered, conditioned on exactly that custody).

## 6. The operation log

- <a id="req-6-1"></a>**REQ-6-1**: Every identity *MUST* be defined by an append-only, hash-chained, signed log of operations; the DID Document *MUST* always be derived by replaying this log, never stored or trusted directly.
- <a id="req-6-2"></a>**REQ-6-2**: Every operation except genesis *MUST* name the CID of the immediately preceding operation (`prev`); a registrar *MUST* reject any operation whose `prev` does not equal the current log head for that identity, except as permitted by [REQ-6-8](#req-6-8) (nullification).
- <a id="req-6-3"></a>**REQ-6-3**: Every identity has an *anchor*: the genesis operation's content hash (a CID, [REQ-6-4](#req-6-4)), computed the same way, by anyone, from the genesis operation alone. The anchor is a property of the log, not of the identifier -- it is never assigned independently by a registrar, and it exists regardless of whether anything ever pins or checks it ([§12.3](#123-pinning)). The identifier itself remains the location-bound `domain[:name]` string defined in [§2](#2-identifier-syntax), which a registrar does assign.
- <a id="req-6-4"></a>**REQ-6-4**: Serialization, hashing, and signing follow `did:plc`: DAG-CBOR encoding, ECDSA signatures (low-S form, base64url-encoded), `prev` as CIDv1 (base32 multibase, dag-cbor codec, sha-256 multihash).
- <a id="req-6-5"></a>**REQ-6-5**: Once an identity's `deactivated` state is true ([§7.3](#73-deactivate)), a registrar *MUST* reject every subsequent operation against it.
- <a id="req-6-6"></a>**REQ-6-6**: A registrar (or any independent verifier) *MUST* derive current state only by replaying the full log from genesis, verifying every operation's signatures against whichever keys/guardians had authority at that point in the log, and applying [REQ-6-8](#req-6-8)'s nullification rule where it occurs.
- <a id="req-6-7"></a>**REQ-6-7**: Every operation's `sigs` map is keyed by signer DID; each signature *MUST* be checked against that DID's own independently-resolved keys, never the ward's, and *MUST* cover the full operation content, binding it to this exact operation.
- <a id="req-6-8"></a>**REQ-6-8** (nullification): A guardian-signed `custodial_rotate` meeting `recovery_threshold` ([§7.2](#72-update)) *MAY* name a `prev` earlier than the current log head, provided the operation immediately following the named `prev` (the operation being nullified) was accepted by the registrar less than the recovery window ([REQ-6-9](#req-6-9)) ago.
- <a id="req-6-9"></a>**REQ-6-9** (recovery window): The recovery window is 72 hours, matching `did:plc`'s own value.
- <a id="req-6-10"></a>**REQ-6-10**: Once a nullifying operation ([REQ-6-8](#req-6-8)) is accepted, every operation that followed the named `prev` in the now-superseded branch *MUST* be excluded from replay ([REQ-6-6](#req-6-6)); the nullifying operation becomes the new log head, and [REQ-6-2](#req-6-2) applies normally from that point forward.
- <a id="req-6-11"></a>**REQ-6-11**: A nullifying operation *MAY* itself later be nullified by a further guardian-signed recovery rotation, under [REQ-6-8](#req-6-8), evaluated against its own acceptance time -- a reversal is the same mechanism applied again, not a distinct operation type. Concretely, this means naming the *same* `prev` the nullification being reversed itself named, not the `prev` of whatever that nullification superseded -- once superseded, an operation's own content is no longer reachable by naming its cid ([REQ-6-10](#req-6-10)); a guardian wanting that exact prior state back has to recreate it as new operation content, the same way any other operation is created.

## 7. Operations

### 7.1 Create

```json {linenos=false}
{
  "type": "custodial_create",
  "name": "alice",
  "operationalKeys": ["did:key:zDnae..."],
  "keySigs": { "did:key:zDnae...": "..." },
  "verificationMethods": { "key-1": "did:key:zDnae..." },
  "services": {},
  "creator": "did:guardian:acme.com",
  "registrar": { "did": "did:guardian:acme.com", "sig": "..." },
  "incoming": [],
  "prev": null
}
```

- <a id="req-7.1-1"></a>**REQ-7.1-1**: `incoming` *MAY* name one or more guardians directly at genesis (v0.3, relaxed from always-`[]`) -- each named DID *MUST* co-sign genesis, in `sigs`. A verifier *MUST* reject a genesis naming an incoming guardian with no corresponding, valid signature. Establishing a guardian later instead, via `guardian_add` ([§7.2](#72-update)), remains available and is unaffected by this -- genesis establishing one directly is an additional option, not a replacement for it.
- <a id="req-7.1-9"></a>**REQ-7.1-9**: A registrar *MUST* reject a genesis naming the identity's DID in `incoming` -- same reasoning as [REQ-7.2-11](#req-7.2-11): a ward is never its own guardian, at genesis or afterward.
- <a id="req-7.1-2"></a>**REQ-7.1-2**: `prev` *MUST* be `null`.
- <a id="req-7.1-3"></a>**REQ-7.1-3**: `operationalKeys`/`verificationMethods`/`services` *MUST* be present.
- <a id="req-7.1-4"></a>**REQ-7.1-4**: `creator` *MUST* be present -- the DID of whichever party initiated this registration. It carries no signature requirement and makes no guardianship or consent claim. A registrar accepting a self-service signup with no other initiating party *MUST* set `creator` to its own bare-domain identity.
- <a id="req-7.1-5"></a>**REQ-7.1-5**: `registrar` *MUST* be present -- an attestation `{did, sig}` from the accepting registrar's key, over the genesis content excluding `registrar`/`sigs`. A verifier *MUST* reject a genesis operation carrying no `registrar` attestation at all, and *MUST* check a present one against the named `did`'s resolved key. (Tightened from `MAY`/checked-only-if-present in this version's [Changelog](#changelog) -- [REQ-12-1](#req-12-1)'s L1 anchoring depends on every genesis actually carrying one.)
- <a id="req-7.1-6"></a>**REQ-7.1-6**: A name's own validity ([REQ-2-1](#req-2-1)) and availability within the accepting registrar's own namespace *MUST* both hold for the operation to be accepted.
- <a id="req-7.1-7"></a>**REQ-7.1-7**: `policy` *MAY* be present -- a full or partial `GuardianPolicy` ([§5](#5-guardianpolicy)) the creator proposes for this ward from genesis, carrying no signature requirement of its own (same standing as `creator`, REQ-7.1-4: a fact about how this ward was set up, not a guardian-tier consent claim). Any field left unset *MUST* resolve to the accepting registrar's own configured creation-time default for that field, which itself *MUST* resolve to this document's own stated default ([§5](#5-guardianpolicy)) if the registrar has not configured one. This is the only point at which `GuardianPolicy` may differ from those stated defaults before any guardian exists to approve a `policy_update` ([REQ-7.2-10](#req-7.2-10)).
- <a id="req-7.1-8"></a>**REQ-7.1-8**: `keySigs` *MUST* be present -- one signature per entry in `operationalKeys`, keyed by the key itself rather than a DID (an operational key is not independently resolvable the way a guardian DID is), each over the genesis content excluding `sig`/`sigs`/`keySigs`/`registrar`, the same content [REQ-7.1-5](#req-7.1-5)'s attestation covers. A verifier *MUST* reject a genesis operation missing a valid signature from any declared key. Control ([§12.1](#121-the-three-authorities)) is otherwise whatever the registrar's naming attestation asserts it to be, with nothing self-certifying behind it; this closes that gap at the one point where the control chain begins.

### 7.2 Update

**`custodial_rotate`** -- replaces `operationalKeys`/`verificationMethods`/`services` wholesale.

- <a id="req-7.2-1"></a>**REQ-7.2-1**: *MUST* be signed by either (a) any single current operational key, or (b) enough current guardians to meet `recovery_threshold`.
- <a id="req-7.2-2"></a>**REQ-7.2-2**: *MUST NOT* modify the guardian tier or `GuardianPolicy`.
- <a id="req-7.2-12"></a>**REQ-7.2-12**: `keySigs` *MUST* be present -- one signature per entry in `operationalKeys` (the new keys being installed), keyed by the key itself, each over the rotation content excluding `sig`/`sigs`/`keySigs`, the same proof-of-possession requirement as genesis ([REQ-7.1-8](#req-7.1-8)) applied every time a key is installed, not just at genesis. Required whether the rotation is authorized by (a) or (b) above -- either way a new key is being added to the document, and REQ-7.2-1's signer requirement authorizes the change, not the new key's possession of itself.

**`guardian_add`** -- adds exactly one new guardian, named in `incoming`.

- <a id="req-7.2-3"></a>**REQ-7.2-3**: A registrar *MUST* reject this operation if `incoming` is already a current guardian.
- <a id="req-7.2-4"></a>**REQ-7.2-4**: When the current guardian set is non-empty, required signers are `incoming`'s own key, and enough current guardians to meet `addition_threshold`.
- <a id="req-7.2-5"></a>**REQ-7.2-5**: When the current guardian set is empty, required signers are `incoming`'s own key, and the ward's own current operational key.
- <a id="req-7.2-11"></a>**REQ-7.2-11**: A registrar *MUST* reject this operation if `incoming` names the ward's own identity. A ward is never its own guardian: aside from the confusion of a ward appearing in both roles at once, an effectively-guarded ward's own guardian set must never be allowed to look non-empty when no independent, external oversight actually exists -- which matters directly for `on_orphan` (REQ-5-8), since that safety net is only ever consulted once the guardian set becomes empty.

**`guardian_remove`** -- removes exactly one current guardian, named in `outgoing`.

- <a id="req-7.2-6"></a>**REQ-7.2-6**: A registrar *MUST* reject this operation if `outgoing` is not a current guardian, or is the only current guardian (use `guardian_relinquish` to end the relationship entirely).
- <a id="req-7.2-7a"></a>**REQ-7.2-7a**: A voluntary `guardian_remove` -- `outgoing` removing itself -- requires only `outgoing`'s own key, alone.
- <a id="req-7.2-7b"></a>**REQ-7.2-7b**: A forced `guardian_remove` -- removing a different current guardian -- requires enough of the *other* current guardians (current minus `outgoing`) to meet `removal_threshold`, *evaluated against the full current guardian set's own size*, the same `N` `guardian_relinquish` (REQ-7.2-8) uses, never against the smaller remaining-guardians pool those signers are drawn from. At exactly two current guardians this makes REQ-7.2-7b unreachable: `majority` of `N=2` is `2`, and only one other guardian is ever available to draw from. This is deliberate, not an oversight -- see [§10](#10-security-considerations). A registrar *MUST* additionally reject either path (REQ-7.2-7a or REQ-7.2-7b) if it would bring the guardian count below `min_guardian_count` ([REQ-5-7](#req-5-7)).

**`guardian_relinquish`** -- sets the guardian set to `[]`.

- <a id="req-7.2-8"></a>**REQ-7.2-8**: Required signers: enough current guardians to meet `removal_threshold`, evaluated against the full current guardian set.

**`policy_update`** -- replaces `GuardianPolicy` wholesale.

- <a id="req-7.2-9"></a>**REQ-7.2-9**: Required signers: enough current guardians to meet the currently-effective `policy_threshold`.
- <a id="req-7.2-10"></a>**REQ-7.2-10**: A registrar *MUST* reject a `policy_update` submitted while the current guardian set is empty.

### 7.3 Deactivate

`custodial_tombstone` -- deactivates the identity (`deactivated = true`; [§6](#6-the-operation-log)).

- <a id="req-7.3-1"></a>**REQ-7.3-1**: Required signers: enough of (the ward's own operational key(s) ∪ the current guardian set) to meet `tombstone_threshold`.

## 8. Resolution

- <a id="req-8-1"></a>**REQ-8-1**: Resolution *MUST* split the identifier on its first colon after the method name: no colon denotes the bare-domain identity; one colon denotes `domain` then `name`.
- <a id="req-8-2"></a>**REQ-8-2**: A conformant registrar *MUST* expose, for each identity it hosts, reachable under `https://<domain>/.well-known/guardian/<name>` (or `.../guardian/_` for the bare-domain identity): `GET` the current derived document; `GET` the full operation log; `POST` one new signed operation. `POST` at a `<name>` this registrar does not yet host *MUST* accept a self-signed `custodial_create` establishing it -- genesis submission is part of the method (v0.3), not a registrar-specific convenience, and `.../operations` is the one surface every conformant registrar already exposes for every other operation type. The registrar checks name validity and availability ([REQ-7.1-6](#req-7.1-6)) and the submitted proof of possession ([REQ-7.1-8](#req-7.1-8)), then adds its attestation ([REQ-7.1-5](#req-7.1-5)) before storing it -- the client can never produce that attestation on its own. A registrar *MAY* expose additional surface; this specification does not constrain it.

## 9. Deactivation and data permanence

- <a id="req-9-1"></a>**REQ-9-1**: The full operation log *MUST* remain permanently, publicly resolvable after `custodial_tombstone`.
- <a id="req-9-2"></a>**REQ-9-2**: A name, once registered, *MUST NOT* be returned to the available pool within its registrar after deactivation.

**Domain migration is out of scope for this version.** An identifier's `domain` ([§2](#2-identifier-syntax)) is fixed for the life of that identifier -- this document defines no operation that changes it, and none is planned for v0.x. Moving to a different domain means creating a new identifier there and linking the two, not relocating the existing one:

1. Register the new identifier on the new domain.
2. Add `alsoKnownAs` entries on each pointing at the other, so a resolver following either arrives at both.
3. Re-establish guardianship on the new identifier -- it starts guardian-less (REQ-7.1-1) regardless of what the old one had.
4. Tombstone the old identifier, or leave it resolvable as a historical record -- either is conformant; REQ-9-1 requires its log stay resolvable regardless.

This keeps the anchor and pinning model ([§12.3](#123-pinning)) useful even without migration: an attacker who takes over an abandoned or expired domain gets a blank slate under that domain, never control of an identifier a verifier had already pinned elsewhere.

## 10. Security considerations

- **Trust model**: a registrar is trusted to order operations and resist denial-of-service against its own log; it is not trusted to forge history, since the log is self-certifying and independently replayable by anyone.
- **Key generation and storage** are a registrar-implementation concern, out of this method's own scope -- this document specifies rotation (REQ-6-2 through REQ-6-11, REQ-7.2-1) and revocation (`guardian_remove`, `guardian_relinquish`, `custodial_tombstone`) precisely; how a given registrar generates or custodies the private key material behind an `operationalKeys`/guardian entry is that registrar's own concern, same as it is for `did:web`.
- **Guardian-claim forgery**: a ward cannot be made to falsely name an unwilling party as its guardian ([REQ-7.2-4](#req-7.2-4)/[REQ-7.2-5](#req-7.2-5) structurally require that party's own signature). A party cannot name itself guardian of an already-guarded ward it doesn't already co-guard ([REQ-7.2-4](#req-7.2-4) requires cooperation from enough of the existing guardian set).
- **Registrar-claim forgery**: a forged `registrar` attestation ([REQ-7.1-5](#req-7.1-5)) fails verification the same way any other forged signature does.
- **Guardian key compromise**: a single compromised guardian key cannot act alone in a guardian set held to anything stricter than `any`. `guardian_remove`'s voluntary path ([REQ-7.2-7a](#req-7.2-7a)) only ever lets a compromised key remove that same guardian, never another. A compromised sole guardian, or a guardian set deliberately held at `any`, is an unmitigated risk. Tombstoning a guardian whose own key is known to be compromised cuts it off from every ward it guards immediately (REQ-4-4), which helps every one of those wards, not just the compromised identity itself.
- **Two-guardian deadlock, deliberate**: at exactly two current guardians, forced `guardian_remove` is unreachable (REQ-7.2-7b) -- there is no safe way to let one of two guardians unilaterally eject the other without that same power being available to a bad actor in the same seat. A ward wanting protection against one uncooperative or compromised co-guardian needs a third guardian; two-guardian wards that lose trust in one party can only dissolve entirely (`guardian_relinquish`, needing both) or have the trusted party voluntarily step down (`guardian_remove`, REQ-7.2-7a) and let the ward go guardian-less, never a clean "eject just the other one."
- **Circular and mutual guardianship**: nothing prevents a ward from guarding its own guardian, directly or in a longer cycle. Mechanically this is safe in the ordinary case (each party's own current key is independently verifiable per REQ-4-2), but it concentrates two risks worth naming: a circular pair that is secretly operated by a single party is Sybil risk (see below) wearing a specific shape, and a circular pair's own operational availability is more likely to be correlated (shared operator, shared infrastructure) than two genuinely independent parties', which matters because recovery of one from the other only works if the other's own key is actually reachable when needed.
- **Nullification window**: for 72 hours after any operation ([REQ-6-9](#req-6-9)), a verifier *SHOULD* treat current state as provisional, not final -- a guardian-signed recovery rotation can still rewrite history back to that point. A compromised guardian set that also meets `recovery_threshold` can itself abuse nullification within the same window; this is the same class of risk as any other guardian-key compromise (above), not a new one.
- **Name squatting**: names are permanent within a registrar ([§9](#9-deactivation-and-data-permanence)); claiming a name ahead of its likely owner is possible, bounded to one registrar's own namespace.
- **Sybil creation**: nothing in this method limits how many identities one party may register, within a registrar or across many -- circular/mutual guardianship (above) is one concrete shape this risk can take.
- **Log forgery and stale snapshots**: a self-certifying log is not the same thing as a self-authenticating name. Anyone can construct an internally-consistent log, with valid signatures all the way through, for a `domain[:name]` they do not control -- [REQ-12-1](#req-12-1)'s L0 proves only that a log agrees with itself. A stale but genuinely-once-accepted log is a narrower version of the same problem: still fully self-consistent, just missing whatever has happened since. [§12](#12-authority-and-trust-model) exists because of exactly this gap.
- **Domain takeover or expiry**: whoever controls a domain at the DNS/TLS level controls that registrar's key material going forward, and can mint a new, equally self-consistent log under identifiers that domain previously hosted. A freshly-fetched registrar key from a domain already taken over is the attacker's key, not the original operator's -- this is exactly why [REQ-12-2](#req-12-2) requires a pinned anchor or registrar key to have come from a *prior* L3 resolution or an out-of-band channel, never from whatever the domain serves right now.
- **Equivocation**: nothing in this document stops a dishonest or compromised registrar from serving two different verifiers two different, both internally-valid, forked continuations of the same log. Detecting this needs an independent witness or mirror comparing what a registrar served different parties at the same time -- out of scope for this version of the method; a registrar that wants to foreclose it today can publish its log somewhere independently auditable, but nothing here requires that yet.
- **Custody disclosure is a declaration, not a proof**: whether an identity's operational key is held by its registrar or by the ward itself ([§12.4](#124-key-custody-modes)) is useful context for a verifier but is not independently checkable from the log alone -- a party can claim self-custody and still, in fact, have handed the key to someone else entirely. The one case with any independent weight is a key a ward supplied itself through a registrar's take-custody-style flow, visible as a `custodial_rotate` the ward's prior key signed, to a new key the registrar never generated.

## 11. Privacy considerations

- **Data permanence**: the full log stays public forever ([§9](#9-deactivation-and-data-permanence)) -- nothing in `services` should be anything that shouldn't be permanently, publicly linkable to this identity.
- **Key reuse (correlation risk)**: reusing an operational or guardian key across more than one identity can leak a relationship between them that was never meant to be public.
- **Cross-registrar identity unification**: two `did:guardian` identities under different registrars are never provably the same party by this method alone, including when they share a name -- this method makes no correlation between them possible by default.

## 12. Authority and trust model

Everything normative about operations and signatures is already stated in [§4](#4-key-material) through [§9](#9-deactivation-and-data-permanence); nothing in this section changes any of it. What this section adds is a name for three things a verifier is implicitly relying on every time it checks those rules, plus a scale for how much of that reliance a given check actually earned.

### 12.1 The three authorities

- **Control** -- who may change or sign as the identity. Held by the identity's key material and `GuardianPolicy`, enforced entirely by the signatures a log entry carries. Fully self-certifying: anyone holding the log can check this offline, no registrar involved in the check -- including at the root, where [REQ-7.1-8](#req-7.1-8) requires genesis to carry proof that the declared keys are held, not merely asserted by the registrar's naming attestation.
- **Naming** -- which log a given `domain[:name]` string actually refers to. Held by whichever registrar accepted genesis, attested by its signature there ([REQ-7.1-5](#req-7.1-5)). Checkable offline only against a registrar key or anchor a verifier already has reason to trust ([§12.3](#123-pinning)) -- a first encounter has no such reason yet.
- **Currency** -- whether a given state is the latest, and what time it is for the 72-hour windows ([REQ-6-9](#req-6-9)). Held by whichever registrar orders operations for that identity. How fresh a verifier can trust this to be depends entirely on how the timestamp backing it reached them ([§12.2](#122-verification-levels)) -- there is no way to check "is this current" purely from a log already in hand, only "was this once current as of some point."

### 12.2 Verification levels

- <a id="req-12-1"></a>**REQ-12-1**: A verifier *MUST* report, alongside any claim about an identity's state, which level below it actually reached -- never an unqualified "valid" with no level attached.
  - **L0 (Consistent)**: the log in hand replays, and every signature and threshold it claims checks out ([REQ-6-6](#req-6-6), [REQ-6-7](#req-6-7)). Proves only that this log agrees with itself -- not that it is the log this identifier currently resolves to, nor that nothing has superseded it since. *MUST NOT* be treated as proof of identity by itself.
  - **L1 (Anchored)**: L0, plus either this log's genesis anchor ([REQ-6-3](#req-6-3)) matches a value the verifier already had reason to trust, or its registrar attestation ([REQ-7.1-5](#req-7.1-5)) verifies against a registrar key the verifier already had reason to trust. Proves this is the same identity seen before, or the one a known registrar actually created -- not that it is current.
  - **L2 (Fresh as of t)**: L1, plus a registrar-signed statement naming the log head and a timestamp `t`, where the verifier's maximum acceptable age exceeds *now − t*. The reference registrar exposes this as a log-head statement (`{did, anchor, headCid, seq, timestamp, registrar, sig}`), signed with the same key REQ-7.1-5's genesis attestation uses, at `.../log-head` (see the registrar API spec).
  - **L3 (Live)**: resolved directly from the registrar, right now, over a channel the verifier trusts (e.g. TLS to the expected domain).
- <a id="req-12-2"></a>**REQ-12-2** (first contact): A verifier's first resolution of a given identifier *MUST* reach L3. An anchor or registrar key *MAY* be pinned from that resolution, or from another channel the verifier already trusts out-of-band, for later L1 checks -- *MUST NOT* be pinned from a resolution that only reached L1 or below, which would just be trusting the claim it was supposed to check.
- <a id="req-12-3"></a>**REQ-12-3**: Authentication, authorization, or any decision sensitive to revocation *MUST* use L3, or L2 with a maximum acceptable age measured in minutes -- never L1 alone. A log that is internally consistent and correctly anchored can still be missing a revocation that has already happened live; L1 says nothing about how long ago it was last true.

### 12.3 Pinning

- <a id="req-12-4"></a>**REQ-12-4**: A `guardian_add` operation *SHOULD* record the incoming guardian's anchor ([REQ-6-3](#req-6-3)) in its optional `anchor` field, alongside its DID, so that a later L1 check of that specific guardian relationship has something to pin against without a separate L3 resolution first. Not required -- a verifier *MUST* still accept a `guardian_add` carrying no `anchor` at all, and the anchor is covered by the same signatures as every other field (there's no separate signature requirement for it). The reference registrar populates it automatically whenever it already custodies the incoming guardian's log (`registerWard`'s same-registrar convenience, `.../adopt`); a relying party receiving a `guardian_add` with no anchor at all gets the same effect by storing `{did, anchor}` the first time it resolves that guardian at L3 -- the same pattern as storing a `sub` from an OIDC provider.

### 12.4 Key custody modes

Non-normative. Nothing in this section is a requirement; [§4](#4-key-material) and [§7](#7-operations) already say everything required about keys and signatures regardless of who holds them. This section exists because [§10](#10-security-considerations)'s custody-disclosure point and [§12.1](#121-the-three-authorities)'s "control" authority both read differently depending on which of two shapes actually holds for a given identity's operational key:

- **Registrar-held**: the registrar generated the operational key and still holds it, encrypted, able to sign ordinary rotations and other self-contained operations on the ward's behalf via whatever login mechanism it offers. Convenient, and the only shape self-service registration produces. The registrar's trustworthiness is now part of what "control" rests on for that identity, not just naming and currency.
- **Self-held**: the ward holds its operational key, and the registrar holds nothing usable -- not even an encrypted copy. A registrar offering a transition from the first shape to the second, after registration, is documented as "take-custody" in the registrar API specification; nothing here requires a registrar to offer it, and this document defines no new operation type for it, since the result is an ordinary guardian- or ward-signed `custodial_rotate` either way.

Neither shape changes which signatures [§7](#7-operations) requires -- it only changes who is capable of producing the ward's half of them, and who a verifier is trusting when a registrar's convenience endpoint produces a signature "on a ward's behalf."

## Conformance

A conformant implementation must replay and verify every fixture in [`interop_tests/`](https://github.com/did-method-guardian/did-method-guardian/tree/main/interop_tests) the same way this reference implementation does -- accepting every fixture whose own `expect` is `accept`, rejecting every one whose `expect` is `reject`, each for the specific reason its own `note` states. [`requirements.json`](https://guardianspec.org/requirements.json) lists every requirement in this document by id, cross-referenced with the reference implementation's own tests that name it. [JSON Schemas](https://guardianspec.org/schemas/operation.schema.json) for `GuardianPolicy` and every operation type are also available, matching this document's own field-by-field requirements.

**Accept:**

- `genesis_two_guardians.json`: Genesis establishing a two-member guardian set, both consenting.
- `guardian_relinquish_unanimous.json`: Both guardians sign off on full relinquishment -- meets the default majority (here, unanimous since n=2) threshold.
- `rotate_then_guardian_transfer.json`: Genesis, an ordinary operational-key rotation, then board-a steps down and board-c joins -- board-b continues and does not re-sign.
- `tombstone_any_single_key.json`: Guardian-less ward tombstoning itself via its own operational key (resolved under its own DID), meeting the default `any` tombstone_threshold.

**Reject:**

- `forged_guardian_claim.json`: 'board-a' is named as initial guardian but the signature was produced by a different, impostor key -- must fail verification against board-a's own resolved public key.
- `relinquish_quorum_not_met.json`: three guardians exist, default removal/relinquish threshold is majority (2 of 3), but only board-a signed.
- `unilateral_coguardian_removal.json`: troy attempts to remove jane from a two-guardian set, but the signature claimed as jane's was produced with troy's own key, not jane's.
- `genesis_missing_registrar_attestation.json`: a genesis operation with no `registrar` attestation at all -- must fail REQ-7.1-5, not just a forged one.

## Changelog

- **v0.2.0** (2026-10-24, current): domain-first identifier grammar (`did:guardian:<domain>:<name>`, matching `did:web`'s own convention); the bare-domain identity as a first-class concept ([§2.1](#21-the-bare-domain-identity)); the nullification window ([REQ-6-9](#req-6-9)); every requirement given a stable `REQ-<section>-<n>` id.
  - **2026-11-21**: relaxed [REQ-7.1-1](#req-7.1-1) -- `incoming` may now name one or more guardians directly at genesis, as long as each co-signs, instead of always being `[]`. Removes the "self-held identities are always born guardian-less" trap, and halves the operations an identity that's always born with a guardian needs (an ephemeral agent fleet under one long-lived guardian, say). Added [REQ-7.1-9](#req-7.1-9): a ward can't name itself as a guardian at genesis either, same reasoning as [REQ-7.2-11](#req-7.2-11). `checkGenesisShape` (`rules.ts`) is wired into the reference registrar's `acceptGenesis` now rather than standing alone as a tested-but-unused function, and checks the new rule's shape (a signature slot exists for each named guardian); genesis's cryptographic checks (those signatures' validity, keySigs, the registrar attestation) still run through `verifyCustodialCreate`, called once the attestation is attached. `@did-guardian/cli`'s `create --guardian <did> --guardian-key <label>` covers the case where the same operator holds both keys. New interop fixtures: a genesis naming an incoming guardian with no signature at all is rejected; one where each named guardian co-signs is accepted (the latter was already covered by an existing fixture, since `verifyCustodialCreate` never actually required `incoming` to be empty -- only this requirement's own wording and the unwired shape check did).
  - **2026-11-21**: amended [REQ-8-2](#req-8-2) -- genesis submission is part of the method now, not a registrar-specific convenience. `POST .../operations` at a name this registrar doesn't yet host accepts a self-signed `custodial_create`, checked for name validity/availability and proof of possession, with the registrar's attestation added before storing it. The reference registrar's `registerWard` (server-generated key) now goes through this exact same acceptance path (`acceptGenesis`, registrar.ts) a client-built genesis does -- one creation path, two kinds of callers. `@did-guardian/cli`'s `create --registrar <domain>` publishes for real now and reports the registrar's returned anchor, not one computed before the attestation existed (that earlier value was never the real one -- adding the attestation changes the content, and so the cid, after the fact). This resolves [issue #4](https://github.com/did-method-guardian/did-method-guardian/issues/4).
  - **2026-11-21**: added [REQ-7.1-8](#req-7.1-8) -- genesis now requires `keySigs`, a proof-of-possession signature from every declared operational key, closing the gap where the control chain's root was whatever the registrar's naming attestation asserted, with nothing self-certifying behind it. Generalized the same requirement to `custodial_rotate` as [REQ-7.2-12](#req-7.2-12): any operation that installs a new key carries that key's proof of possession, not just the signature authorizing the change. The reference library's `signCustodialCreate`/`verifyCustodialCreate`/`signCustodialRotate`/`verifyCustodialRotate` and the real server-side `rotateRule` (`rules.ts`) all check it now; every interop fixture was regenerated to match.
  - **2026-11-19**: implemented [L2](#122-verification-levels) (REQ-12-1) -- the reference registrar now exposes a signed log-head statement at `.../log-head` (registrar API spec), using the same key as REQ-7.1-5's genesis attestation. Also added `multikeyToSpki` to the reference library (the inverse of `spkiToMultikey`), closing a real gap this surfaced: a verifier who only has a resolved DID document had no way to get back to this library's internal key format needed to check any signature at all. [Issue #5](https://github.com/did-method-guardian/did-method-guardian/issues/5) is now fully addressed by this and the REQ-12-4 work below.
  - **2026-11-19**: implemented [REQ-12-4](#req-12-4)'s anchor field on `guardian_add` -- the reference library's `GuardianAddOp` type, the reference registrar's same-registrar convenience paths, `@did-guardian/cli`'s `guardian add`, and the JSON Schema all carry it now. (Filed [issue #6](https://github.com/did-method-guardian/did-method-guardian/issues/6) while adding this: the `interop_tests/` conformance suite has no fixture exercising a standalone `guardian_add` at all, independent of the anchor field specifically.)
  - **2026-11-18**: documented domain migration as explicitly out of scope for this version ([§9](#9-deactivation-and-data-permanence)), with "link, don't move" (a new identifier plus mutual `alsoKnownAs`) as the documented alternative. Added [§12, Authority and trust model](#12-authority-and-trust-model) -- the three authorities (control/naming/currency), verification levels L0-L3 and the first-contact-then-pin rule ([REQ-12-1](#req-12-1)/[REQ-12-2](#req-12-2)/[REQ-12-3](#req-12-3)), pinning ([REQ-12-4](#req-12-4)), and non-normative key custody modes ([§12.4](#124-key-custody-modes)). Reworded [REQ-6-3](#req-6-3) -- the anchor (genesis content hash) is a property of the log, not of the identifier, which was never actually hash-derived under this version's domain-first grammar. Tightened [REQ-7.1-5](#req-7.1-5) from `MAY` to `MUST`: every genesis now requires a registrar attestation, not just accepts one if present -- the reference library's `verifyCustodialCreate` function and every interop fixture were updated to match. Added security-considerations entries for log forgery/stale snapshots, domain takeover, equivocation, and custody disclosure.
- **v0.1** (2026-10-19 through 2026-10-23): initial draft, before the method specification, registrar API, and guide were split into separate documents. Never published as its own standalone page.
