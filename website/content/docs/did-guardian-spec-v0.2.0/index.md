---
layout: docs-sidebar
title: "DID Guardian Method Specification, v0.2.0"
description: "The did:guardian DID method: identifier syntax, DID document shape, the operation log, and every operation's exact signature requirements."
versionTag: true
---
# DID Guardian Method Specification

`did:guardian` merges [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s own operation log and key-rotation model with [`did:web`](https://w3c-ccg.github.io/did-method-web/)'s domain-scoped, directory-free resolution, adding group guardianship on top of both -- a configurable, cryptographically-enforced set of parties able to recover, revoke, or transfer an identity.

> The key words *MUST*, *MUST NOT*, *REQUIRED*, *SHALL*, *SHALL NOT*, *SHOULD*, *SHOULD NOT*, *RECOMMENDED*, *MAY*, and *OPTIONAL* in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).
>
> Each normative rule carries a stable requirement ID (`REQ-<section>-<n>`); an ID's meaning never changes once published, and neither does its number -- a rule added after a section's own IDs are already in use gets the next free number in that section regardless of where in the section it's placed, rather than renumbering anything already published. REQ-7.2-11, placed with `guardian_add`'s other rules despite sorting after REQ-7.2-10, is the one case in this document where that's visible.

## 1. Target system

A registrar: an HTTP server operating one or more `did:guardian` namespaces, one per domain it controls, resolved by domain ([§8](#8-resolution)) the same way `did:web` is -- unlike `did:plc`, there is no single central directory; each registrar operates independently.

## 2. Identifier syntax

```
did-guardian-identifier = "did:guardian:" domain [ ":" name ]
name         = 3*32(ALPHA / DIGIT / "-")
domain       = domain-label *( "." domain-label )
domain-label = 1*63(ALPHA / DIGIT / "-")
```

Domain-first, deliberately isomorphic to `did:web`'s own method-specific-id grammar (`did:web:<domain>:<path...>`) -- did:guardian is that same shape with at most one flat `name` segment, not a coincidence: it keeps a did:guardian identifier visually parallel to the equivalent `did:web:<domain>:<name>`, differing only in the method name, which matters if a future did:web-interop profile ever links the two.

- <a id="req-2-1"></a>**REQ-2-1**: `name`, if present, *MUST* be lowercase ALPHA/DIGIT/"-" only, 3 to 32 characters, *MUST* start and end with ALPHA/DIGIT, and *MUST NOT* contain two consecutive "-" characters.
- <a id="req-2-2"></a>**REQ-2-2**: `domain` *MUST* be written dot-joined, exactly as it appears in ordinary DNS usage (e.g. `acme.com`), never colon-joined.
- <a id="req-2-3"></a>**REQ-2-3**: An identifier with zero colons after the method name denotes the bare-domain identity for that domain (no `name`).
- <a id="req-2-4"></a>**REQ-2-4**: Names are scoped per registrar (per `domain`), not globally -- the same `name` *MAY* exist, as a wholly separate identity with no relationship implied, under two different domains.
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

```json
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
- <a id="req-5-7"></a>**REQ-5-7**: `min_guardian_count` (a non-negative integer, default `0` meaning no minimum) *MUST* be enforced on `guardian_remove` ([REQ-7.2-7](#req-7.2-7)) only: a registrar *MUST* reject a `guardian_remove` that would leave the guardian set smaller than this value. It *MUST NOT* be enforced on `guardian_relinquish` -- full dissolution (REQ-7.2-8) remains available at any guardian-set size regardless of a stated minimum, since it is a deliberate choice by enough of the guardians to end the relationship entirely, not a departure the ward's own policy is positioned to second-guess.
- <a id="req-5-8"></a>**REQ-5-8**: `on_orphan` (one of `"sovereign"`, `"tombstone"`, or `{"transfer_to": <DID>}`, default `"sovereign"`) states the ward's own standing preference for what should happen if its effective guardian set becomes empty other than through an explicit `guardian_relinquish` -- e.g. via REQ-4-4's own cascading exclusion when a sole guardian is deactivated. This field is declarative state only -- part of `GuardianPolicy`, replayed and exposed exactly like any other policy field, and nothing more. The three values are not equally achievable by a pure verification function, and this document does not pretend otherwise:
  - `"sovereign"` needs no operation at all -- REQ-4-4's own exclusion rule already makes `replay()` compute an empty guardian set directly from the existing log. Nothing to construct, nothing to sign, no key material involved anywhere. This is the only one of the three that is actually library-level, in the same sense `min_guardian_count`'s own enforcement is: a pure function of already-replayed state.
  - `"tombstone"` needs a new, signed `custodial_tombstone`, which no pure verification function can produce -- but only ever needs *one* party's key: the orphaned ward's own, alone, since `tombstone_threshold` defaults to `any` (REQ-7.3-1).
  - `{"transfer_to": <DID>}` needs a new, signed `guardian_add`, which likewise no pure verification function can produce. Which signer set this falls under depends on *when* it happens, not just that it happens: once the guardian set has actually reached empty, REQ-7.2-5 applies and it needs *two* parties' keys together, the named DID's own consent and the orphaned ward's own. But a `guardian_add` naming the fallback submitted *before* a sole guardian's own tombstone is accepted -- while the guardian set is still the single outgoing guardian, non-empty -- falls under the ordinary addition rule (REQ-7.2-4) instead, where `addition_threshold` evaluated at `N=1` is `majority = 1`: the outgoing guardian's own signature alone satisfies it, with the orphaned ward's own key never needed at all. The same add-before-remove sequencing §4.3's own ordinary transfer already uses applies here for exactly the same reason.

  Only an application layer that actually holds the relevant keys can act on the latter two, and only for whichever it actually custodies (see the registrar API specification for one way this might be offered, conditioned on exactly that custody).

## 6. The operation log

- <a id="req-6-1"></a>**REQ-6-1**: Every identity *MUST* be defined by an append-only, hash-chained, signed log of operations; the DID Document *MUST* always be derived by replaying this log, never stored or trusted directly.
- <a id="req-6-2"></a>**REQ-6-2**: Every operation except genesis *MUST* name the CID of the immediately preceding operation (`prev`); a registrar *MUST* reject any operation whose `prev` does not equal the current log head for that identity, except as permitted by [REQ-6-8](#req-6-8) (nullification).
- <a id="req-6-3"></a>**REQ-6-3**: The identifier *MUST* be derived from the genesis operation's own content hash, never assigned independently by a registrar.
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

```json
{
  "type": "custodial_create",
  "name": "alice",
  "operationalKeys": ["did:key:z6Mk..."],
  "verificationMethods": { "key-1": "did:key:z6Mk..." },
  "services": {},
  "creator": "did:guardian:acme.com",
  "registrar": { "did": "did:guardian:acme.com", "sig": "..." },
  "incoming": [],
  "prev": null
}
```

- <a id="req-7.1-1"></a>**REQ-7.1-1**: `incoming` *MUST* be `[]`. Genesis *MUST NOT* establish a guardian directly -- guardianship, if any, is established by a subsequent `guardian_add` ([§7.2](#72-update)).
- <a id="req-7.1-2"></a>**REQ-7.1-2**: `prev` *MUST* be `null`.
- <a id="req-7.1-3"></a>**REQ-7.1-3**: `operationalKeys`/`verificationMethods`/`services` *MUST* be present.
- <a id="req-7.1-4"></a>**REQ-7.1-4**: `creator` *MUST* be present -- the DID of whichever party initiated this registration. It carries no signature requirement and makes no guardianship or consent claim. A registrar accepting a self-service signup with no other initiating party *MUST* set `creator` to its own bare-domain identity.
- <a id="req-7.1-5"></a>**REQ-7.1-5**: `registrar` *MAY* be present -- an attestation `{did, sig}` from the accepting registrar's own key. If present, a verifier *MUST* check it against the named `did`'s own resolved key.
- <a id="req-7.1-6"></a>**REQ-7.1-6**: A name's own validity ([REQ-2-1](#req-2-1)) and availability within the accepting registrar's own namespace *MUST* both hold for the operation to be accepted.
- <a id="req-7.1-7"></a>**REQ-7.1-7**: `policy` *MAY* be present -- a full or partial `GuardianPolicy` ([§5](#5-guardianpolicy)) the creator proposes for this ward from genesis, carrying no signature requirement of its own (same standing as `creator`, REQ-7.1-4: a fact about how this ward was set up, not a guardian-tier consent claim). Any field left unset *MUST* resolve to the accepting registrar's own configured creation-time default for that field, which itself *MUST* resolve to this document's own stated default ([§5](#5-guardianpolicy)) if the registrar has not configured one. This is the only point at which `GuardianPolicy` may differ from those stated defaults before any guardian exists to approve a `policy_update` ([REQ-7.2-10](#req-7.2-10)).

### 7.2 Update

**`custodial_rotate`** -- replaces `operationalKeys`/`verificationMethods`/`services` wholesale.

- <a id="req-7.2-1"></a>**REQ-7.2-1**: *MUST* be signed by either (a) any single current operational key, or (b) enough current guardians to meet `recovery_threshold`.
- <a id="req-7.2-2"></a>**REQ-7.2-2**: *MUST NOT* modify the guardian tier or `GuardianPolicy`.

**`guardian_add`** -- adds exactly one new guardian, named in `incoming`.

- <a id="req-7.2-3"></a>**REQ-7.2-3**: A registrar *MUST* reject this operation if `incoming` is already a current guardian.
- <a id="req-7.2-4"></a>**REQ-7.2-4**: When the current guardian set is non-empty, required signers are `incoming`'s own key, and enough current guardians to meet `addition_threshold`.
- <a id="req-7.2-5"></a>**REQ-7.2-5**: When the current guardian set is empty, required signers are `incoming`'s own key, and the ward's own current operational key.
- <a id="req-7.2-11"></a>**REQ-7.2-11**: A registrar *MUST* reject this operation if `incoming` names the ward's own identity. A ward is never its own guardian: aside from the confusion of a ward appearing in both roles at once, an effectively-guarded ward's own guardian set must never be allowed to look non-empty when no independent, external oversight actually exists -- which matters directly for `on_orphan` (REQ-5-8), since that safety net is only ever consulted once the guardian set becomes empty.

**`guardian_remove`** -- removes exactly one current guardian, named in `outgoing`.

- <a id="req-7.2-6"></a>**REQ-7.2-6**: A registrar *MUST* reject this operation if `outgoing` is not a current guardian, or is the only current guardian (use `guardian_relinquish` to end the relationship entirely).
- <a id="req-7.2-7"></a>**REQ-7.2-7**: Required signers are either (a) `outgoing`'s own key, alone, or (b) enough of the *other* current guardians (current minus `outgoing`) to meet `removal_threshold` -- *evaluated against the full current guardian set's own size*, the same `N` `guardian_relinquish` (REQ-7.2-8) uses, never against the smaller remaining-guardians pool those signers are drawn from. At exactly two current guardians this makes (b) unreachable: `majority` of `N=2` is `2`, and only one other guardian is ever available to draw from. This is deliberate, not an oversight -- see [§10](#10-security-considerations). A registrar *MUST* additionally reject this operation under either path if it would bring the guardian count below `min_guardian_count` ([REQ-5-7](#req-5-7)).

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
- <a id="req-8-2"></a>**REQ-8-2**: A conformant registrar *MUST* expose, for each identity it hosts, reachable under `https://<domain>/.well-known/guardian/<name>` (or `.../guardian/_` for the bare-domain identity): `GET` the current derived document; `GET` the full operation log; `POST` one new signed operation. A registrar *MAY* expose additional surface; this specification does not constrain it.

## 9. Deactivation and data permanence

- <a id="req-9-1"></a>**REQ-9-1**: The full operation log *MUST* remain permanently, publicly resolvable after `custodial_tombstone`.
- <a id="req-9-2"></a>**REQ-9-2**: A name, once registered, *MUST NOT* be returned to the available pool within its registrar after deactivation.

## 10. Security considerations

- **Trust model**: a registrar is trusted to order operations and resist denial-of-service against its own log; it is not trusted to forge history, since the log is self-certifying and independently replayable by anyone.
- **Key generation and storage** are a registrar-implementation concern, out of this method's own scope -- this document specifies rotation (REQ-6-2 through REQ-6-11, REQ-7.2-1) and revocation (`guardian_remove`, `guardian_relinquish`, `custodial_tombstone`) precisely; how a given registrar generates or custodies the private key material behind an `operationalKeys`/guardian entry is that registrar's own concern, same as it is for `did:web`.
- **Guardian-claim forgery**: a ward cannot be made to falsely name an unwilling party as its guardian ([REQ-7.2-4](#req-7.2-4)/[REQ-7.2-5](#req-7.2-5) structurally require that party's own signature). A party cannot name itself guardian of an already-guarded ward it doesn't already co-guard ([REQ-7.2-4](#req-7.2-4) requires cooperation from enough of the existing guardian set).
- **Registrar-claim forgery**: a forged `registrar` attestation ([REQ-7.1-5](#req-7.1-5)) fails verification the same way any other forged signature does.
- **Guardian key compromise**: a single compromised guardian key cannot act alone in a guardian set held to anything stricter than `any`. `guardian_remove`'s voluntary path ([REQ-7.2-7a](#req-7.2-7)) only ever lets a compromised key remove that same guardian, never another. A compromised sole guardian, or a guardian set deliberately held at `any`, is a real, unmitigated risk. Tombstoning a guardian whose own key is known to be compromised cuts it off from every ward it guards immediately (REQ-4-4) -- a real mitigation, not just damage containment for the compromised identity's own sake.
- **Two-guardian deadlock, deliberate**: at exactly two current guardians, forced `guardian_remove` is unreachable (REQ-7.2-7) -- there is no safe way to let one of two guardians unilaterally eject the other without that same power being available to a bad actor in the same seat. A ward wanting real protection against one uncooperative or compromised co-guardian needs a third guardian; two-guardian wards that lose trust in one party can only dissolve entirely (`guardian_relinquish`, needing both) or have the trusted party voluntarily step down (`guardian_remove`, REQ-7.2-7a) and let the ward go guardian-less, never a clean "eject just the other one."
- **Circular and mutual guardianship**: nothing prevents a ward from guarding its own guardian, directly or in a longer cycle. Mechanically this is safe in the ordinary case (each party's own current key is independently verifiable per REQ-4-2), but it concentrates two real risks worth naming: a circular pair that is secretly operated by a single party is Sybil risk (see below) wearing a specific shape, and a circular pair's own operational availability is more likely to be correlated (shared operator, shared infrastructure) than two genuinely independent parties', which matters because recovery of one from the other only works if the other's own key is actually reachable when needed.
- **Nullification window**: for 72 hours after any operation ([REQ-6-9](#req-6-9)), a verifier *SHOULD* treat current state as provisional, not final -- a guardian-signed recovery rotation can still rewrite history back to that point. A compromised guardian set that also meets `recovery_threshold` can itself abuse nullification within the same window; this is the same class of risk as any other guardian-key compromise (above), not a new one.
- **Name squatting**: names are permanent within a registrar ([§9](#9-deactivation-and-data-permanence)); claiming a name ahead of its likely owner is possible, bounded to one registrar's own namespace.
- **Sybil creation**: nothing in this method limits how many identities one party may register, within a registrar or across many -- circular/mutual guardianship (above) is one concrete shape this risk can take.

## 11. Privacy considerations

- **Data permanence**: the full log stays public forever ([§9](#9-deactivation-and-data-permanence)) -- nothing in `services` should be anything that shouldn't be permanently, publicly linkable to this identity.
- **Key reuse (correlation risk)**: reusing an operational or guardian key across more than one identity can leak a relationship between them that was never meant to be public.
- **Cross-registrar identity unification**: two `did:guardian` identities under different registrars are never provably the same party by this method alone, including when they share a name -- this method makes no correlation between them possible by default.
