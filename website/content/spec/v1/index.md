---
layout: docs
title: "DID Guardian Method Specification v0.1"
description: "A self-authenticating DID method for custodial oversight -- key recovery, revocation, and transfer by one or more guardians -- without impersonation, governed by configurable consensus thresholds."
---
# DID Guardian Method Specification

**Version 0.1, draft.** Modeled closely on [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s own method specification -- a real, proven, 40-million-identifier-scale design for a self-authenticating, directory-resolved DID with key rotation -- adopted wherever it already solves something this method also needs, extended specifically where it doesn't: **group guardianship** as a first-class, cryptographically-enforced relationship, and **domain-qualified identifiers** in place of a single, central directory.

This page is the friendly explainer, kept deliberately narrative. The sole authoritative, normative text is **[the formal specification, v0.2](/spec/formal/v0.2/)** -- RFC 2119 language, numbered requirement IDs, no teaching prose. Where this page and the formal spec ever appear to disagree, the formal spec is correct and this page has drifted; please file an issue. This page's own content below has been updated to match v0.2 throughout. Separately, **[the registrar API spec](/spec/registrar-api/v1/)** documents this specific registrar's own HTTP surface (convenience endpoints, asynchronous signature collection, login) -- a different registrar implementation is free to expose none of it without being non-conformant to the method itself.

## 1. Motivation

Every identity needs to be controllable by its own keys. Some identities also need a *second*, distinct kind of control: an external party capable of recovering, revoking, or transferring the identity if its own keys are lost, compromised, or simply because responsibility for it is changing hands. Family law has a name for this: guardianship -- a relationship that starts for a reason, is mutable, is transferable by mutual consent, can be shared among several guardians at once, and is meant to end. Nothing in `did:plc`, `did:web`, or the W3C DID Core spec itself models this relationship; each leaves "who controls this identity" as a single, flat, undifferentiated set of keys.

This method treats the governed identity as a **ward** and the overseeing party or parties as its **guardian(s)** -- terms chosen specifically because they carry no assumption about what kind of thing is on either side. A person can be ward to another person's guardianship (a board overseeing an executive's company-issued identity), a person's identity can guard an autonomous agent's, or an organization can guard an account it issues and may need to recover. The method doesn't need to know or care which.

## 2. Identifier syntax

```
did-guardian-identifier = "did:guardian:" [ name ":" ] domain
name         = 3*32(ALPHA / DIGIT / "-")
               ; lowercase only; must start and end with ALPHA/DIGIT, not "-";
               ; no consecutive "--"
domain       = domain-label *( "." domain-label )
domain-label = 1*63(ALPHA / DIGIT / "-")
               ; an ordinary DNS label
```

Examples: `did:guardian:alice:acme.com`, `did:guardian:fred:example.org`, `did:guardian:ops-bot:accounts.example.com` (a subdomain registrar), `did:guardian:acme.com` (no name at all -- see below).

The identifier is **name-first, domain dot-joined**: the ward's own chosen name, if any, comes immediately after the method name, followed by a colon, followed by the registering domain written exactly the way it's written everywhere else (`acme.com`, not `acme:com`) -- `alice`, then `acme.com`, reading the same way `alice@acme.com` does. This is a deliberate choice over the reverse-DNS convention `did:web` itself popularized (`did:web:com:acme` is not how `did:web` actually works, but the general reverse-label convention is common elsewhere, e.g. Java package names): reverse-label ordering earns its keep when one shared, central directory needs to prefix-group entries from many different registrars together for efficient indexing. Resolution in this method is already partitioned by registrar (§5 below) -- each registrar's own server only ever serves its own namespace, by construction, independent of how the identifier string reads -- so that benefit doesn't apply here, leaving plain readability as the deciding factor.

**The domain stays dot-joined, never colon-joined.** Writing the domain exactly the way it's written everywhere else (`acme.com`, inside the identifier, not `acme:com`) is what lets the name be optional without any ambiguity: a name can never contain a dot (its own ABNF above forbids it), so splitting the identifier on its first colon -- if any -- always unambiguously separates a name from a domain, no matter how many labels the domain itself has. `did:guardian:www:example.com` (a ward named `www` at `example.com`) and `did:guardian:www.example.com` (the bare identity for the subdomain `www.example.com`) read as two different strings, because they are two different strings. Zero colons after the method name means there's no name at all; this is covered next.

Names are scoped **per registrar**, not globally flat -- and that's not just a syntax detail, it's what makes a real, common situation expressible at all. Take `did:guardian:alice:acme.com`: Alice is Acme's CEO, and a public company's own executive identity is exactly the case this method's group guardianship was built for -- Acme's board of directors is the guardian set, holding real recovery power (if Alice's key is lost or compromised, or her role simply ends) under whatever quorum Acme's own `GuardianPolicy` requires, the same governance relationship a board already has over the role, now expressed over the identity. Alice *also* keeps `did:guardian:alice:fandom.com` -- a personal account on Fandom (fan wikis and fan communities), under a completely different registrar, with no guardian at all. These are two entirely separate, unrelated DIDs: different keys, different guardians (or none), different independent history. That separation is the point, not a limitation -- Alice's corporate identity carries Acme's own governance and accountability; her personal one carries none of it and nobody at Acme can see it, let alone guard it, which is exactly why it's a separate identity rather than a second "account" hanging off the first. Unifying the two later, if Alice ever wanted to, needs its own explicit, consent-based mechanism; see §8's "cross-registrar identity unification" item -- it is deliberately not possible by default.

### 2.1 The bare domain is itself a valid identity

`did:guardian:acme.com` -- no name, no leading colon -- is Acme's own organizational identity, distinct from (and implying nothing about) any person registered under it, the same split `did:web` itself makes between `did:web:acme.com` (the org) and `did:web:acme.com:user:alice` (a person). A registrar auto-provisions this identity for its own configured domain the first time anything resolves it (§5) -- it is never claimed through ordinary registration the way a name is, since there's exactly one per registrar and it belongs to whoever legitimately operates that domain by construction (the same way domain control is already proven for every other resolution in this method: by being the party DNS and TLS actually route the request to).

## 3. DID Document shape

Resolving `did:guardian:alice:acme.com` returns an ordinary [W3C DID Core](https://www.w3.org/TR/did-core/) document:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:guardian:alice:acme.com",
  "verificationMethod": [
    { "id": "did:guardian:alice:acme.com#key-1", "type": "Multikey", "controller": "did:guardian:alice:acme.com", "publicKeyMultibase": "z..." }
  ],
  "authentication": ["did:guardian:alice:acme.com#key-1"],
  "assertionMethod": ["did:guardian:alice:acme.com#key-1"],
  "service": [
    { "id": "did:guardian:alice:acme.com#registrar", "type": "GuardianRegistrarService", "serviceEndpoint": "https://acme.com" }
  ],
  "alsoKnownAs": []
}
```

Only the **operational tier** of rotation keys (§4) is reflected in `verificationMethod`/`authentication`. The guardian tier, `GuardianPolicy`, and the full operation log are method-internal state needed to *produce* this document, never part of the document itself -- the same way `did:plc`'s own `rotationKeys` are omitted from its presented document. Nothing in this document's own shape distinguishes any particular kind of ward from any other.

## 4. The operation log

Every `did:guardian` identity is defined by an append-only, hash-chained, signed log of operations -- the actual source of truth; the DID Document is always *derived* by replaying it, never stored directly. Directly adopted from `did:plc`: each operation (except genesis) names the CID of the immediately preceding operation (`prev`), forming a verifiable chain; the DID itself is derived from the genesis operation's own hash, not assigned by the registrar, so the registrar cannot forge history even though it's the party trusted to order operations and resist denial-of-service against the log. Serialization, hashing, and signing follow `did:plc` directly and unchanged: DAG-CBOR encoding, ECDSA signatures (low-S form, base64url-encoded), `prev` references as CIDv1 (base32 multibase, dag-cbor codec, sha-256 multihash).

### 4.1 `custodial_create` (genesis)

```json
{
  "type": "custodial_create",
  "name": "alice",
  "operationalKeys": ["did:key:z6Mk..."],
  "verificationMethods": { "key-1": "did:key:z6Mk..." },
  "services": {},
  "creator": "did:guardian:acme-board:acme.com",
  "registrar": { "did": "did:guardian:acme.com", "sig": "..." },
  "incoming": [],
  "prev": null
}
```

`did:guardian:<name>:<domain>` becomes valid once this operation is accepted by the registrar (§5) -- the registrar independently checks the name is free *within its own namespace* (no cross-registrar negotiation needed, since names are scoped per registrar, not global). The bare-domain identity (§2.1) is defined by this exact same operation shape, with `name` empty -- auto-provisioned rather than requested, but genesis, signatures, and the hash-chained log all work identically either way.

- **Genesis is always guardian-less** (`incoming: []`, as of v0.2). Establishing a first guardian is never part of genesis itself -- it's always a subsequent, ordinary `guardian_add` (§4.3) under that operation's own zero-to-one rule. This replaces v0.1's "genesis is a degenerate `guardian_transfer`" framing: with `guardian_transfer` itself withdrawn (§4.3), genesis is simpler for it -- just the ordinary zero-guardians starting state every ward has, nothing special about it. From a caller's own point of view, creating a ward *with* an initial guardian is still one API call (§5 of [the registrar API spec](/spec/registrar-api/v1/#2-self-contained-convenience-endpoints)'s `/adopt`-equivalent-at-creation-time convenience) -- but it always produces **two** log entries, `custodial_create` then `guardian_add`, never one entry carrying both facts at once.
- **`creator`** (new in v0.2) -- plain provenance: the DID of whoever initiated this registration. Reintroduced specifically because genesis no longer carries a guardian directly (the thing v0.1 said made a separate creator field redundant no longer holds). It carries no signature requirement of its own and is not a guardianship or consent claim -- a registrar accepting a self-service signup with no other initiating party sets this to its own bare-domain identity (`did:guardian:acme.com` registering `alice` with nobody else behind it sets `creator: "did:guardian:acme.com"`).
- **`registrar`** (optional, and as of v0.2 actually produced by this project's own registrar, not just described): an attestation from the accepting domain's own key, vouching that this specific registration was legitimately accepted into this domain's namespace. This is a genuinely different fact from guardianship -- it's a namespace-authority/trust-vector claim ("this registrar accepted this registration"), not a social-responsibility claim ("this party guards this ward") -- and matters specifically once more than one registrar exists: it gives a verifier an independently-checkable trust anchor and a forensic trace (which authority is accountable for this registration), without requiring the identifier itself to encode anything beyond the domain it's already qualified by. A forged `registrar` claim fails verification the same way any other forged signature does -- checked against the registrar's own resolved key, never assumed from context. (v0.1's example showed a separate `did:guardian-registrar:` identity scheme for this; this project's own registrar instead reuses its own bare-domain identity's already-custodied key, simpler and requiring no second identity scheme.)
- **`operationalKeys`**: the ward's own, lowest-authority rotation tier (§4.2). For a ward with no independent party able to generate and hold its own keypair at creation time (an autonomous agent, say), this key is generated by whoever is standing up the ward -- a practical bootstrapping fact, not a guardianship claim in itself. Guardianship (the `incoming` field above) is the real, transferable authority relationship, and the two diverge immediately: transfer guardianship once, and the originally-generated operational key becomes irrelevant to anything but ordinary ward-side rotation.

### 4.2 `custodial_rotate` (operational key rotation)

Identical in shape and purpose to `did:plc`'s own regular operation: a signed operation naming the full new state of `operationalKeys`/`verificationMethods`/`services`, with `prev` pointing at the latest valid operation CID. Signed by any current operational-tier key -- did:plc's own any-single-key authority, unchanged. Never touches guardian-tier content; that has its own dedicated operations (§4.3, §4.4) specifically so an ordinary rotation can never, even by a bug, accidentally reach into guardianship.

### 4.3 `guardian_add` and `guardian_remove`

**As of v0.2, these replace `guardian_transfer`.** v0.1's single operation named a wholesale new guardian set (`outgoing`/`incoming`), which quietly produced a real inconsistency: this page's own security-considerations section (§7) claimed that "inserting oneself requires a current guardian's own cooperating signature," but the actual signature rule never required that -- a pure addition (nobody removed) only ever needed the *new* guardian's own consent, nothing from anyone already guarding the ward. Splitting "someone's joining" from "someone's leaving" into two operations makes each one's own consent rule unambiguous, and happens to match how group decision-making actually works: adding a new member to a committee and a member stepping down are different acts with different stakes, not two cases of the same form.

```json
{
  "type": "guardian_add",
  "incoming": "did:guardian:caleb:example.com",
  "prev": "bafyrei...",
  "sigs": {
    "did:guardian:caleb:example.com": "...",
    "did:guardian:troy:example.com": "..."
  }
}
```

`guardian_add` names exactly one new guardian. **Required signers**: the incoming party's own key (consenting to take this on), plus enough *current* guardians to meet `addition_threshold` (new in v0.2, default `majority` -- see §4.6). **The zero-to-one exception**: when the ward currently has no guardians at all, `addition_threshold` is vacuously met (there's nobody to ask), but the ward's own current operational key must sign instead, alongside the incoming guardian. This is the one case where establishing guardianship is a fundamentally different act from an ordinary committee decision -- without the ward's own consent here, a single willing guardian could otherwise impose oversight on an autonomous ward that never agreed to acquire one. An ordinary addition to an already-guarded ward never re-asks the ward, since that consent was already given once, when oversight was first established.

```json
{
  "type": "guardian_remove",
  "outgoing": "did:guardian:troy:example.com",
  "prev": "bafyrei...",
  "sigs": { "did:guardian:troy:example.com": "..." }
}
```

`guardian_remove` removes exactly one current guardian. **Required signer: that guardian's own key, alone** -- nothing from any other guardian, continuing or not. This is deliberately the *only* self-contained, single-party way to leave; forcing out an unwilling guardian needs `guardian_relinquish` (§4.4), and only ever as a full dissolution, never a selective removal of one uncooperative party while others remain (an open question, §8).

**A transfer isn't its own operation.** "Move guardianship from Troy to Caleb" is simply `guardian_add` (Caleb, meeting `addition_threshold`) followed by `guardian_remove` (Troy, his own consent) -- in that order, specifically, so the guardian count never crosses zero and never re-triggers the zero-to-one ward-signature rule in the middle of what's really one logical handoff.

### 4.4 `guardian_relinquish`

```json
{
  "type": "guardian_relinquish",
  "prev": "bafyrei...",
  "sigs": { "did:guardian:troy:example.com": "..." }
}
```

Sets the guardian set to empty -- full, unattenuated standing for the ward. `sigs` must meet the current `GuardianPolicy.removal_threshold` (§4.6) among current guardians; by default this is `majority`, deliberately stricter than the `any` default for ordinary recovery actions, since this ends the relationship entirely rather than exercising it. This is deliberately the *only* forced-removal path in this method -- a majority may dissolve the whole relationship even over a dissenting or unresponsive minority's own refusal to sign, something `guardian_remove` (§4.3) structurally can't do, since that one always needs the departing party's own consent. Whether the ward's *own* signature can ever substitute for or supplement the guardians' here is left explicitly open (§8). Once the guardian set is empty, only `custodial_rotate` (self-signed by the ward's own current operational key) and an ordinary `guardian_add` re-establishing a guardian (§4.3's own zero-to-one case) remain available.

### 4.5 `custodial_tombstone` (deactivate)

`{ "type": "custodial_tombstone", "prev": ..., "sigs": {...} }` -- meeting `GuardianPolicy.tombstone_threshold` (default `any`, i.e. any single current rotation-tier key, operational or guardian). Deactivates the DID; resolution still returns the full historical log (§7), and as of v0.2, no further operation of any type is accepted afterward, full stop -- no exception for a recovery window, since this version deliberately doesn't build the nullification mechanism §4.7 once described (see §4.7, below).

### 4.6 GuardianPolicy and consensus thresholds

Guardian actions are gated by a small, explicit, per-ward policy, not one hardcoded rule for everything:

```json
{
  "recovery_threshold": "any",
  "tombstone_threshold": "any",
  "removal_threshold": "majority",
  "addition_threshold": "majority",
  "policy_threshold": "majority"
}
```

Each threshold is one of:

- **`any`** -- a single current guardian suffices. Well-defined (vacuously unsatisfiable, not a special case) even when the guardian set is empty.
- **`majority`** -- strictly more than half: `M = floor(N/2) + 1` out of `N` current guardians. This is standard M-of-N multisig semantics, not a two-sided vote -- there's no "against" side to tie against, only a threshold count of consenting signatures, so there is no tie to break. The strictness matters: it guarantees **quorum intersection** -- any two valid signing sets must share at least one member, since two disjoint sets each clearing `>N/2` would together exceed `N`. Loosen this to "at least half" and, for even `N`, two fully disjoint cohorts could each independently clear the bar -- e.g. at `N=4`, `{A,B}` and `{C,D}` each reach 2 with zero overlap, meaning two conflicting operations (a guardian transfer to X and a competing one to Y, say) could both be validly signed with no shared signer to even implicate afterward. Strict majority is what prevents that silent fork. One consequence worth stating rather than hiding: at exactly `N=2`, `majority` and `unanimous` are the same threshold (`floor(2/2)+1 = 2`) -- there's no way to express "more than half but not all" with only two guardians, so a two-guardian ward wanting genuine majority-not-unanimity needs a third guardian for that distinction to mean anything.
- **`unanimous`** -- every current guardian (`M = N`).
- **`{"at_least": N}`** -- an absolute count, for a ward that deliberately wants a fixed bar regardless of how the guardian set grows or shrinks later (e.g. "any two of these specific five founding guardians, permanently"). Not the default for anything, since absolute counts drift relative to a changing set size in ways proportional thresholds (`majority`/`unanimous`) don't.

**Defaults are deliberately loose, not strict.** `recovery_threshold` and `tombstone_threshold` default to `any` so that small guardian sets stay low-friction for exactly the moments speed matters most (an operational key may already be actively compromised). `removal_threshold` -- forcibly dissolving the whole guardian relationship via `guardian_relinquish`, possibly over a dissenting minority's own refusal -- defaults to `majority` instead, since that's a meaningfully bigger power than an ordinary action and shouldn't inherit a loose default by accident. `addition_threshold` (new in v0.2, §4.3) defaults to `majority` for the same reason: letting in a new co-guardian permanently dilutes everyone else's own existing share of control, and v0.1's own unguarded default (effectively `any`, since nothing checked it at all) is exactly the gap that motivated splitting `guardian_transfer` into `guardian_add`/`guardian_remove` in the first place.

**The policy governs changes to itself, via `policy_update` (new in v0.2).** `{ "type": "policy_update", "prev": ..., "sigs": {...} }` replaces `GuardianPolicy` wholesale, meeting whichever threshold `policy_threshold` *currently* names -- evaluated against its own value immediately before this update, never the new one it's changing to. (v0.1 described this governing relationship in prose but defined no operation that could ever actually change the policy; every ward was permanently stuck on the defaults above until this operation existed.) This gates weakening your own bar (e.g. dropping `removal_threshold` to `any` right before exploiting a single compromised guardian key) exactly like any other guardian action, never a free unilateral move -- a policy is never editable more loosely than its own current rule allows. A `policy_update` is rejected outright if the current guardian set is empty, since there's nobody eligible to meet any threshold at all.

**Verification is a simple count-and-check, not an enumeration.** For any signed operation, take the signatures actually submitted, check each is valid and from a DID currently eligible under the relevant set, count them, and compare to the threshold. `O(N)`, never a search over possible cohorts -- the quorum-intersection property above is a structural guarantee that makes reasoning about *other* cohorts unnecessary at verification time.

### 4.7 Key rotation authority and recovery

Applied to a **tiered** `rotationKeys` structure rather than one flat list, loosely inspired by `did:plc` but, as of v0.2, scoped more narrowly than `did:plc`'s own nullification mechanism (see below):

- **Operational tier** (`operationalKeys`, §4.2): the ward's own, self-rotatable, any-single-key authority -- did:plc's exact mechanism, unchanged.
- **Guardian tier**: implicitly, the current guardian set's own keys (resolved live, never a frozen snapshot -- §4.8). As of v0.2, enough current guardians to meet `recovery_threshold` may themselves sign an ordinary `custodial_rotate` -- this is the actual mechanism that lets a guardian give a ward a fresh operational key once its own is lost, which v0.1 described in this section's own prose but never actually permitted (v0.1's `custodial_rotate` signature rule only ever accepted the ward's own, by-then-unavailable key).
- **Deliberately not built in this version: nullification.** `did:plc` lets a recovery action *supersede* an earlier rotation within a bounded window (72 hours, in `did:plc`'s own design) by pointing a new operation's `prev` at an earlier CID than the one being undone -- meant for "a thief just rotated my key, undo it," a different scenario from "I lost my key, give me a new one." This method's own `prev`-must-equal-current-head rule (§4) has no exception for this, and this version leaves the whole mechanism as an open question (§8) rather than half-building it.

**Guardianship never grants the power to impersonate the ward.** A guardian's recovery action is always signed by the guardian's *own*, distinct key -- never the ward's -- so it remains a separately attributable, auditable operation in the replayed log, never indistinguishable from the ward acting on its own. This holds as a structural guarantee as long as guardian and ward key material is genuinely kept separate (a custody/deployment concern no protocol can enforce, same as any PKI -- the method guarantees attributability of whichever key actually signed, not what a deployer chooses to do with key material outside the protocol).

**Changing *who* is in the guardian tier is not ordinary rotation or recovery authority** -- it's gated by `guardian_add`/`guardian_remove`'s own per-party consent rules (§4.3), deliberately never reachable via a guardian's ordinary recovery power, specifically so a guardian can't exploit recovery authority to quietly redefine the guardian set itself.

### 4.8 Guardian status is a live reference, not a frozen key

A ward's guardian entries are DID references, resolved fresh at the time of each new signature -- never a snapshot of a specific key taken when guardianship was established. A guardian rotating their own keys (an ordinary `custodial_rotate` on *their own* identity, unrelated to any ward) never locks them out of any ward relationship: their next signature on a ward's operation is simply checked against whatever their current keys now are. The one real failure mode this doesn't cover is full deactivation of the guardian's own identity (no current key left to resolve at all) -- a real, already-acknowledged risk for a sole-guardian ward, not a new one.

One subtler, correct-but-worth-stating consequence: if a guardian's own key rotation is later nullified within *their own* recovery window (§4.7, applied recursively to their own identity), any ward-level action they signed in the interim using the now-reverted key should be treated as only provisionally valid until their own recovery window closes -- the same "not fully final until past the window" property `did:plc` already has for a single identity, propagating one hop across a guardianship relationship.

## 5. Resolution

Registrars operate independently -- there is no single, central directory for this method, unlike `did:plc`. Resolution is a single, deterministic parse: split the identifier on its first colon after the method name. No colon -> the entire remainder is the domain and this is the bare-domain identity (§2.1). One colon -> everything before it is the name, everything after is the domain.

**Named identity** (`did:guardian:alice:acme.com`):

1. `GET https://acme.com/.well-known/guardian/alice` -- returns the current, derived DID Document (§3).
2. `GET https://acme.com/.well-known/guardian/alice/log` -- returns the full, timestamped operation log.
3. `POST https://acme.com/.well-known/guardian/alice/operations` -- submits one new signed operation.

**Bare-domain identity** (`did:guardian:acme.com`): identical shape, with the reserved path segment `_` in place of a name -- `_` can never collide with an actual registration, since a name's own ABNF (§2) forbids it.

1. `GET https://acme.com/.well-known/guardian/_` -- returns the current, derived DID Document for the domain's own root identity.
2. `GET https://acme.com/.well-known/guardian/_/log` -- returns its full operation log.
3. `POST https://acme.com/.well-known/guardian/_/operations` -- submits one new signed operation against it.

The identifier's own shape (§2.1) tells a resolver which of the two forms it's looking at before any network request is made.

Full validation requires replaying the entire log from genesis: checking the genesis hash matches the DID and verifying every operation's signatures against whichever keys/guardians had authority *at that point in the log* -- the registrar's own say-so is never the root of trust, the self-certifying log is, exactly as `did:plc` already establishes for its own single directory. (No nullification rules to apply, as of v0.2 -- see §4.7.)

## 6. Deactivation and data permanence

The full operation log remains permanently, publicly resolvable even after `custodial_tombstone` -- deactivation stops a ward from acting, it does not erase its history. A name is never reclaimed into the available pool within its registrar after deactivation, for the same reason a real person's old handle shouldn't become available for someone else to impersonate them with later.

## 7. Security and privacy considerations

Adopted directly from `did:plc`, unchanged in substance:

- **Trust model**: a registrar is trusted to order operations and resist denial-of-service against its own log; it is not trusted to forge history, since the log is self-certifying and independently replayable by anyone.
- **Data permanence**: the full log stays public forever (§6) -- don't put anything in `services`/`alsoKnownAs` that shouldn't be permanently, publicly linkable to this identity.
- **Key reuse**: reusing an operational or guardian key across more than one identity can leak a relationship between them that was never meant to be public.

New to this method:

- **Guardian-claim forgery, analyzed in both directions.** *A ward falsely claiming an unwilling party as guardian*: closed by §4.3's per-party consent requirement -- a `guardian_add` requires the named party's own signature, checked against their own resolved keys, so a forged claim simply fails verification; the named party never produced it. *A party falsely claiming to be guardian of a ward it doesn't actually guard*: genesis is immutable by construction (§4.1), so this can't be done retroactively against an existing ward's own origin. **As of v0.2, ongoing guardianship is also closed for this** -- `addition_threshold` requires enough of a ward's *existing* guardians to cooperate before a new one can join (§4.3/§4.6); you cannot name yourself guardian of an already-guarded ward you don't already co-guard. (v0.1's text claimed this guarantee already held; it didn't -- v0.1's own signature rule for a pure addition required nothing from any existing guardian. `addition_threshold` is the fix, not a restatement.) What was already safe before this method existed, for completeness: producing a valid signature without holding the actual key was never possible under the underlying ECDSA scheme -- the gap this method closes is specifically about unverified *relationship* claims riding on top of otherwise-valid, self-authenticated operations, not the base signature scheme itself.
- **Registrar-claim forgery**: can a ward falsely claim a registrar's endorsement it never received? No -- the `registrar` attestation (§4.1) is checked the same way any other signature is, against that registrar's own independently-resolved key; a forged claim fails immediately.
- **Guardian key compromise**: a compromised guardian key could attempt a malicious `guardian_add`/`guardian_remove` or recovery action -- mitigated, not eliminated, by the per-party/threshold requirements (§4.3, §4.6): a single compromised key cannot act alone in a multi-guardian set held to anything stricter than `any`, and `guardian_remove`'s own single-party shape only ever lets a compromised key remove *that same guardian*, never anyone else. A compromised *sole* guardian, or a guardian set deliberately held at the loose `any` default, is a real, unmitigated risk -- worth flagging rather than glossing over; choosing a stricter threshold or co-guardianship for anything that matters is a policy choice this method makes available, not one it forces.
- **Name squatting**: because names are permanent within a registrar (§2, §6), claiming a name someone else would obviously want, ahead of them, is possible in principle -- though the blast radius is now bounded to one registrar's own namespace rather than a single global one, smaller than an equivalent risk under a flat, centrally-directoried method. This version doesn't propose a mitigation (a reservation period, a dispute process) beyond that natural bound -- flagged as unresolved, not solved by omission.
- **Sybil creation**: nothing in this method limits how many identities one party can register, within a registrar or across many. Intentional, not an oversight -- standing should be earned by a ward's own history, never gated at creation time.
- **Cross-registrar identity unification is not designed in this version.** The same underlying person or organization may hold several, entirely separate `did:guardian` identities under different registrars (§2) -- unifying them (asserting "these are the same actor") needs its own mechanism, and should use the same mutual, bidirectionally-signed pattern as everything else in this method: a credential requiring a signature from *both* identities' own current keys, never a one-sided claim from either side, for exactly the same reason a one-sided guardianship claim is forgeable. Left as an explicit open item (§8), not designed here.

## 8. What this version leaves open

- Whether a majority of guardians may ever forcibly remove *one specific* uncooperative or compromised co-guardian while the rest remain guardians -- today the only forced-removal path (`guardian_relinquish`, §4.4) dissolves the entire relationship; there's no "forced, single-target `guardian_remove`."
- Whether `guardian_relinquish` can ever be self-initiated by the ward being relinquished, versus always requiring the guardians' own signatures to meet `removal_threshold` -- genuinely unresolved, since it decides who actually gets to call a ward ready for full autonomy.
- Nullification of a rotation within a bounded recovery window (did:plc's own 72-hour model) -- deliberately not built this version (§4.7); re-entering guardianship from zero, by contrast, is *resolved* as of v0.2 -- an ordinary `guardian_add` under its own zero-to-one rule (§4.3).
- The exact recovery window duration, if nullification is ever built.
- Precisely which of a guardian's own keys a signature should be checked against if the guardian later rotates away from the one used, beyond the general "at the time of the signing" principle already stated (§4.8) -- needs more precision before this is fully implementable.
- Cross-registrar identity unification (§7) -- the mechanism is sketched, not designed.
- Rate limits, field size constraints, and DoS-resistance at a registrar -- `did:plc`'s own spec lists these as its own future work too, not a gap unique to this version.
- Interoperability with an identity under a different DID method entirely (an existing `did:web` or `did:plc` identity someone already holds) -- not addressed here.
