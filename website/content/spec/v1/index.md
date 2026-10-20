---
layout: docs
title: "DID Guardian Method Specification v0.1"
description: "A self-authenticating DID method for custodial oversight -- key recovery, revocation, and transfer by one or more guardians -- without impersonation, governed by configurable consensus thresholds."
---
# DID Guardian Method Specification

**Version 0.1, draft.** Modeled closely on [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s own method specification -- a real, proven, 40-million-identifier-scale design for a self-authenticating, directory-resolved DID with key rotation -- adopted wherever it already solves something this method also needs, extended specifically where it doesn't: **group guardianship** as a first-class, cryptographically-enforced relationship, and **domain-qualified identifiers** in place of a single, central directory.

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

**The domain stays dot-joined, never colon-joined, specifically so the name can be optional without becoming ambiguous.** An earlier draft of this spec colon-joined the entire identifier, domain labels included (`did:guardian:alice:acme:com`) -- which works fine as long as a name is always present, but breaks the moment it isn't: `did:guardian:www:example:com` would be unparseable as written, genuinely ambiguous between "a ward named `www` at `example.com`" and "the bare identity for the subdomain `www.example.com`" -- both independently valid, resolvable things that could really coexist, with no way to tell which was meant from the string alone. Keeping the domain as a single, ordinarily-written, dot-joined string closes this outright: a name can never contain a dot (its own ABNF above forbids it), so splitting the identifier on its first colon -- if any -- is always unambiguous. Zero colons after the method name means there's no name at all; this is covered next.

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
  "services": { "registrar": { "type": "GuardianRegistrarService", "endpoint": "https://acme.com" } },
  "registrar": { "did": "did:guardian-registrar:acme.com", "sig": "..." },
  "outgoing": [],
  "incoming": ["did:guardian:acme-board:acme.com"],
  "prev": null,
  "sigs": { "did:guardian:acme-board:acme.com": "..." }
}
```

`did:guardian:<name>:<domain>` becomes valid once this operation is accepted by the registrar (§5) -- the registrar independently checks the name is free *within its own namespace* (no cross-registrar negotiation needed, since names are scoped per registrar, not global). The bare-domain identity (§2.1) is defined by this exact same operation shape, with `name` empty -- auto-provisioned rather than requested, but genesis, signatures, and the hash-chained log all work identically either way.

- **No separate "creator" or "lineage" field exists in this method.** An earlier design (carried over from a human-family-guardianship analogy) tracked "who created this" as its own permanent, separately-signed fact, distinct from guardianship. It turned out to be redundant: the genesis operation is itself permanently hash-chained into the identifier and can never be rewritten, so "who the first guardian was" is already a permanent historical fact, recoverable forever by reading the earliest entry in the guardian history -- with zero extra machinery. Genesis guardian establishment is deliberately given the **exact same shape and consent rule** as an ordinary `guardian_transfer` (§4.3) -- `outgoing: []` (nothing to remove, since there's no prior guardian), `incoming` naming the initial guardian set, `prev: null`. This is not a separate concept bolted onto genesis; it *is* a `guardian_transfer`, just the degenerate first one.
- **`registrar`** (optional): an attestation from the accepting domain's own key (resolved independently, e.g. via that domain's own `did:guardian-registrar:` identity or a well-known key published alongside its directory service), vouching that this specific registration was legitimately accepted into this domain's namespace. This is a genuinely different fact from guardianship -- it's a namespace-authority/trust-vector claim ("this registrar accepted this registration"), not a social-responsibility claim ("this party guards this ward") -- and matters specifically once more than one registrar exists: it gives a verifier an independently-checkable trust anchor and a forensic trace (which authority is accountable for this registration), without requiring the identifier itself to encode anything beyond the domain it's already qualified by. A forged `registrar` claim fails verification the same way any other forged signature does -- checked against the registrar's own resolved key, never assumed from context.
- **`operationalKeys`**: the ward's own, lowest-authority rotation tier (§4.2). For a ward with no independent party able to generate and hold its own keypair at creation time (an autonomous agent, say), this key is generated by whoever is standing up the ward -- a practical bootstrapping fact, not a guardianship claim in itself. Guardianship (the `incoming` field above) is the real, transferable authority relationship, and the two diverge immediately: transfer guardianship once, and the originally-generated operational key becomes irrelevant to anything but ordinary ward-side rotation.

### 4.2 `custodial_rotate` (operational key rotation)

Identical in shape and purpose to `did:plc`'s own regular operation: a signed operation naming the full new state of `operationalKeys`/`verificationMethods`/`services`, with `prev` pointing at the latest valid operation CID. Signed by any current operational-tier key -- did:plc's own any-single-key authority, unchanged. Never touches guardian-tier content; that has its own dedicated operations (§4.3, §4.4) specifically so an ordinary rotation can never, even by a bug, accidentally reach into guardianship.

### 4.3 `guardian_transfer`

```json
{
  "type": "guardian_transfer",
  "outgoing": ["did:guardian:troy:example.com"],
  "incoming": ["did:guardian:caleb:example.com"],
  "prev": "bafyrei...",
  "sigs": {
    "did:guardian:troy:example.com": "...",
    "did:guardian:caleb:example.com": "..."
  }
}
```

`outgoing` must be a subset of the current guardian set -- empty whenever nobody is being removed, including establishing a guardian from a currently guardian-less state (§4.1's genesis case is the degenerate first instance of this, not a special exception to it). `incoming` must be non-empty -- an empty `incoming` is §3.4's shape (`guardian_relinquish`), a different operation, kept separate so "someone's replacing the departing guardian(s)" and "this ward is becoming guardian-less" are never ambiguous from the operation type alone. `incoming` becomes the new guardian set wholesale (not an add/remove delta -- a three-guardian set transferring to two-of-the-original-plus-one-new is expressed as one operation naming the complete new set).

**Signature requirement, stated precisely:** `sigs` carries one signature per affected party, keyed by their own DID, each checked against *that DID's own* independently-resolved keys -- never against the ward's own keys. The set of required signers is `outgoing ∪ (incoming \ current)`, where `current` is the guardian set immediately before this operation: every guardian being removed, plus every guardian who is *genuinely new* -- not already a guardian beforehand. A guardian who continues unaffected (already in `current`, still in `incoming`, not named in `outgoing`) doesn't need to re-sign. Telling "continuing" apart from "newly joining" genuinely requires knowing `current`, not just `outgoing`/`incoming` -- both look identical ("absent from outgoing, present in incoming") without it. Each signature covers the full operation content (`outgoing`, `incoming`, `prev` together), binding it to this exact transfer so it can't be lifted and replayed to vouch for a different one.

This closes two forgery directions by construction, not by convention: a ward cannot be made to falsely name an unwilling party as its guardian (that party's own signature is structurally required), and one co-guardian cannot unilaterally strip a different co-guardian's standing (the co-guardian being removed is named in `outgoing` and must sign too).

**A third requirement, easy to miss and important enough to state on its own: when `current` is empty, the ward's own current operational key must also sign**, alongside the incoming guardian(s). This is establishing guardianship over a previously autonomous, guardian-less ward -- a fundamentally different act from an ordinary reshuffle among guardians the ward already consented to being overseen by. Without this, a willing guardian's own signature alone would be *sufficient* to impose oversight on an autonomous ward that never agreed to acquire one -- a real gap found by testing the zero-to-one case directly, not a hypothetical: the signature set `outgoing ∪ (incoming \ current)` degenerates to just `incoming` when `current` is empty, and nothing in that set requires the ward itself to agree. The fix folds the ward's own DID into the required-signer set specifically for this transition, and only for it -- an ordinary transfer among a ward's own already-established guardians doesn't re-require the ward's consent each time, since that consent was already given once, when oversight was first established.

### 4.4 `guardian_relinquish`

```json
{
  "type": "guardian_relinquish",
  "prev": "bafyrei...",
  "sigs": { "did:guardian:troy:example.com": "..." }
}
```

Sets the guardian set to empty -- full, unattenuated standing for the ward. `sigs` must meet the current `GuardianPolicy.removal_threshold` (§4.6) among current guardians; by default this is `majority`, deliberately stricter than the `any` default for ordinary recovery actions, since this ends the relationship entirely rather than exercising it. Whether the ward's *own* signature can ever substitute for or supplement the guardians' is left explicitly open (§8) -- it decides who actually gets to call a ward ready for full autonomy, and this version doesn't resolve it. Once the guardian set is empty, only `custodial_rotate` (self-signed by the ward's own current operational key) and a future `guardian_transfer` re-establishing a guardian remain available; there is no operation in this version for re-entering guardianship from zero, itself an open question (§8), not a settled permanent rule.

### 4.5 `custodial_tombstone` (deactivate)

`{ "type": "custodial_tombstone", "prev": ..., "sigs": {...} }` -- meeting `GuardianPolicy.tombstone_threshold` (default `any`, i.e. any single current rotation-tier key, operational or guardian). Deactivates the DID; resolution still returns the full historical log (§7), but no new operations are accepted afterward except a recovery nullification within the recovery window (§4.7).

### 4.6 GuardianPolicy and consensus thresholds

Guardian actions are gated by a small, explicit, per-ward policy, not one hardcoded rule for everything:

```json
{
  "recovery_threshold": "any",
  "tombstone_threshold": "any",
  "removal_threshold": "majority",
  "policy_threshold": "majority"
}
```

Each threshold is one of:

- **`any`** -- a single current guardian suffices. Well-defined (vacuously unsatisfiable, not a special case) even when the guardian set is empty.
- **`majority`** -- strictly more than half: `M = floor(N/2) + 1` out of `N` current guardians. This is standard M-of-N multisig semantics, not a two-sided vote -- there's no "against" side to tie against, only a threshold count of consenting signatures, so there is no tie to break. The strictness matters: it guarantees **quorum intersection** -- any two valid signing sets must share at least one member, since two disjoint sets each clearing `>N/2` would together exceed `N`. Loosen this to "at least half" and, for even `N`, two fully disjoint cohorts could each independently clear the bar -- e.g. at `N=4`, `{A,B}` and `{C,D}` each reach 2 with zero overlap, meaning two conflicting operations (a guardian transfer to X and a competing one to Y, say) could both be validly signed with no shared signer to even implicate afterward. Strict majority is what prevents that silent fork. One consequence worth stating rather than hiding: at exactly `N=2`, `majority` and `unanimous` are the same threshold (`floor(2/2)+1 = 2`) -- there's no way to express "more than half but not all" with only two guardians, so a two-guardian ward wanting genuine majority-not-unanimity needs a third guardian for that distinction to mean anything.
- **`unanimous`** -- every current guardian (`M = N`).
- **`{"at_least": N}`** -- an absolute count, for a ward that deliberately wants a fixed bar regardless of how the guardian set grows or shrinks later (e.g. "any two of these specific five founding guardians, permanently"). Not the default for anything, since absolute counts drift relative to a changing set size in ways proportional thresholds (`majority`/`unanimous`) don't.

**Defaults are deliberately loose, not strict.** `recovery_threshold` and `tombstone_threshold` default to `any` so that small guardian sets stay low-friction for exactly the moments speed matters most (an operational key may already be actively compromised). `removal_threshold` -- forcibly removing a guardian *without* their own consent signature, the deadlock-escape mechanism for an unresponsive or uncooperative co-guardian -- defaults to `majority` instead, since bypassing someone's own consent is a meaningfully bigger power than ordinary mutual transfer and shouldn't inherit a loose default by accident.

**The policy governs changes to itself.** Updating `GuardianPolicy` requires meeting whichever threshold `policy_threshold` *currently* names -- defaulting to `majority` -- so weakening your own bar (e.g. dropping `removal_threshold` to `any` right before exploiting a single compromised guardian key) is gated exactly like any other guardian action, never a free unilateral move. This mirrors the same self-referential pattern used elsewhere for policy documents that govern their own editing: a policy is never editable more loosely than its own current rule allows.

**Verification is a simple count-and-check, not an enumeration.** For any signed operation, take the signatures actually submitted, check each is valid and from a DID currently eligible under the relevant set, count them, and compare to the threshold. `O(N)`, never a search over possible cohorts -- the quorum-intersection property above is a structural guarantee that makes reasoning about *other* cohorts unnecessary at verification time.

### 4.7 Key rotation authority and recovery

Directly adopted from `did:plc`, applied to a **tiered** `rotationKeys` structure rather than one flat list:

- **Operational tier** (`operationalKeys`, §4.2): the ward's own, self-rotatable, any-single-key authority -- did:plc's exact mechanism, unchanged.
- **Guardian tier**: implicitly, the current guardian set's own keys (resolved live, never a frozen snapshot -- §4.8). Any current guardian may sign a recovery action meeting `recovery_threshold`; a recovery action may **nullify** an operational-tier rotation within a bounded recovery window (`did:plc` uses 72 hours as its own starting point; this version proposes the same, not a value independently re-derived) by submitting a new operation whose `prev` points to an earlier valid CID than the operation being superseded.

**Guardianship never grants the power to impersonate the ward.** A guardian's recovery action is always signed by the guardian's *own*, distinct key -- never the ward's -- so it remains a separately attributable, auditable operation in the replayed log, never indistinguishable from the ward acting on its own. This holds as a structural guarantee as long as guardian and ward key material is genuinely kept separate (a custody/deployment concern no protocol can enforce, same as any PKI -- the method guarantees attributability of whichever key actually signed, not what a deployer chooses to do with key material outside the protocol).

**Changing *who* is in the guardian tier is not ordinary rotation authority** -- it's gated by `guardian_transfer`'s own per-party consent rule (§4.3), deliberately never reachable via a single guardian's ordinary recovery power, specifically so one guardian can't exploit recovery authority to quietly redefine the guardian set itself.

### 4.8 Guardian status is a live reference, not a frozen key

A ward's guardian entries are DID references, resolved fresh at the time of each new signature -- never a snapshot of a specific key taken when guardianship was established. A guardian rotating their own keys (an ordinary `custodial_rotate` on *their own* identity, unrelated to any ward) never locks them out of any ward relationship: their next signature on a ward's operation is simply checked against whatever their current keys now are. The one real failure mode this doesn't cover is full deactivation of the guardian's own identity (no current key left to resolve at all) -- a real, already-acknowledged risk for a sole-guardian ward, not a new one.

One subtler, correct-but-worth-stating consequence: if a guardian's own key rotation is later nullified within *their own* recovery window (§4.7, applied recursively to their own identity), any ward-level action they signed in the interim using the now-reverted key should be treated as only provisionally valid until their own recovery window closes -- the same "not fully final until past the window" property `did:plc` already has for a single identity, propagating one hop across a guardianship relationship.

## 5. Resolution

Registrars operate independently -- there is no single, central directory for this method, unlike `did:plc`. Resolution is a single, deterministic parse, never a guess-and-retry: split the identifier on its first colon after the method name. No colon -> the entire remainder is the domain and this is the bare-domain identity (§2.1). One colon -> everything before it is the name, everything after is the domain.

**Named identity** (`did:guardian:alice:acme.com`):

1. `GET https://acme.com/.well-known/guardian/alice` -- returns the current, derived DID Document (§3).
2. `GET https://acme.com/.well-known/guardian/alice/log` -- returns the full, timestamped operation log.
3. `POST https://acme.com/.well-known/guardian/alice/operations` -- submits one new signed operation.

**Bare-domain identity** (`did:guardian:acme.com`): identical shape, with the reserved path segment `_` in place of a name -- `_` can never collide with an actual registration, since a name's own ABNF (§2) forbids it.

1. `GET https://acme.com/.well-known/guardian/_` -- returns the current, derived DID Document for the domain's own root identity.
2. `GET https://acme.com/.well-known/guardian/_/log` -- returns its full operation log.
3. `POST https://acme.com/.well-known/guardian/_/operations` -- submits one new signed operation against it.

An earlier draft of this section tried to make a bare and a named identifier distinguishable by having a resolver attempt the longest possible domain interpretation first and fall back to peeling off a leading name segment on a 404. That's unnecessary (§2.1 already makes the two forms lexically distinct, not just probabilistically likely) and was flagged, correctly, as fragile on top of that -- a 404 from an intermediate domain that simply doesn't run a registrar at all isn't the same signal as one from a registrar that genuinely has no bare identity registered, and nothing in that scheme actually resolved the subdomain-collision case (`www` as a name vs. `www.example.com` as a bare identity) it was meant to fix. The dot-joined domain closes that at the grammar level instead, making resolution a parse, not a probe.

Full validation requires replaying the entire log from genesis: checking the genesis hash matches the DID, verifying every operation's signatures against whichever keys/guardians had authority *at that point in the log*, and applying nullification rules -- the registrar's own say-so is never the root of trust, the self-certifying log is, exactly as `did:plc` already establishes for its own single directory.

## 6. Deactivation and data permanence

The full operation log remains permanently, publicly resolvable even after `custodial_tombstone` -- deactivation stops a ward from acting, it does not erase its history. A name is never reclaimed into the available pool within its registrar after deactivation, for the same reason a real person's old handle shouldn't become available for someone else to impersonate them with later.

## 7. Security and privacy considerations

Adopted directly from `did:plc`, unchanged in substance:

- **Trust model**: a registrar is trusted to order operations and resist denial-of-service against its own log; it is not trusted to forge history, since the log is self-certifying and independently replayable by anyone.
- **Data permanence**: the full log stays public forever (§6) -- don't put anything in `services`/`alsoKnownAs` that shouldn't be permanently, publicly linkable to this identity.
- **Key reuse**: reusing an operational or guardian key across more than one identity can leak a relationship between them that was never meant to be public.

New to this method:

- **Guardian-claim forgery, analyzed in both directions.** *A ward falsely claiming an unwilling party as guardian*: closed by §4.3/§4.1's per-party consent requirement -- genesis guardian establishment and every later transfer both require the named party's own signature, checked against their own resolved keys, so a forged claim simply fails verification; the named party never produced it. *A party falsely claiming to be guardian of a ward it doesn't actually guard*: genesis is immutable by construction (§4.1), so this can't be done retroactively against an existing ward's own origin; ongoing guardianship is equally closed, since inserting oneself requires a current guardian's own cooperating signature (§4.3) -- you cannot name yourself guardian of a ward you don't already co-guard. What was already safe before this method existed, for completeness: producing a valid signature without holding the actual key was never possible under the underlying ECDSA scheme -- the gap this method closes is specifically about unverified *relationship* claims riding on top of otherwise-valid, self-authenticated operations, not the base signature scheme itself.
- **Registrar-claim forgery**: can a ward falsely claim a registrar's endorsement it never received? No -- the `registrar` attestation (§4.1) is checked the same way any other signature is, against that registrar's own independently-resolved key; a forged claim fails immediately.
- **Guardian key compromise**: a compromised guardian key could attempt a malicious `guardian_transfer` or recovery action -- mitigated, not eliminated, by the per-party/threshold requirements (§4.3, §4.6): a single compromised key cannot act alone in a multi-guardian set held to anything stricter than `any`. A compromised *sole* guardian, or a guardian set deliberately held at the loose `any` default, is a real, unmitigated risk -- worth flagging rather than glossing over; choosing a stricter threshold or co-guardianship for anything that matters is a policy choice this method makes available, not one it forces.
- **Name squatting**: because names are permanent within a registrar (§2, §6), claiming a name someone else would obviously want, ahead of them, is possible in principle -- though the blast radius is now bounded to one registrar's own namespace rather than a single global one, smaller than an equivalent risk under a flat, centrally-directoried method. This version doesn't propose a mitigation (a reservation period, a dispute process) beyond that natural bound -- flagged as unresolved, not solved by omission.
- **Sybil creation**: nothing in this method limits how many identities one party can register, within a registrar or across many. Intentional, not an oversight -- standing should be earned by a ward's own history, never gated at creation time.
- **Cross-registrar identity unification is not designed in this version.** The same underlying person or organization may hold several, entirely separate `did:guardian` identities under different registrars (§2) -- unifying them (asserting "these are the same actor") needs its own mechanism, and should use the same mutual, bidirectionally-signed pattern as everything else in this method: a credential requiring a signature from *both* identities' own current keys, never a one-sided claim from either side, for exactly the same reason a one-sided guardianship claim is forgeable. Left as an explicit open item (§8), not designed here.

## 8. What this version leaves open

- Whether `guardian_relinquish` can ever be self-initiated by the ward being relinquished, versus always requiring the guardians' own signatures to meet `removal_threshold` -- genuinely unresolved, since it decides who actually gets to call a ward ready for full autonomy.
- Whether a guardian-less ward can ever re-enter guardianship later, and if so, who may initiate it and what it requires.
- The exact recovery window duration (this version proposes `did:plc`'s own 72 hours as a starting point, not independently re-derived).
- Precisely which of a guardian's own keys a signature should be checked against if the guardian later rotates away from the one used, beyond the general "at the time of the signing" principle already stated (§4.8) -- needs more precision before this is fully implementable.
- Cross-registrar identity unification (§7) -- the mechanism is sketched, not designed.
- Rate limits, field size constraints, and DoS-resistance at a registrar -- `did:plc`'s own spec lists these as its own future work too, not a gap unique to this version.
- Interoperability with an identity under a different DID method entirely (an existing `did:web` or `did:plc` identity someone already holds) -- not addressed here.
