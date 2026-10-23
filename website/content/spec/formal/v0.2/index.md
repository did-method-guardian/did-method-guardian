---
layout: docs
title: "DID Guardian Method Specification (Formal), v0.2"
description: "The authoritative, RFC 2119 normative specification of the did:guardian method -- identifier syntax, DID document shape, the operation log, and every operation's exact signature requirements."
---
# DID Guardian Method Specification (Formal)

**Version 0.2.** This document is the sole normative, authoritative specification of the `did:guardian` method. It supersedes v0.1 (see [§12](#12-changes-from-v01)). It intentionally contains no motivation, no worked examples beyond what disambiguates a rule, and no teaching prose -- for that, read [the explainer](/spec/v1/), which describes this document rather than the other way around. This document also makes no statement about any one registrar's own HTTP surface beyond the three endpoints every conformant registrar MUST expose ([§9](#9-resolution)); a specific registrar's additional API (convenience endpoints, login flows, asynchronous signature collection, etc.) is out of scope here by design -- see [the registrar API specification](/spec/registrar-api/v1/) for one registrar's own such surface. A registrar MAY differ from that document in every particular without being non-conformant to this one.

## 1. Conformance language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

Each normative rule below carries a stable requirement ID of the form `REQ-<section>-<n>` (e.g. `REQ-6.3-2`). An ID's number never changes meaning once published; a rule that is later removed is marked **Withdrawn** rather than reused for something else, and a new rule gets a new, previously-unused ID.

## 2. Identifier syntax

```
did-guardian-identifier = "did:guardian:" [ name ":" ] domain
name         = 3*32(ALPHA / DIGIT / "-")
domain       = domain-label *( "." domain-label )
domain-label = 1*63(ALPHA / DIGIT / "-")
```

- **REQ-2-1**: `name`, if present, MUST be lowercase ALPHA/DIGIT/"-" only, 3 to 32 characters.
- **REQ-2-2**: `name` MUST start and end with ALPHA/DIGIT, never "-".
- **REQ-2-3**: `name` MUST NOT contain two consecutive "-" characters.
- **REQ-2-4**: `domain` MUST be written dot-joined, exactly as it appears in ordinary DNS usage (e.g. `acme.com`), never colon-joined.
- **REQ-2-5**: An identifier with zero colons after the method name denotes the bare-domain identity for that domain (no `name`).
- **REQ-2-6**: Names are scoped per registrar (per `domain`), not globally -- the same `name` MAY exist, as a wholly separate identity with no relationship implied, under two different domains.
- **REQ-2-7**: The bare-domain identity's reserved path segment, where a registrar's own resolution surface needs one, is the literal string `_`. A registrar MUST reject any attempt to register `_` as an ordinary `name` (already excluded by REQ-2-2, since `_` is neither ALPHA nor DIGIT).

## 3. DID Document

Resolving an identifier MUST yield a document conformant to W3C DID Core, containing:

- **REQ-3-1**: exactly one `verificationMethod` entry per entry in the ward's current `operationalKeys` ([§5](#5-key-tiers)), each of type `Multikey`.
- **REQ-3-2**: `authentication` and `assertionMethod` arrays referencing every such `verificationMethod`.
- **REQ-3-3**: The guardian tier, `GuardianPolicy`, and the full operation log MUST NOT appear in the presented document -- they are method-internal state used to *produce* it, resolvable separately ([§9](#9-resolution)).

## 4. The operation log

- **REQ-4-1**: Every identity MUST be defined by an append-only, hash-chained, signed log of operations; the DID Document MUST always be derived by replaying this log, never stored or trusted directly.
- **REQ-4-2**: Every operation except genesis MUST name the CID of the immediately preceding operation (`prev`); a registrar MUST reject any operation whose `prev` does not equal the current log head for that identity (no exceptions -- this method defines no operation that supersedes an earlier entry; see [§13](#13-open-questions)).
- **REQ-4-3**: The identifier MUST be derived from the genesis operation's own content hash, never assigned independently by a registrar.
- **REQ-4-4**: Serialization, hashing, and signing follow `did:plc`: DAG-CBOR encoding, ECDSA signatures (low-S form, base64url-encoded), `prev` as CIDv1 (base32 multibase, dag-cbor codec, sha-256 multihash).
- **REQ-4-5**: Once an identity's `deactivated` state is true ([§11](#11-deactivation)), a registrar MUST reject every subsequent operation of every type against it.

## 5. Key tiers

- **REQ-5-1**: `operationalKeys` is the ward's own, lowest-authority, self-rotatable tier. Any single current operational key suffices to authorize an ordinary rotation ([§6.2](#62-custodial_rotate)).
- **REQ-5-2**: The guardian tier is, at any point in the log, exactly the current guardian set as derived by replay -- a live reference, never a value fixed at the moment guardianship was established. A signature from a guardian DID MUST be checked against that DID's own currently-resolved keys at verification time, not a cached key.
- **REQ-5-3**: A guardian action MUST always be signed by the guardian's own distinct key, never the ward's -- a guardian MUST NOT be able to produce an operation indistinguishable from the ward acting on its own.

## 6. Operations

Every operation is a `type`, a `prev` (except genesis), and a `sigs` map keyed by signer DID (`custodial_rotate` uses a single `sig` instead, per REQ-5-1's any-single-key model).

### 6.1 `custodial_create` (genesis)

- **REQ-6.1-1**: `incoming` MUST be `[]`. Genesis MUST NOT establish a guardian directly -- guardianship, if any, is always established by a subsequent `guardian_add` ([§6.3](#63-guardian_add)). *(This withdraws and replaces v0.1's genesis-is-a-degenerate-transfer model; see [§12](#12-changes-from-v01).)*
- **REQ-6.1-2**: `prev` MUST be `null`.
- **REQ-6.1-3**: `operationalKeys`/`verificationMethods`/`services` MUST be present, establishing the ward's initial operational tier.
- **REQ-6.1-4**: `creator` MUST be present -- the DID of whichever party initiated this registration. It is provenance metadata: it carries no signature requirement of its own and makes no guardianship or consent claim. A registrar accepting a self-service signup with no other initiating party MUST set `creator` to its own bare-domain identity.
- **REQ-6.1-5**: `registrar` MAY be present -- an attestation `{did, sig}` from the accepting registrar's own key, vouching that this registration was legitimately accepted into this namespace. A registrar MUST verify this the same as any other signature (against the named `did`'s own resolved key) if present; its absence is not itself an error.
- **REQ-6.1-6**: A name's own validity (REQ-2-1 through REQ-2-3) and availability within the accepting registrar's own namespace MUST both hold for the operation to be accepted.

### 6.2 `custodial_rotate`

- **REQ-6.2-1**: Replaces `operationalKeys`/`verificationMethods`/`services` wholesale (full new state, not a delta).
- **REQ-6.2-2**: MUST be signed by either (a) any single current operational key, or (b) enough current guardians to meet `recovery_threshold` ([§7](#7-guardianpolicy)).
- **REQ-6.2-3**: MUST NOT modify the guardian tier or `GuardianPolicy` -- those have their own dedicated operations ([§6.3](#63-guardian_add)-[§6.6](#66-policy_update)).

### 6.3 `guardian_add`

- **REQ-6.3-1**: Adds exactly one new guardian, named in `incoming` (a single DID). A registrar MUST reject this operation if `incoming` is already a current guardian.
- **REQ-6.3-2**: When the current guardian set is non-empty, required signers are: `incoming`'s own key, AND enough current guardians to meet `addition_threshold` ([§7](#7-guardianpolicy)).
- **REQ-6.3-3**: When the current guardian set is empty, required signers are: `incoming`'s own key, AND the ward's own current operational key. *(`addition_threshold` is vacuously satisfied with zero current guardians to ask; the ward's own consent is required instead -- this is the zero-to-one case, and it is the only case in which the ward's own key signs a guardian-tier operation.)*
- **REQ-6.3-4**: Each signature MUST cover the full operation content, binding it to this exact addition.

### 6.4 `guardian_remove`

- **REQ-6.4-1**: Removes exactly one current guardian, named in `outgoing` (a single DID). A registrar MUST reject this operation if `outgoing` is not a current guardian, or if it is the *only* current guardian (use `guardian_relinquish`, [§6.5](#65-guardian_relinquish), to end the relationship entirely).
- **REQ-6.4-2**: Required signer: `outgoing`'s own key, alone. No other current guardian's signature is required or consulted.

### 6.5 `guardian_relinquish`

- **REQ-6.5-1**: Sets the guardian set to `[]` -- every current guardian relinquishes at once, regardless of whether each individually signed.
- **REQ-6.5-2**: Required signers: enough current guardians to meet `removal_threshold` ([§7](#7-guardianpolicy)) -- a majority (the default) MAY force out a minority that does not or cannot sign, which `guardian_remove` structurally cannot do. This is the method's only forced-removal mechanism, and it only ever dissolves the relationship entirely (see [§13](#13-open-questions) for the narrower case this does not cover).
- **REQ-6.5-3**: Whether the ward's own signature may ever substitute for or supplement the guardians' here is explicitly out of scope for this version ([§13](#13-open-questions)); a registrar MUST NOT treat the ward's own signature as counting toward `removal_threshold`.

### 6.6 `policy_update`

- **REQ-6.6-1**: Replaces `GuardianPolicy` wholesale (full new state, not a delta).
- **REQ-6.6-2**: Required signers: enough current guardians to meet the *currently effective* `policy_threshold` -- i.e. the threshold in force immediately before this operation, never the one it is changing to.
- **REQ-6.6-3**: A registrar MUST reject a `policy_update` submitted while the current guardian set is empty (nobody eligible to meet any threshold).

### 6.7 `custodial_tombstone`

- **REQ-6.7-1**: Deactivates the identity (`deactivated = true`); see [§11](#11-deactivation) for effect.
- **REQ-6.7-2**: Required signers: enough of (the ward's own operational key(s) ∪ the current guardian set) to meet `tombstone_threshold` ([§7](#7-guardianpolicy)).

## 7. GuardianPolicy

```json
{
  "recovery_threshold": "any",
  "tombstone_threshold": "any",
  "removal_threshold": "majority",
  "addition_threshold": "majority",
  "policy_threshold": "majority"
}
```

- **REQ-7-1**: `addition_threshold` governs `guardian_add` ([§6.3](#63-guardian_add)) when the guardian set is non-empty. Default `majority`. *(New in v0.2 -- see [§12](#12-changes-from-v01).)*
- **REQ-7-2**: `removal_threshold` governs `guardian_relinquish` ([§6.5](#65-guardian_relinquish)) only. Default `majority`. It does not govern `guardian_remove`, which requires no threshold at all (REQ-6.4-2).
- **REQ-7-3**: `recovery_threshold` governs a guardian-initiated `custodial_rotate` (REQ-6.2-2b). Default `any`.
- **REQ-7-4**: `tombstone_threshold` governs `custodial_tombstone`. Default `any`.
- **REQ-7-5**: `policy_threshold` governs `policy_update` itself, evaluated against its own *current* value before the update, never the proposed new value. Default `majority`.
- **REQ-7-6**: A threshold value MUST be one of: `"any"` (`M = 1` if `N > 0`, else unsatisfiable), `"majority"` (`M = floor(N/2) + 1`), `"unanimous"` (`M = N`), or `{"at_least": k}` (`M = max(k, 0)`), where `N` is the size of the eligible set at evaluation time and `M` is the number of valid, distinct signatures required.
- **REQ-7-7**: At `N = 2`, `"majority"` and `"unanimous"` denote the same `M` (`2`); this is a property of the arithmetic, not a special case a registrar must implement separately.

## 8. Replay

- **REQ-8-1**: A registrar (or any independent verifier) MUST derive current state only by replaying the full log from genesis, verifying every operation's signatures against whichever keys/guardians had authority *at that point in the log* -- a registrar's own say-so is never the root of trust.
- **REQ-8-2**: State derived by replay consists of: `operationalKeys`, `verificationMethods`, `services`, the current guardian set, the current `GuardianPolicy`, and `deactivated`.

## 9. Resolution

- **REQ-9-1**: A conformant registrar MUST expose, for each identity it hosts, at minimum: `GET` the current derived document; `GET` the full operation log; `POST` one new signed operation.
- **REQ-9-2**: A registrar MAY expose any additional surface beyond REQ-9-1; such surface is not specified by this document (see [the registrar API specification](/spec/registrar-api/v1/) for one registrar's own choices).

## 10. Deactivation and data permanence

- **REQ-10-1**: The full operation log MUST remain permanently, publicly resolvable after `custodial_tombstone` -- deactivation stops an identity from acting, it does not erase its history.
- **REQ-10-2**: A name, once registered, MUST NOT be returned to the available pool within its registrar after deactivation.

## 11. Deactivation

Covered under [§4](#4-the-operation-log) (REQ-4-5) and [§10](#10-deactivation-and-data-permanence); this section intentionally left as a cross-reference, not a duplicate ruleset.

## 12. Changes from v0.1

v0.1 was this document's own predecessor, published only as narrative prose (now [the explainer](/spec/v1/)), never as a separately versioned formal text. Substantive changes, for anyone tracking what moved:

- `guardian_transfer` is withdrawn, replaced by `guardian_add` ([§6.3](#63-guardian_add)) and `guardian_remove` ([§6.4](#64-guardian_remove)). v0.1's single wholesale-replacement operation conflated departure (needs only the departing party's own consent) with arrival (needed nothing from the existing committee at all, contradicting v0.1's own security-considerations prose) into one ambiguous shape.
- Genesis (REQ-6.1-1) now always starts guardian-less; establishing a first guardian is always a subsequent, ordinary `guardian_add` under its own zero-to-one rule (REQ-6.3-3), not a special "degenerate transfer."
- `creator` (REQ-6.1-4) is reintroduced on `custodial_create`. v0.1 argued this field was redundant with "who the first guardian was," which only held while genesis could carry a guardian directly; it no longer can.
- `addition_threshold` (REQ-7-1) is new, closing the gap above.
- `policy_update` ([§6.6](#66-policy_update)) is new -- v0.1 described `policy_threshold` as governing policy changes but defined no operation that could ever make one.
- `custodial_rotate` (REQ-6.2-2b) may now also be signed by guardians meeting `recovery_threshold`, not only the ward's own key -- v0.1 described guardian-initiated recovery in prose but its own signature rule never actually permitted it.
- Tombstone (REQ-4-5) now actually halts every later operation; v0.1 described this but no registrar enforced it.

## 13. Open questions

- Whether a majority of guardians may ever forcibly remove *one specific* uncooperative or compromised co-guardian while the rest remain guardians -- today the only forced-removal path (`guardian_relinquish`) dissolves the entire relationship; there is no "forced `guardian_remove`."
- Whether `guardian_relinquish` can ever be self-initiated by the ward being relinquished (REQ-6.5-3 currently forbids counting the ward's own signature toward it).
- Whether a guardian-less ward can ever re-enter guardianship after `guardian_relinquish` by any path other than an ordinary zero-to-one `guardian_add`.
- Nullification of a rotation within a bounded recovery window (did:plc's own 72-hour model) -- deliberately not built this version; REQ-4-2's strict `prev`-must-equal-head rule forecloses it entirely for now.
- The exact recovery window duration, if nullification is ever built.
- Precisely which of a guardian's own keys a signature is checked against if the guardian rotates mid-flight, beyond REQ-5-2's general "at the time of signing" principle.
- Cross-registrar identity unification.
- Rate limits, field size constraints, and DoS-resistance at a registrar.
- Interoperability with an identity under a different DID method entirely.
