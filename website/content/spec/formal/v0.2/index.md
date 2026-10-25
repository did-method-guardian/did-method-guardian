---
layout: docs
title: "DID Guardian Method Specification, v0.2"
description: "The did:guardian DID method: identifier syntax, DID document shape, the operation log, and every operation's exact signature requirements."
---
# DID Guardian Method Specification

`did:guardian` is a self-authenticating DID method that adds group guardianship -- a configurable, cryptographically-enforced set of parties able to recover, revoke, or transfer an identity -- on top of the self-rotation [`did:plc`](https://github.com/did-method-plc/did-method-plc) already provides.

The key words *MUST*, *MUST NOT*, *REQUIRED*, *SHALL*, *SHALL NOT*, *SHOULD*, *SHOULD NOT*, *RECOMMENDED*, *MAY*, and *OPTIONAL* in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Each normative rule carries a stable requirement ID (`REQ-<section>-<n>`); an ID's meaning never changes once published.

## 1. Target system

A registrar: an HTTP server operating one or more `did:guardian` namespaces, one per domain it controls. Unlike `did:plc`, there is no single central directory -- each registrar operates independently, resolved by domain ([§8](#8-resolution)).

## 2. Identifier syntax

```
did-guardian-identifier = "did:guardian:" [ name ":" ] domain
name         = 3*32(ALPHA / DIGIT / "-")
domain       = domain-label *( "." domain-label )
domain-label = 1*63(ALPHA / DIGIT / "-")
```

- **REQ-2-1**: `name`, if present, *MUST* be lowercase ALPHA/DIGIT/"-" only, 3 to 32 characters, *MUST* start and end with ALPHA/DIGIT, and *MUST NOT* contain two consecutive "-" characters.
- **REQ-2-2**: `domain` *MUST* be written dot-joined, exactly as it appears in ordinary DNS usage (e.g. `acme.com`), never colon-joined.
- **REQ-2-3**: An identifier with zero colons after the method name denotes the bare-domain identity for that domain (no `name`).
- **REQ-2-4**: Names are scoped per registrar (per `domain`), not globally -- the same `name` *MAY* exist, as a wholly separate identity with no relationship implied, under two different domains.
- **REQ-2-5**: The bare-domain identity's reserved path segment, where a registrar's own resolution surface needs one, is the literal string `_`. A registrar *MUST* reject any attempt to register `_` as an ordinary `name`.

## 3. DID Document

Resolving an identifier *MUST* yield a document conformant to [W3C DID Core](https://www.w3.org/TR/did-core/), containing:

- **REQ-3-1**: exactly one `verificationMethod` entry per entry in the ward's current `operationalKeys` ([§4](#4-key-material)), each of type `Multikey`.
- **REQ-3-2**: `authentication` and `assertionMethod` arrays referencing every such `verificationMethod`.
- **REQ-3-3**: The guardian tier, `GuardianPolicy`, and the full operation log *MUST NOT* appear in the presented document -- they are method-internal state used to derive it, resolvable separately ([§8](#8-resolution)).

## 4. Key material

- **REQ-4-1**: `operationalKeys` is the ward's own, lowest-authority, self-rotatable tier. Any single current operational key suffices to authorize an ordinary rotation ([§7.2](#72-update)).
- **REQ-4-2**: The guardian tier is, at any point in the log, exactly the current guardian set as derived by replay -- a live reference, never a value fixed at the moment guardianship was established. A signature from a guardian DID *MUST* be checked against that DID's own currently-resolved keys at verification time, not a cached key.
- **REQ-4-3**: A guardian action *MUST* always be signed by the guardian's own distinct key, never the ward's.

## 5. GuardianPolicy

```json
{
  "recovery_threshold": "any",
  "tombstone_threshold": "any",
  "removal_threshold": "majority",
  "addition_threshold": "majority",
  "policy_threshold": "majority"
}
```

- **REQ-5-1**: A threshold value *MUST* be one of: `"any"` (`M = 1` if `N > 0`, else unsatisfiable), `"majority"` (`M = floor(N/2) + 1`), `"unanimous"` (`M = N`), or `{"at_least": k}` (`M = max(k, 0)`), where `N` is the size of the eligible set at evaluation time and `M` is the number of valid, distinct signatures required.
- **REQ-5-2**: `recovery_threshold` governs a guardian-initiated `custodial_rotate` ([§7.2](#72-update)). Default `any`.
- **REQ-5-3**: `tombstone_threshold` governs `custodial_tombstone` ([§7.3](#73-deactivate)). Default `any`.
- **REQ-5-4**: `removal_threshold` governs both a forced `guardian_remove` and `guardian_relinquish` ([§7.2](#72-update)). Default `majority`.
- **REQ-5-5**: `addition_threshold` governs `guardian_add` ([§7.2](#72-update)). Default `majority`.
- **REQ-5-6**: `policy_threshold` governs `policy_update` itself, evaluated against its own currently-effective value, never the proposed new one. Default `majority`.

## 6. The operation log

- **REQ-6-1**: Every identity *MUST* be defined by an append-only, hash-chained, signed log of operations; the DID Document *MUST* always be derived by replaying this log, never stored or trusted directly.
- **REQ-6-2**: Every operation except genesis *MUST* name the CID of the immediately preceding operation (`prev`); a registrar *MUST* reject any operation whose `prev` does not equal the current log head for that identity.
- **REQ-6-3**: The identifier *MUST* be derived from the genesis operation's own content hash, never assigned independently by a registrar.
- **REQ-6-4**: Serialization, hashing, and signing follow `did:plc`: DAG-CBOR encoding, ECDSA signatures (low-S form, base64url-encoded), `prev` as CIDv1 (base32 multibase, dag-cbor codec, sha-256 multihash).
- **REQ-6-5**: Once an identity's `deactivated` state is true ([§7.3](#73-deactivate)), a registrar *MUST* reject every subsequent operation against it.
- **REQ-6-6**: A registrar (or any independent verifier) *MUST* derive current state only by replaying the full log from genesis, verifying every operation's signatures against whichever keys/guardians had authority at that point in the log.
- **REQ-6-7**: Every operation's `sigs` map is keyed by signer DID; each signature *MUST* be checked against that DID's own independently-resolved keys, never the ward's, and *MUST* cover the full operation content, binding it to this exact operation.

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

- **REQ-7.1-1**: `incoming` *MUST* be `[]`. Genesis *MUST NOT* establish a guardian directly -- guardianship, if any, is established by a subsequent `guardian_add` ([§7.2](#72-update)).
- **REQ-7.1-2**: `prev` *MUST* be `null`.
- **REQ-7.1-3**: `operationalKeys`/`verificationMethods`/`services` *MUST* be present.
- **REQ-7.1-4**: `creator` *MUST* be present -- the DID of whichever party initiated this registration. It carries no signature requirement and makes no guardianship or consent claim. A registrar accepting a self-service signup with no other initiating party *MUST* set `creator` to its own bare-domain identity.
- **REQ-7.1-5**: `registrar` *MAY* be present -- an attestation `{did, sig}` from the accepting registrar's own key. If present, a verifier *MUST* check it against the named `did`'s own resolved key.
- **REQ-7.1-6**: A name's own validity (REQ-2-1) and availability within the accepting registrar's own namespace *MUST* both hold for the operation to be accepted.

### 7.2 Update

**`custodial_rotate`** -- replaces `operationalKeys`/`verificationMethods`/`services` wholesale.

- **REQ-7.2-1**: *MUST* be signed by either (a) any single current operational key, or (b) enough current guardians to meet `recovery_threshold`.
- **REQ-7.2-2**: *MUST NOT* modify the guardian tier or `GuardianPolicy`.

**`guardian_add`** -- adds exactly one new guardian, named in `incoming`.

- **REQ-7.2-3**: A registrar *MUST* reject this operation if `incoming` is already a current guardian.
- **REQ-7.2-4**: When the current guardian set is non-empty, required signers are `incoming`'s own key, and enough current guardians to meet `addition_threshold`.
- **REQ-7.2-5**: When the current guardian set is empty, required signers are `incoming`'s own key, and the ward's own current operational key.

**`guardian_remove`** -- removes exactly one current guardian, named in `outgoing`.

- **REQ-7.2-6**: A registrar *MUST* reject this operation if `outgoing` is not a current guardian, or is the only current guardian (use `guardian_relinquish` to end the relationship entirely).
- **REQ-7.2-7**: Required signers are either (a) `outgoing`'s own key, alone, or (b) enough of the *other* current guardians (current minus `outgoing`) to meet `removal_threshold`.

**`guardian_relinquish`** -- sets the guardian set to `[]`.

- **REQ-7.2-8**: Required signers: enough current guardians to meet `removal_threshold`, evaluated against the full current guardian set.

**`policy_update`** -- replaces `GuardianPolicy` wholesale.

- **REQ-7.2-9**: Required signers: enough current guardians to meet the currently-effective `policy_threshold`.
- **REQ-7.2-10**: A registrar *MUST* reject a `policy_update` submitted while the current guardian set is empty.

### 7.3 Deactivate

`custodial_tombstone` -- deactivates the identity (`deactivated = true`; [§6](#6-the-operation-log)).

- **REQ-7.3-1**: Required signers: enough of (the ward's own operational key(s) ∪ the current guardian set) to meet `tombstone_threshold`.

## 8. Resolution

- **REQ-8-1**: Resolution *MUST* split the identifier on its first colon after the method name: no colon denotes the bare-domain identity; one colon denotes `name` then `domain`.
- **REQ-8-2**: A conformant registrar *MUST* expose, for each identity it hosts, reachable under `https://<domain>/.well-known/guardian/<name>` (or `.../guardian/_` for the bare-domain identity): `GET` the current derived document; `GET` the full operation log; `POST` one new signed operation. A registrar *MAY* expose additional surface; this specification does not constrain it.

## 9. Deactivation and data permanence

- **REQ-9-1**: The full operation log *MUST* remain permanently, publicly resolvable after `custodial_tombstone`.
- **REQ-9-2**: A name, once registered, *MUST NOT* be returned to the available pool within its registrar after deactivation.

## 10. Security and privacy considerations

- **Trust model**: a registrar is trusted to order operations and resist denial-of-service against its own log; it is not trusted to forge history, since the log is self-certifying and independently replayable by anyone.
- **Data permanence**: the full log stays public forever ([§9](#9-deactivation-and-data-permanence)) -- nothing in `services` should be anything that shouldn't be permanently, publicly linkable to this identity.
- **Key reuse**: reusing an operational or guardian key across more than one identity can leak a relationship between them that was never meant to be public.
- **Guardian-claim forgery**: a ward cannot be made to falsely name an unwilling party as its guardian (REQ-7.2-4/REQ-7.2-5 structurally require that party's own signature). A party cannot name itself guardian of an already-guarded ward it doesn't already co-guard (REQ-7.2-4 requires cooperation from enough of the existing guardian set).
- **Registrar-claim forgery**: a forged `registrar` attestation (REQ-7.1-5) fails verification the same way any other forged signature does.
- **Guardian key compromise**: a single compromised guardian key cannot act alone in a guardian set held to anything stricter than `any`. `guardian_remove`'s voluntary path (REQ-7.2-7a) only ever lets a compromised key remove that same guardian, never another. A compromised sole guardian, or a guardian set deliberately held at `any`, is a real, unmitigated risk.
- **Name squatting**: names are permanent within a registrar ([§9](#9-deactivation-and-data-permanence)); claiming a name ahead of its likely owner is possible, bounded to one registrar's own namespace.
- **Sybil creation**: nothing in this method limits how many identities one party may register, within a registrar or across many.
- **Cross-registrar identity unification**: not specified by this version ([§11](#11-open-questions)).

## 11. Open questions

- Whether nullification of a rotation within a bounded recovery window (`did:plc`'s own model) should be added -- REQ-6-2's strict `prev`-equals-head rule forecloses it for now.
- Precisely which of a guardian's own keys a signature is checked against if the guardian rotates mid-flight, beyond REQ-4-2's general "at the time of signing" principle.
- Cross-registrar identity unification.
- Rate limits, field size constraints, and DoS-resistance at a registrar.
- Interoperability with an identity under a different DID method entirely.
