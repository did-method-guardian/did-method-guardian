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
updated_at: '2026-11-22'
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

# The did:guardian Method, v0.2.0

Status: Draft, 2026-11-22.

## 1. Overview

This section is non-normative.

A did:guardian identity is a signed, hash-chained log of operations, hosted at a domain. The identity's keys control it. Guardians are other DIDs that the identity names. Guardians can recover the identity and govern it, under a policy the identity sets. The registrar for a domain hosts the logs for that domain and attests each new identity. Any party can verify a log without trusting the registrar's word.

did:guardian combines the hosting model of did:web, the signed log of did:plc, and guardianship.

## 2. Conformance

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when they appear in all capitals.

Sections 1, 12, 13 and Appendix A are non-normative. All other sections are normative.

This specification defines requirements for three roles: identities (the parties that create operations), registrars and verifiers.

## 3. Terminology

**identity**
: A DID of this method, and the log that defines it.

**operation**
: A JSON object that changes the state of an identity.

**log**
: The ordered list of all operations of an identity.

**state**
: The values that result from applying every operation of a log in order (Section 6).

**key**
: A P-256 public key in the state's `keys` list.

**guardian**
: A DID in the state's `guardians` list.

**registrar**
: The service that hosts the logs for a domain.

**root identity**
: The identity `did:guardian:<domain>`, which belongs to the registrar of that domain.

**operation hash**
: The hash of an operation, defined in Section 5.2.

**anchor**
: The operation hash of the first operation of a log.

**approval**
: A valid proof on an operation (Section 5.4).

## 4. Identifier

<a id="req-4-1"></a>**REQ-4-1.** A did:guardian DID MUST match one of these forms:

```
did:guardian:<domain>
did:guardian:<domain>:<name>
```

<a id="req-4-2"></a>**REQ-4-2.** `<domain>` MUST be a fully qualified DNS hostname in lowercase, without a trailing dot and without a port.

<a id="req-4-3"></a>**REQ-4-3.** `<name>` MUST be 3 to 32 characters from `a`–`z`, `0`–`9` and `-`. It MUST begin and end with a letter or a digit.

<a id="req-4-4"></a>**REQ-4-4.** The form without `<name>` identifies the root identity of the domain.

<a id="req-4-5"></a>**REQ-4-5.** The path segment of an identity is its `<name>`, or `_` for the root identity.

## 5. Encoding

### 5.1 Values

<a id="req-5-1"></a>**REQ-5-1.** An operation MUST be a JSON object (RFC 8259).

<a id="req-5-2"></a>**REQ-5-2.** Every number in an operation MUST be an integer between 0 and 2^53 − 1.

<a id="req-5-3"></a>**REQ-5-3.** Every string in an operation MUST be valid UTF-8 and MUST NOT contain unpaired surrogates.

<a id="req-5-4"></a>**REQ-5-4.** An operation MUST NOT contain members other than those defined for its type in Section 7.

<a id="req-5-5"></a>**REQ-5-5.** The canonical form of a JSON value is its JSON Canonicalization Scheme serialization (RFC 8785).

### 5.2 Operation hash

<a id="req-5-6"></a>**REQ-5-6.** The operation hash of an operation is computed as follows:

1. Remove the `proof` member from the operation.
2. Serialize the result in canonical form.
3. Compute the SHA-256 digest of the serialization.
4. Prefix the digest with the multihash header bytes `0x12 0x20`.
5. Encode the result as base58btc with the multibase prefix `z`.

### 5.3 Keys

<a id="req-5-7"></a>**REQ-5-7.** A key MUST be a P-256 public key encoded as a Multikey: the multicodec prefix `0x1200` followed by the 33-byte compressed point, encoded as base58btc with the multibase prefix `z`.

### 5.4 Proofs

<a id="req-5-8"></a>**REQ-5-8.** An operation's `proof` member MUST be an array of Data Integrity proofs.

<a id="req-5-9"></a>**REQ-5-9.** Each proof MUST contain exactly these members:

| Member | Value |
|---|---|
| `type` | `"DataIntegrityProof"` |
| `cryptosuite` | `"ecdsa-jcs-2019"` |
| `verificationMethod` | a key reference or a DID reference (REQ-5-12) |
| `proofPurpose` | `"capabilityInvocation"` |
| `proofValue` | the signature |

<a id="req-5-10"></a>**REQ-5-10.** Proofs MUST be created and verified with the `ecdsa-jcs-2019` cryptosuite (W3C Data Integrity ECDSA Cryptosuites v1.0). The secured document is the operation with the `proof` member removed.

<a id="req-5-11"></a>**REQ-5-11.** The signature MUST use the low-S form. A verifier MUST reject a signature whose S value is greater than half the order of the P-256 curve.

<a id="req-5-12"></a>**REQ-5-12.** A `verificationMethod` MUST take one of two forms:

- A **key reference**: `did:key:<key>#<key>`. The signer is the key.
- A **DID reference**: `<did>?versionId=<hash>#key-<n>`. The signer is `<did>`. `<hash>` is the operation hash of an operation in the log of `<did>`. `<n>` is a decimal integer without leading zeros.

<a id="req-5-13"></a>**REQ-5-13.** A proof with a key reference is valid if its signature verifies with that key.

<a id="req-5-14"></a>**REQ-5-14.** A proof with a DID reference is valid if all of these hold:

1. The log of `<did>` contains an operation whose operation hash is `<hash>`.
2. The log of `<did>`, up to and including that operation, verifies (Section 8).
3. The state after that operation is not deactivated.
4. The state after that operation has a key at index `<n>`.
5. The signature verifies with that key.

<a id="req-5-15"></a>**REQ-5-15.** An operation MUST NOT contain two proofs from the same signer.

<a id="req-5-16"></a>**REQ-5-16.** A signer approves an operation if the operation contains a valid proof from that signer.

## 6. State

<a id="req-6-1"></a>**REQ-6-1.** The state of an identity consists of:

| Field | Value |
|---|---|
| `keys` | a list of 1 to 8 distinct keys |
| `guardians` | a list of 0 to 32 distinct DIDs |
| `policy` | a policy object (Section 6.1) |
| `services` | a list of 0 to 32 service objects |
| `alsoKnownAs` | a list of 0 to 32 distinct URI strings |
| `deactivated` | `true` or `false` |

<a id="req-6-2"></a>**REQ-6-2.** A service object MUST contain exactly the members `id`, `type` and `serviceEndpoint`. `id` MUST be a string that begins with `#`. `type` MUST be a string. `serviceEndpoint` MUST be a URI string. Two services in a list MUST NOT have the same `id`.

<a id="req-6-3"></a>**REQ-6-3.** The DID of an identity MUST NOT appear in its `guardians`.

### 6.1 Policy

<a id="req-6-4"></a>**REQ-6-4.** A policy object MAY contain these members and MUST NOT contain others. A member that is absent takes its default value.

| Member | Governs | Allowed values | Default |
|---|---|---|---|
| `recovery` | guardian approval of `update` | `"any"`, `"majority"`, `"all"`, integer k ≥ 1 | `"majority"` |
| `membership` | guardian approval of `addGuardian` and `setPolicy` | `"majority"`, `"all"`, integer k ≥ 1 | `"majority"` |
| `removal` | guardian approval of `removeGuardian` | `"any"`, `"majority"`, `"all"`, integer k ≥ 1 | `"majority"` |
| `deactivation` | approval of `deactivate` | a deactivation object (REQ-6-5) | `{"by": "both", "threshold": "majority"}` |

<a id="req-6-5"></a>**REQ-6-5.** A deactivation object MUST contain exactly the members `by` and `threshold`. `by` MUST be one of `"self"`, `"guardians"`, `"either"` or `"both"`. `threshold` MUST be `"majority"`, `"all"` or an integer k ≥ 1.

### 6.2 Required approvals

<a id="req-6-6"></a>**REQ-6-6.** Let N be the number of guardians in the state before an operation. Let E be the number of guardians eligible to approve it. E equals N, except for `removeGuardian`, where E equals N − 1. For a setting value v, the number of guardian approvals required is computed as follows:

1. Start with a base value: 1 for `"any"`, floor(E / 2) + 1 for `"majority"`, E for `"all"`, and the smaller of k and E for an integer k.
2. If v is not `"any"` and N is at least 2, raise the value to at least 2.
3. For `membership` and for the `threshold` of `deactivation`, raise the value to at least floor(N / 2) + 1.

<a id="req-6-7"></a>**REQ-6-7.** If the required number is greater than E, guardians cannot approve the operation.

## 7. Operations

### 7.1 Common members

<a id="req-7-1"></a>**REQ-7-1.** Every operation MUST contain the members `type`, `prev` and `proof`.

<a id="req-7-2"></a>**REQ-7-2.** `type` MUST be one of `create`, `update`, `addGuardian`, `removeGuardian`, `setPolicy` or `deactivate`.

<a id="req-7-3"></a>**REQ-7-3.** In a `create` operation, `prev` MUST be `null`. In every other operation, `prev` MUST be the operation hash of the preceding operation in the log.

### 7.2 Approval rules

In the following rules, "one current key" means approval by at least one key in the state before the operation. "Guardians per s" means approvals from the number of guardians that REQ-6-6 requires for setting s.

<a id="req-7-4"></a>**REQ-7-4.** An operation MUST have every approval its rule lists. An operation MUST NOT contain a proof from a signer that its rule does not list.

| Type | Required approvals |
|---|---|
| `create` | every key in `keys`; every DID in `guardians`; the root identity of the DID's domain, unless the DID is the root identity |
| `update` | every key in `keys`; and either one current key or guardians per `recovery` |
| `addGuardian` | the added guardian; and one current key if N = 0, otherwise guardians per `membership` |
| `removeGuardian` | one of: the removed guardian; guardians per `removal`, from the guardians other than the removed one; or, if `evidence` is present, one current key or one guardian |
| `setPolicy` | one current key; and guardians per `membership` if N > 0 |
| `deactivate` | if N = 0, one current key; otherwise, as `policy.deactivation.by` specifies: `self`, one current key; `guardians`, guardians per `deactivation.threshold`; `either`, one of the two; `both`, both |

### 7.3 create

<a id="req-7-5"></a>**REQ-7-5.** A `create` operation MUST contain the members `type`, `did`, `keys`, `guardians`, `policy`, `services`, `alsoKnownAs`, `prev` and `proof`.

<a id="req-7-6"></a>**REQ-7-6.** `did` is the DID of the identity. `keys`, `guardians`, `policy`, `services` and `alsoKnownAs` set the initial state, and `deactivated` is `false`.

### 7.4 update

<a id="req-7-7"></a>**REQ-7-7.** An `update` operation MUST contain the members `type`, `keys`, `services`, `alsoKnownAs`, `prev` and `proof`.

<a id="req-7-8"></a>**REQ-7-8.** `update` replaces `keys`, `services` and `alsoKnownAs` in the state.

### 7.5 addGuardian

<a id="req-7-9"></a>**REQ-7-9.** An `addGuardian` operation MUST contain the members `type`, `guardian`, `prev` and `proof`.

<a id="req-7-10"></a>**REQ-7-10.** `guardian` MUST NOT already be a guardian.

<a id="req-7-11"></a>**REQ-7-11.** `addGuardian` appends `guardian` to `guardians`.

### 7.6 removeGuardian

<a id="req-7-12"></a>**REQ-7-12.** A `removeGuardian` operation MUST contain the members `type`, `guardian`, `prev` and `proof`. It MAY contain the member `evidence`.

<a id="req-7-13"></a>**REQ-7-13.** `guardian` MUST be a current guardian.

<a id="req-7-14"></a>**REQ-7-14.** If present, `evidence` MUST be the operation hash of a `deactivate` operation in the log of `guardian`, and the log of `guardian` up to and including that operation MUST verify.

<a id="req-7-15"></a>**REQ-7-15.** `removeGuardian` removes `guardian` from `guardians`.

### 7.7 setPolicy

<a id="req-7-16"></a>**REQ-7-16.** A `setPolicy` operation MUST contain the members `type`, `policy`, `prev` and `proof`.

<a id="req-7-17"></a>**REQ-7-17.** `setPolicy` replaces `policy` in the state.

### 7.8 deactivate

<a id="req-7-18"></a>**REQ-7-18.** A `deactivate` operation MUST contain the members `type`, `prev` and `proof`.

<a id="req-7-19"></a>**REQ-7-19.** `deactivate` sets `deactivated` to `true`.

## 8. Verification

<a id="req-8-1"></a>**REQ-8-1.** A verifier MUST verify the log of a DID by the following steps. The log verifies if every step succeeds.

1. The log is a non-empty array of operations.
2. The first operation is a `create` whose `did` equals the DID.
3. Each later operation's `prev` equals the operation hash of the operation before it.
4. No operation follows a `deactivate`.
5. For each operation in order:
   1. The operation conforms to Sections 5 and 7.
   2. Every proof is valid (REQ-5-13, REQ-5-14).
   3. The approvals meet the rule in REQ-7-4, evaluated against the state before the operation.
   4. The operation's effect produces a state that conforms to Section 6.
   5. Apply the operation to the state.

<a id="req-8-2"></a>**REQ-8-2.** Verification depends only on the log and the logs of the DIDs its proofs reference. It does not depend on the time of verification.

<a id="req-8-3"></a>**REQ-8-3.** A verifier MUST reject a proof whose verification requires verifying, directly or indirectly, the operation that contains it.

<a id="req-8-4"></a>**REQ-8-4.** A verifier that cannot retrieve a referenced log MUST report the log as not verified.

## 9. DID document

<a id="req-9-1"></a>**REQ-9-1.** The DID document of an identity is derived from its state after the last operation of its log.

<a id="req-9-2"></a>**REQ-9-2.** The DID document MUST contain:

| Member | Value |
|---|---|
| `@context` | `["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]` |
| `id` | the DID |
| `verificationMethod` | for each key at index n: `{"id": "<did>#key-<n>", "type": "Multikey", "controller": "<did>", "publicKeyMultibase": "<key>"}` |
| `authentication`, `assertionMethod`, `capabilityInvocation` | the `id` of every verification method |
| `service` | the services, with each `id` prefixed by the DID |
| `alsoKnownAs` | the `alsoKnownAs` list, if it is not empty |

<a id="req-9-3"></a>**REQ-9-3.** DID resolution metadata MUST include `versionId`, the operation hash of the last operation.

<a id="req-9-4"></a>**REQ-9-4.** If the state is deactivated, DID document metadata MUST include `"deactivated": true`, and the DID document MUST NOT contain verification methods.

## 10. Registrar

<a id="req-10-1"></a>**REQ-10-1.** The registrar for a domain MUST serve these resources over HTTPS at `https://<domain>/.well-known/guardian/<segment>`, where `<segment>` is the path segment of the identity (REQ-4-5):

| Method and path | Response |
|---|---|
| `GET .../<segment>/log` | the log, as a JSON array in log order |
| `GET .../<segment>` | the DID document |
| `POST .../<segment>/operations` | accepts one operation as the request body |

<a id="req-10-2"></a>**REQ-10-2.** A registrar MUST accept an operation only if all of these hold:

1. Its `prev` equals the operation hash of the last operation in the log, or it is a `create` for a path segment that has no log.
2. The log, with the operation appended, verifies.
3. In each DID reference, `<hash>` is the operation hash of the last operation in that DID's log at the time of acceptance.

<a id="req-10-3"></a>**REQ-10-3.** For a `create`, the registrar MUST also require that the DID's domain is the registrar's domain and that the name is unused (REQ-10-6). The registrar adds its root identity's proof before it applies REQ-10-2.

<a id="req-10-4"></a>**REQ-10-4.** A registrar MUST create its root identity before it accepts any other `create`.

<a id="req-10-5"></a>**REQ-10-5.** A registrar MUST NOT remove or alter an accepted operation. A registrar MUST continue to serve the log of a deactivated identity.

<a id="req-10-6"></a>**REQ-10-6.** A name, once used, MUST NOT be used for another identity.

<a id="req-10-7"></a>**REQ-10-7.** A registrar that holds the private key of a key, or of a guardian, MUST create proofs with that key only on the authorization of the identity the key belongs to.

<a id="req-10-8"></a>**REQ-10-8.** A registrar MUST respond to a rejected operation with HTTP status 400 and a JSON object with an `error` member that describes the reason.

## 11. Resolution

<a id="req-11-1"></a>**REQ-11-1.** To resolve a DID, a resolver MUST fetch its log from the registrar, verify it (Section 8), and derive the DID document (Section 9).

<a id="req-11-2"></a>**REQ-11-2.** A resolver SHOULD record the anchor of each DID it resolves. If a later resolution of the same DID yields a different anchor, the resolver MUST report that the DID now refers to a different identity.

<a id="req-11-3"></a>**REQ-11-3.** A verifier MAY verify a log that another party presents, together with the logs of the DIDs its proofs reference. A presented log is current only as of its last operation.

## 12. Security considerations

This section is non-normative.

**Stolen key.** A party that holds a stolen key can act as the identity until the guardians replace that key. Those operations remain in the log.

**Unilateral settings.** `recovery: "any"` lets one guardian replace the keys. `removal: "any"` lets one guardian remove another; with two guardians, either can remove the other. `deactivation.by: "self"` or `"either"` lets anyone who holds a key end the identity. Choose these settings deliberately.

**Two guardians.** With two guardians and `removal` other than `"any"`, neither guardian can remove the other. If one guardian becomes unresponsive, the guardian list cannot change except by self-removal. Use three or more guardians to avoid this, or set `removal: "any"`.

**Deactivated guardians.** A guardian whose identity is deactivated cannot approve operations but still counts in N. Remove it with `removeGuardian` and `evidence`.

**Old keys.** A DID reference names a version of the signer's log. A registrar requires the signer's current version (REQ-10-2). A verifier cannot check this later. A party with an old, replaced key and the cooperation of a registrar could produce an operation that verifies.

**Hostile registrar.** A registrar cannot forge proofs. It can refuse operations, serve an outdated log, or serve different logs to different parties. Resolvers detect a replaced log by its anchor (REQ-11-2). Two different logs for one DID, each with a valid attestation, are evidence of registrar misconduct.

**Root identity.** The root identity's key attests every `create` on its domain. A party with that key can attest a forged `create` for an unused name. Recorded anchors protect identities that a resolver has seen before.

**Domain transfer.** A new owner of a domain controls its registrar. The new owner cannot produce logs that match previously recorded anchors.

**Registrar-held keys.** A registrar that holds an identity's key can create proofs as that identity. REQ-10-7 limits when it may do so, but verifiers cannot check that limit.

## 13. Privacy considerations

This section is non-normative.

Logs are public and permanent. Every key, guardian relationship, policy, service and alias that an identity has ever had is visible to anyone. Do not put personal data in names, services or `alsoKnownAs`.

## Appendix A. Examples

This appendix is non-normative. Hashes, keys and signatures are shortened with `…`.

A `create` for `did:guardian:acme.com:alice` with one guardian, before the registrar adds its proof:

```json
{
  "type": "create",
  "did": "did:guardian:acme.com:alice",
  "keys": ["zDnaeAlice…"],
  "guardians": ["did:guardian:acme.com:bob"],
  "policy": {},
  "services": [],
  "alsoKnownAs": [],
  "prev": null,
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "ecdsa-jcs-2019",
      "verificationMethod": "did:key:zDnaeAlice…#zDnaeAlice…",
      "proofPurpose": "capabilityInvocation",
      "proofValue": "z3Fx…"
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "ecdsa-jcs-2019",
      "verificationMethod": "did:guardian:acme.com:bob?versionId=zQmBob…#key-0",
      "proofPurpose": "capabilityInvocation",
      "proofValue": "z5Kq…"
    }
  ]
}
```

The registrar then adds a proof whose `verificationMethod` is `did:guardian:acme.com?versionId=zQmRoot…#key-0`.

An `update` in which Bob replaces Alice's lost key. Alice has one guardian, so `recovery: "majority"` requires one guardian approval:

```json
{
  "type": "update",
  "keys": ["zDnaeAliceNew…"],
  "services": [],
  "alsoKnownAs": [],
  "prev": "zQmCreate…",
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "ecdsa-jcs-2019",
      "verificationMethod": "did:key:zDnaeAliceNew…#zDnaeAliceNew…",
      "proofPurpose": "capabilityInvocation",
      "proofValue": "z2Mn…"
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "ecdsa-jcs-2019",
      "verificationMethod": "did:guardian:acme.com:bob?versionId=zQmBob…#key-0",
      "proofPurpose": "capabilityInvocation",
      "proofValue": "z4Rt…"
    }
  ]
}
```

Required guardian approvals under the default policy:

| Guardians (N) | `recovery` | `membership` | `removal` | `deactivation` (guardian part) |
|---|---|---|---|---|
| 1 | 1 | 1 | not possible | 1 |
| 2 | 2 | 2 | not possible | 2 |
| 3 | 2 | 2 | 2 | 2 |
| 5 | 3 | 3 | 3 | 3 |

With one guardian, `removeGuardian` is approved by the removed guardian, or with `evidence`.

## Changelog

- **v0.2.0** (2026-10-24, current):
  - **2026-11-22**: Replaced the specification. Operations are `create`, `update`, `addGuardian`, `removeGuardian`, `setPolicy`, and `deactivate`. Verification depends only on logs, never on time. Removed nullification, the recovery window, receipts, the signed log head, and verification levels L0 through L3. Removed `creator`, `on_orphan`, and `guardian_transfer`. Entries dated before this one describe the removed design.

- **v0.2.0** (2026-10-24, current): domain-first identifier grammar (`did:guardian:<domain>:<name>`, matching `did:web`'s own convention); the bare-domain identity as a first-class concept ([§2.1](#21-the-bare-domain-identity)); the nullification window ([REQ-6-9](#req-6-9)); every requirement given a stable `REQ-<section>-<n>` id.
  - **2026-11-22**: five more spec-design gaps from the same external review, resolved per the user's own earlier decisions on each: added [REQ-5-10](#req-5-10) -- an unset `GuardianPolicy` field resolves to this document's own stated default only, never a registrar-configured one, and simplified [REQ-7.1-5](#req-7.1-5)/genesis-policy's wording ([REQ-7.1-7](#req-7.1-7)) to match (an earlier version of REQ-7.1-7 allowed a registrar-configured override at genesis specifically, contradicting the general rule this entry now states). Tightened [REQ-7.1-5](#req-7.1-5): the registrar DID a genesis attestation is checked against is now explicitly `did:guardian:<domain-of-did>`, structurally derived from `did` the same way [REQ-7.1-10](#req-7.1-10) already does, never read from the proof's own `verificationMethod` as an independently-trusted value (already true of the reference implementation's `expectedRegistrarDid`; this entry states it normatively). Added a root-identity lifecycle paragraph to [§2.1](#21-the-bare-domain-identity) covering bootstrap (self-attestation, Fix 7), rotation (an ordinary `custodial_rotate`, point-in-time key resolution per [REQ-4-2](#req-4-2) applying to a registrar-as-signer same as a guardian-as-signer), and tombstone (blocks *new* genesis acceptance under that domain without retroactively un-attesting anything already signed). Clarified [REQ-5-1](#req-5-1): `N`/`M` count distinct signer DIDs, never raw signatures or keys -- a ward presenting more than one operational key still counts as exactly one member of a union-based eligible set (already true of `quorum.ts`'s own `Set`-based counting; stated normatively). Added two [§10](#10-security-considerations) entries: cross-registrar guardian history (a guardian hosted elsewhere transitively imports that registrar's own trust properties, deliberately left unrestricted rather than add a same-registrar-only rule with its own edge cases) and name non-reuse ([REQ-9-2](#req-9-2)) relying on registrar honesty, detectable the same way domain takeover already is -- a pinned anchor from first contact ([REQ-12-2](#req-12-2)) catching a later resolution under the same `domain:name` returning a different log entirely.
  - **2026-11-22**: [REQ-8-2](#req-8-2) now requires a log-head endpoint from every conformant registrar -- [L2](#122-verification-levels) freshness moves from a reference-registrar convenience to a method requirement, closing the gap where [Method and registrar profile](#method-and-registrar-profile)'s own summary already described it that way while the requirement's actual text hadn't caught up. The log-head statement's `sig` field (raw base64url, the one signature in this method that didn't follow [REQ-6-7](#req-6-7)'s own format) is replaced with `proof`, a single [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) proof -- never an array, since a log-head statement has exactly one signer by construction. Also stated explicitly what the implementation already did: `seq` counts every entry the full stored log holds, superseded branches included, not just the currently-active chain, so it only ever grows. The reference library's `signLogHeadStatement`/`verifyLogHeadStatement` now use the same `createProof`/`verifyAgainstKeys` machinery every other signature in this method already uses, instead of the separate `signPayload`/`verifyPayload` raw scheme.
  - **2026-11-21**: a coordinated security rewrite, following an external review of this version's own proof-of-possession/registrar-attestation work above. Seven fixes, implemented together since several touch the same signed content:
    - **Fix 1 -- operational-key proof-of-possession, tightened ([REQ-7.1-8](#req-7.1-8)/[REQ-7.2-12](#req-7.2-12))**: the prior `verificationMethods` map (a separate, DID-indexed list of presented keys) is removed entirely -- a DID Document's `verificationMethod` entries are now derived directly from `operationalKeys` by position, with nothing else to desync from it. More importantly, proof-of-possession verification now checks that each operational key has its OWN matching proof, rather than merely that some valid proof exists somewhere in the set -- closing a real gap where an attacker could present a victim's key in the document while actually controlling, and only ever proving possession of, a different key.
    - **Fix 2 -- genesis bound to its own domain ([REQ-7.1-10](#req-7.1-10))**: genesis now carries a required `did` field, and a registrar must reject any genesis whose `did` doesn't match the identity it would actually create under that registrar's own domain. Closes cross-registrar genesis replay: before this, a public genesis accepted at one registrar carried no cryptographic link to where it was meant to live, and could be resubmitted verbatim at a different registrar under the same free name.
    - **Fix 3 -- deterministic, malleability-resistant anchors ([REQ-6-4](#req-6-4))**: a cid is now computed with every proof stripped from the content first, rather than over the full signed operation -- making it independent of which signature happened to be produced, and computable by a client before submission. Paired with this, ECDSA signing/verification now rejects (not merely avoids producing) a signature's high-S, equally-valid-but-malleable counterpart, so a given (message, key) pair has exactly one valid signature, bit for bit.
    - **Fix 4 -- canonicalization and wire format, unified**: serialization moves from DAG-CBOR to [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785); every cid becomes a sha2-256 [multihash](https://github.com/multiformats/multihash), base58btc-encoded with a leading `z`; every public key, everywhere this method presents one, becomes a [Multikey](https://www.w3.org/TR/cid-1.0/#Multikey) -- the earlier base64url SPKI format is now purely an internal implementation detail at the WebCrypto import/export boundary, never part of this method's own wire format.
    - **Fix 5 -- the signed envelope replaced with W3C Data Integrity proofs ([REQ-6-7](#req-6-7))**: the `sig`/`sigs`/`keySigs`/`registrar` fields are retired in favor of one `proof` array of [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) proofs (`ecdsa-jcs-2019`), each proof naming its own signer via `verificationMethod` instead of being keyed externally by DID or raw key string. The registrar's own genesis attestation is now just one more proof in the same array, rather than a separately-shaped field -- see Fix 7 below for the one case where it's absent by design. Because a proof's own `created` timestamp sits outside the (proof-stripped) anchor content, the [L2](#122-verification-levels) log-head statement gains a required `logHash` field separately committing to the full log including every proof, closing the gap where a registrar could otherwise re-sign an identical entry under a different `created` undetected.
    - **Fix 6 -- `GuardianPolicy` versioning replaces "ignore unknown fields" ([REQ-5-9](#req-5-9))**: the previous rule (a verifier ignores any policy field it doesn't recognize) is replaced with an explicit `version` field and a hard refusal: a verifier encountering a policy version newer than it understands must refuse to evaluate ANY operation that policy governs, not just skip the one field it can't parse. The earlier rule was a silent downgrade risk -- ignoring an unrecognized field gives no way to tell whether some OTHER, more restrictive unrecognized field was also supposed to apply to that same decision.
    - **Fix 7 -- root genesis self-attestation ([REQ-7.1-5](#req-7.1-5))**: the bare-domain root identity's own genesis is now explicitly accepted with no separate registrar attestation, since its own required proof of possession already is the only attestation possible for the one identity a deployment bootstraps on its own -- there is no other party on that deployment to vouch for it. Implemented as a narrow exception (`did === registrarDid`) inside genesis verification, not a general carve-out.

      Together these replace every `signCustodialCreate`/`verifyCustodialCreate`/`signCustodialRotate`/`verifyCustodialRotate`/`signGuardianAdd`/`signGuardianRemove`/`signPolicyUpdate`/`signGuardianRelinquish`/`signCustodialTombstone` function in the reference library, the reference registrar's full acceptance path (including its asynchronous multi-signer pending-operations machinery) and its cross-registrar signature relay, and every command in `@did-guardian/cli` that builds or submits an operation. Every interop fixture was regenerated from the reference implementation itself (never hand-edited), plus two new ones specifically exercising Fix 1 (`genesis_pop_key_mismatch.json`) and Fix 6 (`policy_version_gate_blocks_governed_op.json`), and a new accept fixture for Fix 7 (`root_genesis_self_attestation.json`).
  - **2026-11-21**: added [Method and registrar profile](#method-and-registrar-profile), drawing an explicit boundary between what every conformant registrar must do and this reference registrar's operational choices -- prompted by this version's own steps blurring that line in places (genesis submission moving into the method itself, custody modes touching on registrar behavior). The registrar API spec now labels itself a registrar profile, not the method, and [§12.4](#124-key-custody-modes) says plainly that a registrar holding a ward's key is acting as that ward's key-holding client, not exercising a separate method-level authority.
  - **2026-11-21**: relaxed [REQ-7.1-1](#req-7.1-1) -- `incoming` may now name one or more guardians directly at genesis, as long as each co-signs, instead of always being `[]`. Removes the "self-held identities are always born guardian-less" trap, and halves the operations an identity that's always born with a guardian needs (an ephemeral agent fleet under one long-lived guardian, say). Added [REQ-7.1-9](#req-7.1-9): a ward can't name itself as a guardian at genesis either, same reasoning as [REQ-7.2-11](#req-7.2-11). `checkGenesisShape` (`rules.ts`) is wired into the reference registrar's `acceptGenesis` now rather than standing alone as a tested-but-unused function, and checks the new rule's shape (a signature slot exists for each named guardian); genesis's cryptographic checks (those signatures' validity, keySigs, the registrar attestation) still run through `verifyCustodialCreate`, called once the attestation is attached. `@did-guardian/cli`'s `create --guardian <did> --guardian-key <label>` covers the case where the same operator holds both keys. New interop fixtures: a genesis naming an incoming guardian with no signature at all is rejected; one where each named guardian co-signs is accepted (the latter was already covered by an existing fixture, since `verifyCustodialCreate` never actually required `incoming` to be empty -- only this requirement's own wording and the unwired shape check did).
  - **2026-11-21**: amended [REQ-8-2](#req-8-2) -- genesis submission is part of the method now, not a registrar-specific convenience. `POST .../operations` at a name this registrar doesn't yet host accepts a self-signed `custodial_create`, checked for name validity/availability and proof of possession, with the registrar's attestation added before storing it. The reference registrar's `registerWard` (server-generated key) now goes through this exact same acceptance path (`acceptGenesis`, registrar.ts) a client-built genesis does -- one creation path, two kinds of callers. `@did-guardian/cli`'s `create --registrar <domain>` publishes for real now and reports the registrar's returned anchor as the confirmed value for convenience. (Corrected 2026-11-22: per [REQ-6-4](#req-6-4), every proof is stripped before hashing, so this anchor is identical to the one computed locally before the attestation existed -- the attestation never changes it. An earlier version of this entry claimed otherwise; [WS-3.7 audit fix](#changelog) corrected the CLI's own labels to match.) This resolves [issue #4](https://github.com/did-method-guardian/did-method-guardian/issues/4).
  - **2026-11-21**: added [REQ-7.1-8](#req-7.1-8) -- genesis now requires `keySigs` (a field name this same day's later [Fix 5 rewrite above](#changelog) retires in favor of the unified `proof` array; this entry records the requirement's own origin, not its current wire shape), a proof-of-possession signature from every declared operational key, closing the gap where the control chain's root was whatever the registrar's naming attestation asserted, with nothing self-certifying behind it. Generalized the same requirement to `custodial_rotate` as [REQ-7.2-12](#req-7.2-12): any operation that installs a new key carries that key's proof of possession, not just the signature authorizing the change. The reference library's `signCustodialCreate`/`verifyCustodialCreate`/`signCustodialRotate`/`verifyCustodialRotate` (all four, themselves later retired by [Fix 5](#changelog) in favor of the current proof-model functions) and the real server-side `rotateRule` (`rules.ts`) all checked it; every interop fixture was regenerated to match.
  - **2026-11-19**: implemented [L2](#122-verification-levels) (REQ-12-1) -- the reference registrar now exposes a signed log-head statement at `.../log-head` (registrar API spec), using the same key as REQ-7.1-5's genesis attestation. Also added `multikeyToSpki` to the reference library (the inverse of `spkiToMultikey`), closing a real gap this surfaced: a verifier who only has a resolved DID document had no way to get back to this library's internal key format needed to check any signature at all. [Issue #5](https://github.com/did-method-guardian/did-method-guardian/issues/5) is now fully addressed by this and the REQ-12-4 work below.
  - **2026-11-19**: implemented [REQ-12-4](#req-12-4)'s anchor field on `guardian_add` -- the reference library's `GuardianAddOp` type, the reference registrar's same-registrar convenience paths, `@did-guardian/cli`'s `guardian add`, and the JSON Schema all carry it now. (Filed [issue #6](https://github.com/did-method-guardian/did-method-guardian/issues/6) while adding this: the `interop_tests/` conformance suite has no fixture exercising a standalone `guardian_add` at all, independent of the anchor field specifically.)
    - **2026-11-21**: closed [issue #6](https://github.com/did-method-guardian/did-method-guardian/issues/6). Added `guardian_add_zero_to_one.json` (accept) and `guardian_add_missing_ward_signature.json` (reject), and fixed the gap the issue's title undersold: `interop.test.ts`'s `verifyLog` harness had no case for `guardian_add`, `guardian_remove`, or `policy_update` at all -- any fixture exercising one would have silently passed regardless of whether its signatures were actually valid, since none of those types matched any branch and the loop just moved on. Now routed through `verifyByRules` (`rules.ts`), the same function the registrar uses, with the fixture's state replayed incrementally as of just before each entry.
  - **2026-11-18**: documented domain migration as explicitly out of scope for this version ([§9](#9-deactivation-and-data-permanence)), with "link, don't move" (a new identifier plus mutual `alsoKnownAs`) as the documented alternative. Added [§12, Authority and trust model](#12-authority-and-trust-model) -- the three authorities (control/naming/currency), verification levels L0-L3 and the first-contact-then-pin rule ([REQ-12-1](#req-12-1)/[REQ-12-2](#req-12-2)/[REQ-12-3](#req-12-3)), pinning ([REQ-12-4](#req-12-4)), and non-normative key custody modes ([§12.4](#124-key-custody-modes)). Reworded [REQ-6-3](#req-6-3) -- the anchor (genesis content hash) is a property of the log, not of the identifier, which was never actually hash-derived under this version's domain-first grammar. Tightened [REQ-7.1-5](#req-7.1-5) from `MAY` to `MUST`: every genesis now requires a registrar attestation, not just accepts one if present -- the reference library's `verifyCustodialCreate` function (later rewritten, same name retained, by [Fix 5](#changelog)'s proof-model migration) and every interop fixture were updated to match. Added security-considerations entries for log forgery/stale snapshots, domain takeover, equivocation, and custody disclosure.
- **v0.1** (2026-10-19 through 2026-10-23): initial draft, before the method specification, registrar API, and guide were split into separate documents. Never published as its own standalone page.
