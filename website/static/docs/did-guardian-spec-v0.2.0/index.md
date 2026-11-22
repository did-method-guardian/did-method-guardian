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

A did:guardian identity is a signed, hash-chained log of operations, hosted at a domain. The identity's keys control it. Guardians are other did:guardian identities that the identity names, and each guardian records the identities it guards in its log. Guardians can recover the identity and govern it, under a policy the identity sets. The registrar for a domain hosts the logs for that domain, decides the order of their operations, and attests each new identity.

Every proof on an operation verifies from the log that contains it. When an operation involves another identity, the registrar checks that identity's current log before it accepts the operation. Resolvers check attestations and the state of guardian relationships.

did:guardian combines the hosting model of did:web, the signed log of did:plc, and guardianship.

## 2. Conformance

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when they appear in all capitals.

Sections 1, 12, 13 and Appendix A are non-normative. All other sections are normative.

This specification defines requirements for identities, registrars and resolvers.

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
: A P-256 public key.

**guardian**
: An identity named in another identity's `guardians`.

**ward**
: An identity that names a guardian.

**successor**
: An identity named in another identity's `successor`. It becomes the guardian when the last guardian is removed (Section 6.2).

**entry**
: The record of a guardian or a successor in a ward's state (REQ-6-2).

**registrar**
: The service that hosts the logs for a domain.

**root identity**
: The identity `did:guardian:<domain>`, which belongs to the registrar of that domain.

**operation hash**
: The hash of a complete operation (Section 5.2).

**version**
: The operation hash of an operation in a log. The version of a log is the operation hash of its last operation.

**anchor**
: The hash of parts of the first operation of a log (REQ-5-7).

## 4. Identifier

<a id="req-4-1"></a>**REQ-4-1.** A did:guardian DID MUST match one of these forms:

```
did:guardian:<domain>
did:guardian:<domain>:<name>
```

<a id="req-4-2"></a>**REQ-4-2.** `<domain>` MUST be a DNS hostname of two or more labels, in lowercase, at most 253 characters long. Each label MUST be 1 to 63 characters from `a`–`z`, `0`–`9` and `-`, and MUST begin and end with a letter or a digit. Internationalized names MUST use their A-label form. The last label MUST NOT consist only of digits.

<a id="req-4-3"></a>**REQ-4-3.** `<name>` MUST be 3 to 32 characters from `a`–`z`, `0`–`9` and `-`. It MUST begin and end with a letter or a digit.

<a id="req-4-4"></a>**REQ-4-4.** The form without `<name>` identifies the root identity of the domain.

<a id="req-4-5"></a>**REQ-4-5.** The path segment of an identity is its `<name>`, or `_` for the root identity.

<a id="req-4-6"></a>**REQ-4-6.** Two DIDs are equal if their strings are equal.

## 5. Encoding

### 5.1 Values

<a id="req-5-1"></a>**REQ-5-1.** An operation MUST be an I-JSON message (RFC 7493).

<a id="req-5-2"></a>**REQ-5-2.** Every number in an operation MUST have an integer value between 0 and 2^53 − 1.

<a id="req-5-3"></a>**REQ-5-3.** An operation MUST contain exactly the members that Section 7 defines for its type, and MAY also contain the members `extensions` and `critical` (Section 7.11). Every object inside an operation MUST contain exactly the members that this specification defines for it. A policy object MAY also contain the member `extensions`.

<a id="req-5-4"></a>**REQ-5-4.** The canonical form of a JSON value is its JSON Canonicalization Scheme serialization (RFC 8785).

<a id="req-5-5"></a>**REQ-5-5.** Two lists of keys are equal if they contain the same keys, in any order.

### 5.2 Hashes

<a id="req-5-6"></a>**REQ-5-6.** The hash of a JSON value is computed as follows:

1. Serialize the value in canonical form.
2. Compute the SHA-256 digest of the serialization.
3. Prefix the digest with the multihash header bytes `0x12 0x20`.
4. Encode the result as base58btc with the multibase prefix `z`.

The operation hash of an operation is the hash of the complete operation.

<a id="req-5-7"></a>**REQ-5-7.** The anchor of a log is the hash of its first operation with the `proof`, `attestation`, `guardians` and `successor` members removed.

### 5.3 Keys

<a id="req-5-8"></a>**REQ-5-8.** A key MUST be a P-256 public key encoded as a Multikey: the bytes `0x80 0x24` (the unsigned-varint encoding of multicodec `0x1200`), followed by the 33-byte compressed point, encoded as base58btc with the multibase prefix `z`.

<a id="req-5-9"></a>**REQ-5-9.** The compressed point MUST decode to a point on the P-256 curve.

### 5.4 Proofs

<a id="req-5-10"></a>**REQ-5-10.** An operation's `proof` member MUST be an array of Data Integrity proofs, sorted by `verificationMethod` in code-point order. Each proof secures the operation independently.

<a id="req-5-11"></a>**REQ-5-11.** Each proof MUST contain exactly these members:

| Member | Value |
|---|---|
| `type` | `"DataIntegrityProof"` |
| `cryptosuite` | `"ecdsa-jcs-2019"` |
| `verificationMethod` | `did:key:<key>#<key>` |
| `proofPurpose` | `"capabilityInvocation"` |
| `proofValue` | the signature |

<a id="req-5-12"></a>**REQ-5-12.** Proofs MUST be created and verified with the `ecdsa-jcs-2019` cryptosuite (W3C Data Integrity ECDSA Cryptosuites v1.0), as follows:

1. The secured document is the operation with the `proof` and `attestation` members removed.
2. The proof configuration is the proof with the `proofValue` member removed.
3. The signed data is the SHA-256 digest of the canonical proof configuration, followed by the SHA-256 digest of the canonical secured document.
4. The signature is an ECDSA P-256 signature over the signed data, using SHA-256.
5. `proofValue` is the 64-byte signature value, R followed by S, encoded as base58btc with the multibase prefix `z`.

<a id="req-5-13"></a>**REQ-5-13.** The signature MUST use the low-S form. A verifier MUST reject a signature whose S value is greater than half the order of the P-256 curve.

<a id="req-5-14"></a>**REQ-5-14.** The signer of a proof is the key in its `verificationMethod`. A proof is valid if its signature verifies with that key.

<a id="req-5-15"></a>**REQ-5-15.** An operation MUST NOT contain two proofs from the same key.

<a id="req-5-16"></a>**REQ-5-16.** A key approves an operation if the operation contains a valid proof from that key. A guardian or successor approves an operation if at least one key in its entry approves it.

## 6. State

<a id="req-6-1"></a>**REQ-6-1.** The state of an identity consists of:

| Field | Value |
|---|---|
| `keys` | a list of 1 to 8 distinct keys |
| `guardians` | a list of 0 to 32 entries with distinct DIDs |
| `successor` | an entry, or `null` |
| `wards` | a list of ward records with distinct DIDs |
| `policy` | a policy object (Section 6.3) |
| `services` | a list of 0 to 32 services with distinct `id` values |
| `alsoKnownAs` | a list of 0 to 32 distinct URIs (RFC 3986) |
| `deactivated` | `true` or `false` |
| `critical` | a list of distinct extension names (Section 7.11) |

<a id="req-6-2"></a>**REQ-6-2.** An entry MUST contain exactly the members `did`, `anchor`, `keys` and `consent`. `did` is a did:guardian DID. `anchor` is the anchor of that DID's log. `keys` is a list of 1 to 8 distinct keys. `consent` is the operation hash of an `acceptWard` in that DID's log.

<a id="req-6-3"></a>**REQ-6-3.** A key MUST NOT appear more than once across `keys`, the `keys` of every entry in `guardians`, and the `keys` of `successor`.

<a id="req-6-4"></a>**REQ-6-4.** A ward record MUST contain exactly the members `did` and `anchor`. `did` is a did:guardian DID. `anchor` is the anchor of that DID's log.

<a id="req-6-5"></a>**REQ-6-5.** The DID of an identity MUST NOT appear in its `guardians`, its `successor` or its `wards`. The DID of `successor` MUST NOT appear in `guardians`.

<a id="req-6-6"></a>**REQ-6-6.** A service MUST contain exactly the members `id`, `type` and `serviceEndpoint`. `id` MUST be `#` followed by a DID URL fragment. `type` MUST be a string. `serviceEndpoint` MUST be a URI (RFC 3986).

<a id="req-6-7"></a>**REQ-6-7.** After each operation, the state MUST conform to REQ-6-1 through REQ-6-6 and Section 6.3.

### 6.1 Required approvals

<a id="req-6-8"></a>**REQ-6-8.** Let N be the number of guardians in the state before an operation. Let E be the number of guardians eligible to approve it. E equals N − 1 for `removeGuardian`, and N for every other operation. For a setting value v, the number of guardian approvals required is computed as follows:

1. Start with a base value: 1 for `"any"`, floor(E / 2) + 1 for `"majority"`, E for `"all"`, and the smaller of k and E for an integer k.
2. If v is not `"any"` and N is at least 2, raise the value to at least 2.
3. For `membership` and for the `threshold` of `deactivation`, raise the value to at least floor(N / 2) + 1.

<a id="req-6-9"></a>**REQ-6-9.** A clause of REQ-7-6 that requires guardians per a setting cannot be met if E is 0 or if the required number is greater than E.

### 6.2 Orphaning

<a id="req-6-10"></a>**REQ-6-10.** When a `removeGuardian` leaves `guardians` empty, the state changes according to `policy.orphan`:

| `orphan` | Change |
|---|---|
| `"deactivate"` | `deactivated` becomes `true` |
| `"independent"` | no change |
| `"successor"` | the `successor` entry becomes the only entry in `guardians`, `successor` becomes `null`, and `orphan` becomes `"deactivate"` |

### 6.3 Policy

<a id="req-6-11"></a>**REQ-6-11.** A policy object MAY contain these members. A member that is absent takes its default value.

| Member | Governs | Allowed values | Default |
|---|---|---|---|
| `recovery` | guardian approval of `update`, `acceptWard` and `releaseWard` | `"any"`, `"majority"`, `"all"`, integer k | `"majority"` |
| `membership` | guardian approval of `addGuardian` and `setPolicy` | `"majority"`, `"all"`, integer k | `"majority"` |
| `removal` | guardian approval of `removeGuardian` | `"any"`, `"majority"`, `"all"`, integer k | `"majority"` |
| `deactivation` | approval of `deactivate` | a deactivation object (REQ-6-12) | `{"by": "both", "threshold": "majority"}` |
| `orphan` | the change when the last guardian is removed (REQ-6-10) | `"deactivate"`, `"independent"`, `"successor"` | `"deactivate"` |
| `maxWards` | the largest allowed size of `wards` | integer k ≥ 1 | no limit |

<a id="req-6-12"></a>**REQ-6-12.** A deactivation object MUST contain exactly the members `by` and `threshold`. `by` MUST be one of `"self"`, `"guardians"`, `"either"` or `"both"`. `threshold` MUST be `"majority"`, `"all"` or an integer k.

<a id="req-6-13"></a>**REQ-6-13.** An integer k in `recovery`, `membership`, `removal` or `threshold` MUST be between 1 and 32.

<a id="req-6-14"></a>**REQ-6-14.** `orphan` MUST be `"successor"` if `successor` is an entry, and MUST NOT be `"successor"` if `successor` is `null`.

<a id="req-6-15"></a>**REQ-6-15.** If `maxWards` is present, `wards` MUST NOT contain more than `maxWards` records.

## 7. Operations

### 7.1 Common members

<a id="req-7-1"></a>**REQ-7-1.** Every operation MUST contain the members `type`, `prev` and `proof`.

<a id="req-7-2"></a>**REQ-7-2.** `type` MUST be one of `create`, `update`, `addGuardian`, `updateGuardian`, `removeGuardian`, `setPolicy`, `acceptWard`, `releaseWard` or `deactivate`.

<a id="req-7-3"></a>**REQ-7-3.** The first operation of a log MUST be a `create`. A later operation MUST NOT be a `create`.

<a id="req-7-4"></a>**REQ-7-4.** In a `create`, `prev` MUST be `null`. In every other operation, `prev` MUST be the operation hash of the preceding operation.

### 7.2 Approval rules

In the following rules:
- "one current key" means approval by at least one key in `keys` in the state before the operation;
- "guardians per s" means approvals from the number of current guardians that REQ-6-8 requires for setting s;
- "every key in X" means approval by every key in the list X in the operation.

For a `create`, the state before the operation is empty and N is 0.

<a id="req-7-5"></a>**REQ-7-5.** Every proof on an operation MUST come from one of these keys: a key in `keys`, in an entry in `guardians`, or in `successor`, in the state before the operation; or a key in a list of keys in the operation.

<a id="req-7-6"></a>**REQ-7-6.** An operation MUST have the approvals that the following table requires.

| Type | Required approvals |
|---|---|
| `create` | every key in `keys`; every key in each entry in `guardians`; every key in `successor`, if it is an entry |
| `update` | every key in `keys`; and either one current key or guardians per `recovery` |
| `addGuardian` | every key in `entry`; one current key; and guardians per `membership`, if N > 0 |
| `updateGuardian` | every key in `keys`; and either a key in the named entry, or one current key together with one guardian other than the named one |
| `removeGuardian` | one of: the removed guardian, if N ≥ 2; guardians per `removal`, from the guardians other than the removed one; one current key, if `evidence` is present; or one current key together with the successor, if N = 1 and `successor` is an entry |
| `setPolicy` | one current key; guardians per `membership`, if N > 0; and every key in `successor`, if it is an entry that differs from the current `successor` |
| `acceptWard` | one current key, or guardians per `recovery` |
| `releaseWard` | one current key, or guardians per `recovery` |
| `deactivate` | if N = 0, one current key; otherwise, as `policy.deactivation.by` specifies: `self`, one current key; `guardians`, guardians per `deactivation.threshold`; `either`, one of the two; `both`, both |

### 7.3 create

<a id="req-7-7"></a>**REQ-7-7.** A `create` MUST contain the members `type`, `did`, `keys`, `guardians`, `successor`, `policy`, `services`, `alsoKnownAs`, `prev` and `proof`. The `create` of an identity other than a root identity MUST contain the member `attestation`. The `create` of a root identity MUST NOT contain it.

<a id="req-7-8"></a>**REQ-7-8.** `did` is the DID of the identity. `keys`, `guardians`, `successor`, `policy`, `services` and `alsoKnownAs` set the initial state. `wards` is empty and `deactivated` is `false`.

<a id="req-7-9"></a>**REQ-7-9.** `attestation` MUST be a Data Integrity proof as in REQ-5-11, except that its `cryptosuite` may be any string and its `verificationMethod` is `did:guardian:<domain>?versionId=<version>#key-<n>`, where `<domain>` is the domain of `did`, `<version>` is a version of the root identity's log, and `<n>` is a decimal integer without leading zeros. It secures the same document as the other proofs (REQ-5-12). Section 11 defines how it is verified.

### 7.4 update

<a id="req-7-10"></a>**REQ-7-10.** An `update` MUST contain the members `type`, `keys`, `services`, `alsoKnownAs`, `prev` and `proof`.

<a id="req-7-11"></a>**REQ-7-11.** `update` replaces `keys`, `services` and `alsoKnownAs` in the state.

### 7.5 addGuardian

<a id="req-7-12"></a>**REQ-7-12.** An `addGuardian` MUST contain the members `type`, `entry`, `prev` and `proof`. `entry` is an entry (REQ-6-2).

<a id="req-7-13"></a>**REQ-7-13.** The DID of `entry` MUST NOT already be a guardian.

<a id="req-7-14"></a>**REQ-7-14.** `addGuardian` appends `entry` to `guardians`.

### 7.6 updateGuardian

<a id="req-7-15"></a>**REQ-7-15.** An `updateGuardian` MUST contain the members `type`, `guardian`, `keys`, `prev` and `proof`. `guardian` is the DID of a current guardian or of the successor.

<a id="req-7-16"></a>**REQ-7-16.** `updateGuardian` replaces the `keys` of the entry for `guardian`.

### 7.7 removeGuardian

<a id="req-7-17"></a>**REQ-7-17.** A `removeGuardian` MUST contain the members `type`, `guardian`, `prev` and `proof`. It MAY contain the member `evidence`. `guardian` is the DID of a current guardian.

<a id="req-7-18"></a>**REQ-7-18.** If present, `evidence` is the operation hash of a `deactivate`, or of a `releaseWard` whose `ward` is this identity, in the log of `guardian`.

<a id="req-7-19"></a>**REQ-7-19.** `removeGuardian` removes the entry for `guardian`, and then applies REQ-6-10.

### 7.8 setPolicy

<a id="req-7-20"></a>**REQ-7-20.** A `setPolicy` MUST contain the members `type`, `policy`, `successor`, `prev` and `proof`. `successor` is an entry or `null`.

<a id="req-7-21"></a>**REQ-7-21.** `setPolicy` replaces `policy` and `successor` in the state.

### 7.9 acceptWard and releaseWard

<a id="req-7-22"></a>**REQ-7-22.** A `acceptWard` MUST contain the members `type`, `ward`, `prev` and `proof`. `ward` is a ward record (REQ-6-4).

<a id="req-7-23"></a>**REQ-7-23.** The DID of `ward` MUST NOT already be in `wards`.

<a id="req-7-24"></a>**REQ-7-24.** `acceptWard` appends `ward` to `wards`. It records that the identity consents to be a guardian or successor of that ward.

<a id="req-7-25"></a>**REQ-7-25.** An `releaseWard` MUST contain the members `type`, `ward`, `prev` and `proof`. `ward` is the DID of a record in `wards`.

<a id="req-7-26"></a>**REQ-7-26.** `releaseWard` removes the record for `ward` from `wards`. It records that the identity withdraws its consent.

### 7.10 deactivate

<a id="req-7-27"></a>**REQ-7-27.** A `deactivate` MUST contain the members `type`, `prev` and `proof`.

<a id="req-7-28"></a>**REQ-7-28.** `deactivate` sets `deactivated` to `true`.

### 7.11 Extensions

<a id="req-7-29"></a>**REQ-7-29.** `extensions` is an object. Each member name is an extension name, and each value is defined by that extension. An extension name MUST be an absolute URI.

<a id="req-7-30"></a>**REQ-7-30.** `critical` is a non-empty list of distinct extension names. Only a `create` or a `setPolicy` MAY contain `critical`. Each name in `critical` MUST be a member of the `extensions` of the operation's `policy`. The configuration of a critical extension is held only in `policy.extensions`.

<a id="req-7-31"></a>**REQ-7-31.** An extension affects whether an operation is valid only while its name is in the state's `critical`.

<a id="req-7-32"></a>**REQ-7-32.** An operation adds each name in its `critical` to the state's `critical`, if it is not already there. A name in the state's `critical` remains there for every later operation of the log.

<a id="req-7-33"></a>**REQ-7-33.** An extension MAY add requirements to operations. An extension MUST NOT remove or weaken a requirement of this specification.

<a id="req-7-34"></a>**REQ-7-34.** A verifier MUST ignore every extension whose name is not in the state's `critical`, whether or not it implements that extension. Ignored extensions remain part of the operation hash and the secured document. The contents of an extension value are defined by the extension, not by REQ-5-3.

<a id="req-7-35"></a>**REQ-7-35.** An extension defines how its configuration changes. A change to an extension's configuration requires the approvals that this specification requires for the operation that makes it.

## 8. Verification

<a id="req-8-1"></a>**REQ-8-1.** A verifier MUST verify the log of a DID by the following steps, and report one of three results. An operation is **unsupported** if the state's `critical` before it, or the operation's `critical`, names an extension that the verifier does not implement, or if its `type`, or the `cryptosuite` of one of its proofs, has a value that the verifier does not implement. The verifier processes operations in order and stops at the first operation that is unsupported or that fails a step. Within one operation, the unsupported conditions are checked before the steps. It reports **unsupported** or **invalid** for that operation, or **valid** if no operation stops it. A verifier MUST NOT treat an unsupported log as valid.

1. The log is a non-empty array of operations.
2. The first operation is a `create` whose `did` equals the DID.
3. Each later operation's `prev` equals the operation hash of the operation before it.
4. No operation follows a state in which `deactivated` is `true`.
5. For each operation in order:
   1. The operation conforms to Sections 5 and 7.
   2. Every proof is valid (REQ-5-14) and comes from a permitted key (REQ-7-5).
   3. The approvals meet the rule in REQ-7-6, evaluated against the state before the operation.
   4. Apply the operation to the state, and check that the result conforms to Section 6.

<a id="req-8-2"></a>**REQ-8-2.** Verification of a log depends only on that log. It does not depend on other logs or on the time of verification.

## 9. DID document

<a id="req-9-1"></a>**REQ-9-1.** The DID document of an identity is derived from its state after the last operation of its log.

<a id="req-9-2"></a>**REQ-9-2.** If the state is not deactivated, the DID document MUST contain exactly:

| Member | Value |
|---|---|
| `@context` | `["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]` |
| `id` | the DID |
| `verificationMethod` | for each key at index n of `keys`: `{"id": "<did>#key-<n>", "type": "Multikey", "controller": "<did>", "publicKeyMultibase": "<key>"}` |
| `authentication`, `assertionMethod`, `capabilityInvocation` | the `id` of every verification method |
| `service` | the services, each with its `id` prefixed by the DID; an empty list if there are none |
| `alsoKnownAs` | the `alsoKnownAs` list, if it is not empty |

<a id="req-9-3"></a>**REQ-9-3.** If the state is deactivated, the DID document MUST contain exactly `@context` and `id`.

<a id="req-9-4"></a>**REQ-9-4.** DID document metadata MUST include `versionId`, the version of the log, and `anchor`, the anchor of the log. If the state is deactivated, DID document metadata MUST include `"deactivated": true`.

<a id="req-9-5"></a>**REQ-9-5.** Resolving a DID URL with the parameter `versionId=<version>` yields the DID document derived from the state after the operation whose operation hash is `<version>`. Only the log up to and including that operation needs to verify.

## 10. Registrar

### 10.1 Resources

<a id="req-10-1"></a>**REQ-10-1.** The registrar for a domain MUST serve these resources over HTTPS at `https://<domain>/.well-known/guardian/<segment>`, where `<segment>` is the path segment of the identity (REQ-4-5):

| Method and path | Response |
|---|---|
| `GET .../<segment>/log` | the log, as a JSON array in log order |
| `GET .../<segment>` | the DID document |
| `POST .../<segment>/operations` | accepts one operation as the request body |

<a id="req-10-2"></a>**REQ-10-2.** A `GET` request MUST NOT change any state.

<a id="req-10-3"></a>**REQ-10-3.** A registrar MUST NOT serve two logs for one DID where neither is a prefix of the other.

<a id="req-10-4"></a>**REQ-10-4.** A registrar MUST respond to a rejected operation with HTTP status 400 and a JSON object with an `error` member that describes the reason.

### 10.2 Accepting operations

<a id="req-10-5"></a>**REQ-10-5.** A registrar MUST accept an operation only if all of these hold:

1. Its `prev` equals the version of the log, or it is a `create` for a path segment that has no log.
2. The log, with the operation appended, is valid (Section 8). An unsupported result is a rejection.
3. Every check in REQ-10-7 that applies to the operation holds.

<a id="req-10-6"></a>**REQ-10-6.** An entry has standing for an identity if the current log of the entry's `did` verifies and, in that log:

1. the anchor equals the entry's `anchor`;
2. the state is not deactivated;
3. the state's `keys` equal the entry's `keys`;
4. `consent` is an `acceptWard` whose `ward` names the identity's DID and anchor;
5. the state's `wards` contains that record.

<a id="req-10-7"></a>**REQ-10-7.** Before accepting an operation, a registrar MUST fetch the current log of each other identity that the operation involves, and check:

| Case | Check |
|---|---|
| an operation adds or replaces an entry | the new entry has standing |
| a guardian or successor approves an operation | its entry has standing, except for item 3 when the operation is an `updateGuardian` for that guardian or successor |
| an `updateGuardian` | the new `keys` equal the `keys` in the current state of `guardian` |
| a `removeGuardian` with `evidence` | in the log of `guardian`, the anchor equals the entry's `anchor`; `evidence` is a `deactivate`, or a `releaseWard` whose `ward` is this identity, and it follows the entry's `consent`; and the entry does not have standing because of item 2 or item 5 of REQ-10-6 |
| a `removeGuardian` that promotes the successor (REQ-6-10) | the successor's entry has standing |
| an `acceptWard` | if the ward's DID has a log, the `ward` record names its anchor |

<a id="req-10-8"></a>**REQ-10-8.** A registrar MUST accept at most one operation for each value of `prev`.

<a id="req-10-9"></a>**REQ-10-9.** For a `create`, the registrar MUST also require that the DID's domain is its domain and that the name is unused (REQ-10-12). It MUST add the `attestation`, using a key of its root identity and the current version of the root identity's log, before it applies REQ-10-5.

<a id="req-10-10"></a>**REQ-10-10.** A registrar MUST create its root identity before it accepts any other `create`.

<a id="req-10-11"></a>**REQ-10-11.** A registrar MUST NOT remove or alter an accepted operation. A registrar MUST continue to serve the log of a deactivated identity.

<a id="req-10-12"></a>**REQ-10-12.** A name, once used, MUST NOT be used for another identity.

### 10.3 Held keys

<a id="req-10-13"></a>**REQ-10-13.** A registrar that holds a private key for an identity MUST create a proof with that key only in response to a request authenticated as that identity.

<a id="req-10-14"></a>**REQ-10-14.** Apart from the `attestation`, one request MUST NOT cause a registrar to create proofs for more than one identity.

## 11. Resolution

<a id="req-11-1"></a>**REQ-11-1.** To resolve a DID, a resolver MUST:

1. fetch the log from the registrar of the DID's domain;
2. verify the log (Section 8);
3. verify the `attestation` of its `create`, unless the DID is a root identity (REQ-11-2);
4. derive the DID document (Section 9).

<a id="req-11-2"></a>**REQ-11-2.** A resolver that does not implement the `cryptosuite` of an `attestation` MUST report the attestation as unsupported. Otherwise, an `attestation` is valid if the log of the root identity of the DID's domain contains the operation named by `versionId`, that log up to and including that operation verifies, the state after that operation is not deactivated and has a key at index `<n>`, and the signature verifies with that key.

<a id="req-11-3"></a>**REQ-11-3.** A resolver SHOULD record the anchor and the version of each log it fetches.

<a id="req-11-4"></a>**REQ-11-4.** If a later fetch of a log yields a different anchor, the resolver MUST report that the DID refers to a different identity. If it yields a log that does not contain the recorded version, the resolver MUST report that the log was rolled back or forked.

<a id="req-11-5"></a>**REQ-11-5.** For each entry in `guardians` and `successor`, a resolver MAY fetch the log of the entry's `did` and report the first result in this table whose condition holds:

| Result | Condition |
|---|---|
| unavailable | the log cannot be fetched or does not verify |
| different identity | the log's anchor differs from the entry's `anchor` |
| deactivated | the state is deactivated |
| withdrawn | `consent` is not an `acceptWard` that names this identity's DID and anchor, or `wards` does not contain that record |
| keys out of date | the state's `keys` differ from the entry's `keys` |
| mutual | none of the above |

<a id="req-11-6"></a>**REQ-11-6.** For each record in `wards`, a resolver MAY fetch the log of the record's `did` and report the first result whose condition holds: unavailable, if the log cannot be fetched or does not verify; different identity, if its anchor differs from the record's `anchor`; guardian, if its `guardians` has an entry for this identity; successor, if its `successor` is an entry for this identity; otherwise, not related.

<a id="req-11-7"></a>**REQ-11-7.** A resolver MUST NOT present a guardianship as mutual unless REQ-11-5 reports mutual or keys out of date.

<a id="req-11-8"></a>**REQ-11-8.** A resolver MAY verify a log that another party presents. A presented log is current only as of its version.

## 12. Security considerations

This section is non-normative.

**Order of operations.** Every proof is verifiable from its log, but the registrar decides the order in which operations are accepted. A verifier relies on the registrar for that order, as with did:web and did:plc.

**Checks at acceptance.** The checks in REQ-10-7 compare an operation with other logs at the time of acceptance. A verifier does not repeat them. A resolver can compare current logs (REQ-11-5), but cannot tell what another log contained at the time of acceptance. Removal with `evidence` depends on these checks; it also requires one current key, so a registrar alone cannot use it.

**Joining and leaving.** A guardian records `acceptWard` before the ward adds it, because REQ-10-7 requires the consent to exist. A guardian that leaves SHOULD remove itself from the ward before it records `releaseWard`. A guardian that records `releaseWard` first, or that deactivates, loses standing, so a registrar rejects its approvals for that ward (REQ-10-7), and the ward can remove it with `evidence`. Evidence counts only if it follows the guardian's current consent, so a `releaseWard` from an earlier period of guardianship cannot be reused.

**Guardian keys.** A ward's entry holds a copy of the guardian's keys. When a guardian replaces its keys, it updates each of its entries with `updateGuardian`; its `wards` lists them. Until then, a registrar rejects approvals made with the old keys (REQ-10-7). A successor's entry is updated with `updateGuardian` or `setPolicy`. A resolver reports entries whose keys are out of date (REQ-11-5).

**Stolen guardian key.** A party that holds a guardian's current key can act as that guardian in every ward until each ward removes the entry or the guardian replaces its keys.

**Lost guardian key.** A guardian that loses its key recovers its identity through its guardians. Each ward then updates the entry with one current key and one other guardian (REQ-7-6). A ward whose only guardian lost its key cannot update the entry; its successor, if any, can replace that guardian.

**Sole guardian.** A sole guardian that leaves SHOULD first approve the addition of a replacement, then remove itself. A sole guardian that dies or withdraws without a replacement cannot be replaced by the ward's keys alone, because the ward cannot add a guardian, name a successor or change `orphan` without its guardians. The ward can then only remove the guardian with `evidence`, which applies `orphan`. A successor refreshes its entry with `updateGuardian`.

**Mutual guardians.** If two identities are each other's only guardian, one stolen key gives control of both: the holder replaces the keys of one identity, then uses it as guardian to replace the keys of the other. Give each identity at least one guardian outside such a pair.

**Stolen key.** A party that holds a stolen key can act as the identity until the guardians replace the key. Those operations remain in the log.

**Unilateral settings.** `recovery: "any"` lets one guardian replace the keys. `removal: "any"` lets one guardian remove another; with two guardians, either can remove the other. `deactivation.by: "self"` or `"either"` lets anyone who holds a key end the identity. Choose these settings deliberately.

**Two guardians.** With two guardians and `removal` other than `"any"`, neither guardian can remove the other. Use three or more guardians, or set `removal: "any"`.

**Orphaning.** Every way to remove the last guardian requires one current key. Under the default `orphan: "deactivate"`, the identity is then deactivated, and deactivation is permanent. To lower the risk, use guardians on more than one domain, or name a successor.

**Unavailable guardians.** A registrar cannot check the standing of a guardian whose log cannot be fetched, so it cannot accept that guardian's approvals or changes to its entry, or a removal with `evidence`. If no guardian can approve, operations that need guardians cannot be accepted. A successor can act only when there is one guardian.

**Successor.** A successor and one current key can replace a sole guardian, and the successor then becomes the guardian. Name only a successor you trust with that power.

**One-sided records.** Any identity can record `acceptWard` for any ward. A guardianship is mutual only when REQ-11-5 reports it.

**Unsupported operations.** A registrar, or a party that presents a log, can append an operation with an unknown `type` or `cryptosuite`. A verifier then reports the log as unsupported. This has the same effect as withholding the log, and resolvers detect it by the recorded version (REQ-11-4).

**Forks.** Any party that holds the keys can sign two different operations with the same `prev`. Any party can also remove an unneeded proof from an operation, which produces a different operation hash. A registrar accepts only one operation for each `prev` (REQ-10-8). Resolvers detect a fork by the recorded version (REQ-11-4).

**Anchor.** The anchor does not cover the initial `guardians` and `successor`. Two `create` operations that differ only in those members have the same anchor; a registrar accepts one of them.

**Extensions.** A verifier that does not implement a critical extension reports the log as unsupported, never valid. An extension that is not listed in `critical` has no effect on validity for any verifier, so an extension that changes who may approve an operation must be made critical. Only `create` and `setPolicy` can make an extension critical, so adding one requires the same approvals as a policy change. A critical extension cannot be removed from a log, so every later verifier must implement it.

**Hostile registrar.** A registrar cannot forge proofs. It can refuse operations, serve an outdated or forged log to a resolver that has not seen the identity before, or skip the checks in REQ-10-7. Resolvers detect a replaced, rolled-back or forked log by its anchor and recorded version (REQ-11-4). A registrar that serves a forged log for a guardian on its domain can mislead a ward that adds that guardian; the ward detects this if it knows the guardian's anchor. A registrar that skips the checks in REQ-10-7 lets a party with one current key remove guardians with false `evidence`, and lets retired or withdrawn guardian keys approve operations.

**Root identity.** The root identity's key attests every `create` on its domain. A party with that key, or with an old root key, can attest a forged `create` for an unused name. Recorded anchors protect identities that a resolver has seen before.

**Domain transfer.** A new owner of a domain controls its registrar. The new owner cannot produce logs that match recorded anchors.

**Registrar-held keys.** A registrar that holds an identity's key can create proofs as that identity. REQ-10-13 and REQ-10-14 limit when it may do so, but no other party can check that limit.

**Checking a registrar.** Registrar requirements fall into three groups:

| Group | Who can check | Requirements |
|---|---|---|
| Provable from logs | anyone, by fetching and verifying logs | REQ-10-5 (items 1 and 2), REQ-10-11, REQ-10-12 |
| Testable | an operator, against a test deployment | REQ-10-1, REQ-10-2, REQ-10-4, REQ-10-8, REQ-10-9, REQ-10-10 |
| Trusted | no other party | REQ-10-3, REQ-10-7, REQ-10-13, REQ-10-14 |

## 13. Privacy considerations

This section is non-normative.

Logs are public and permanent. Every key, guardian relationship, ward, policy, service and alias that an identity has ever had is visible to anyone. A guardian's `wards` lists every identity it guards. Do not put personal data in names, services or `alsoKnownAs`.

## Appendix A. Examples

This appendix is non-normative. Hashes, keys and signatures are shortened with `…`, and proofs are abbreviated to their `verificationMethod`.

Bob agrees to guard Alice. Alice's client computes the anchor of her `create`, which does not depend on her guardians (REQ-5-7). Bob records `acceptWard` in his log:

```json
{
  "type": "acceptWard",
  "ward": {"did": "did:guardian:acme.com:alice", "anchor": "zQmAliceAnchor…"},
  "prev": "zQmBob1…",
  "proof": [{"verificationMethod": "did:key:zDnaeBob…#zDnaeBob…", "…": "…"}]
}
```

Bob's `acceptWard` has operation hash `zQmBobAccept…`. Alice's `create` names Bob as a guardian:

```json
{
  "type": "create",
  "did": "did:guardian:acme.com:alice",
  "keys": ["zDnaeAlice…"],
  "guardians": [
    {
      "did": "did:guardian:acme.com:bob",
      "anchor": "zQmBobAnchor…",
      "keys": ["zDnaeBob…"],
      "consent": "zQmBobAccept…"
    }
  ],
  "successor": null,
  "policy": {},
  "services": [],
  "alsoKnownAs": [],
  "prev": null,
  "proof": [
    {"verificationMethod": "did:key:zDnaeAlice…#zDnaeAlice…", "…": "…"},
    {"verificationMethod": "did:key:zDnaeBob…#zDnaeBob…", "…": "…"}
  ],
  "attestation": {"verificationMethod": "did:guardian:acme.com?versionId=zQmRoot…#key-0", "…": "…"}
}
```

Bob replaces the key in his log, then updates his entry in Alice's log. In this example, `zDnaeBob…` sorts before `zDnaeBobNew…`; real keys sort by their full encoded values (REQ-5-10):

```json
{
  "type": "updateGuardian",
  "guardian": "did:guardian:acme.com:bob",
  "keys": ["zDnaeBobNew…"],
  "prev": "zQmAliceCreate…",
  "proof": [
    {"verificationMethod": "did:key:zDnaeBob…#zDnaeBob…", "…": "…"},
    {"verificationMethod": "did:key:zDnaeBobNew…#zDnaeBobNew…", "…": "…"}
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

A sole guardian is removed with `evidence` and one current key, or by the successor and one current key. `orphan` then applies.

## Changelog

- **v0.2.0** (2026-10-24, current):
  - **2026-11-22**: REQ-5-2 now constrains a number's value, not how it is written. A standard JSON parser cannot distinguish `1` from `1.0` after parsing, so the earlier "written without a fraction or an exponent" wording checked nothing a conforming implementation could actually observe.
  - **2026-11-22**: Replaced the specification again, after six rounds of independent clean-room verification against the previous replacement found a critical hole (guardians could not be required to approve anything when zero were eligible, REQ-6-9) and about 25 smaller gaps. Guardian and successor relationships now use snapshot entries (`{did, anchor, keys, consent}`); every proof is a `did:key` reference, so verifying a log depends only on that log (REQ-8-2) with no cross-log recursion or cycle rule. The operation hash now covers the complete operation including its proofs; only the anchor excludes `proof`, `attestation`, `guardians` and `successor`. The registrar's attestation moved to its own `attestation` member on `create`, verified during resolution (Section 11), not during verification (Section 8). Added `acceptWard`/`releaseWard` (a guardian records its own consent, and the relationship is checked for mutuality at resolution, never affecting validity), `updateGuardian` (refreshing a stale entry's keys), and orphan handling (`policy.orphan`: deactivate, independent or successor). Added an extension mechanism (Section 7.11) with a three-way valid/invalid/unsupported verification result. Removed the word "sovereign" throughout; the orphan value is `"independent"`.
  - **2026-11-22**: Replaced the specification. Operations are `create`, `update`, `addGuardian`, `removeGuardian`, `setPolicy`, and `deactivate`. Verification depends only on logs, never on time. Removed nullification, the recovery window, receipts, the signed log head, and verification levels L0 through L3. Removed `creator`, `on_orphan`, and `guardian_transfer`. Entries dated before this one describe the removed design.
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
