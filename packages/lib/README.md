# @did-guardian/lib

Reference implementation of the [`did:guardian`](https://guardianspec.org/docs/) method: operation log verification, registrar acceptance checks, resolution, and DID document rendering. Platform-agnostic (Web Crypto, no Node-specific APIs) -- runs in Node, a browser, or a Cloudflare Worker.

`did:guardian` is a distributed identity built around guardianship: a configurable group of other identities that can recover a lost key, approve membership changes, or deactivate an identity on its behalf, under rules its own policy sets in advance. See the [guide](https://guardianspec.org/docs/) for an introduction and the [formal specification](https://guardianspec.org/docs/did-guardian-spec-v1.0.0/) for the normative method definition.

## Install

```bash
npm install @did-guardian/lib
```

## What's in this package

- `verifyLog(did, log, implementedExtensions?)` -- §8 verification: checks a log entirely on its own terms (hash chain, proof signatures, approval thresholds), with no network calls and no other identity's log involved. Returns `"valid"`, `"invalid"`, or `"unsupported"` (an unrecognized operation type, cryptosuite, or critical extension).
- `resolve(did, log, resolveLog, implementedExtensions?, versionId?)` -- §11 resolution: runs `verifyLog`, then (for a non-root identity) verifies the `create`'s registrar attestation against the named root identity's own log, fetched through the `resolveLog` callback you supply. Returns the DID document and resolution metadata, or the same three-way result `verifyLog` does.
- `checkAcceptance(did, existingLog, candidate, resolveLog, implementedExtensions?)` -- §10.2: whether a registrar should accept a newly-submitted operation, including the cross-log standing checks (REQ-10-6/10-7) that only make sense at acceptance time, not during plain verification.
- `checkMutuality(did, anchor, entry, resolveLog)` / `checkWardReport(...)` -- REQ-11-5/11-6: whether a guardian or successor entry is still a genuine, current, mutual relationship, and the status of each of an identity's own wards.
- `checkPin(did, log, store)` / a `PinStore` interface (`src/pin.ts`) -- REQ-11-3/11-4: tracks the anchor and version last seen for a DID, to detect a resolver being served a different identity, a rollback, or a fork on a later fetch.
- `apply(did, stateBefore, op)` / `toDidDocument(did, state)` -- the lower-level primitives `verifyLog`/`resolve` are built from: apply one operation to a state, or render a state as an ordinary [W3C DID Core](https://www.w3.org/TR/did-core/) document. Most callers want `verifyLog`/`resolve` instead of these directly.
- `generateKeypair()` / `createProof()` / `createAttestation()` / `verifyProofSignature()` -- P-256 ECDSA keys and [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) proofs (`ecdsa-jcs-2019`), the signed envelope every operation carries (`src/crypto.ts`, `src/operations.ts`). Every public key this library produces or accepts is a [Multikey](https://www.w3.org/TR/cid-1.0/#Multikey) multibase string.
- Shape and approval-rule checks for every operation type and for `Policy` (`src/operations.ts`, `src/rules.ts`), matching the formal spec's §5 through §7.
- `schemas/` -- JSON Schemas for `Policy` and every operation type, matching this package's own `src/types.ts`.

This package implements the method itself. For a runnable, self-hostable server built on top of it (OIDC provider, account dashboard, admin console), see [`@did-guardian/server`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/server); for a command-line tool built on it instead (key management, registration, resolution/verification, guardianship), see [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) -- both in the same repository.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE). Downstream projects may choose either, or both, at their discretion.
