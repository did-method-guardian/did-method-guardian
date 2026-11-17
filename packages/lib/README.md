# @did-guardian/lib

Reference implementation of the [`did:guardian`](https://guardianspec.org/docs/) method: operation log replay, signature verification, threshold rules, key crypto, and DID document rendering. Platform-agnostic (Web Crypto, no Node-specific APIs) -- runs in Node, a browser, or a Cloudflare Worker.

`did:guardian` is a distributed identity built around guardianship: a configurable group of other identities that can recover, revoke, transfer, or act on behalf of an identity, under rules its owner sets in advance. See the [guide](https://guardianspec.org/docs/) for an introduction and the [formal specification](https://guardianspec.org/docs/did-guardian-spec-v0.2.0/) for the normative method definition.

## Install

```bash
npm install @did-guardian/lib
```

## What's in this package

- `replay(did, log)` / `toDidDocument(state)` -- reconstruct current state from an operation log, and render it as an ordinary [W3C DID Core](https://www.w3.org/TR/did-core/) document.
- `generateKeypair()` / `signPayload()` / `verifyPayload()` -- P-256 ECDSA key operations (`src/crypto.ts`).
- `spkiToMultikey()` -- converts this library's internal key format into a proper [Multikey](https://www.w3.org/TR/vc-data-integrity/#multikey) multibase string, exactly what `toDidDocument` uses to render `publicKeyMultibase`.
- Threshold and guardian-policy verification rules (`src/rules.ts`) matching the formal spec's §5 and §7.
- `schemas/` -- JSON Schemas for `GuardianPolicy` and every operation type, matching this package's own `src/types.ts`.

This package implements the method itself. For a runnable, self-hostable server built on top of it (OIDC provider, account dashboard, admin console), see [`@did-guardian/server`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/server) in the same repository.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE). Downstream projects may choose either, or both, at their discretion.
