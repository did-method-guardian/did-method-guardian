# Contributing

Thanks for taking a look at `did:guardian`. This is a young, early-stage project — issues, discussion, and PRs are all welcome, but please open an issue to discuss anything non-trivial before investing time in a PR, especially anything touching the method spec itself (`packages/lib`) or the operation semantics.

## Repo layout

- `packages/lib` — the reference crypto/operations library (Web Crypto-based, portable across Workers/Node/browser). This is the actual implementation of the spec: operation validation, guardian threshold logic, signature verification, DID resolution.
- `packages/server` — the reference registrar: a self-hostable Cloudflare Worker with an OIDC/OAuth provider, account dashboard, admin console, and the cross-registrar signature relay.
- `interop_tests` — shared operation-log fixtures, for verifying an independent implementation against this one.
- `website` — the spec, docs, and guardianspec.org site source (HyperTemplates).

## Building and testing

```bash
# from the repo root
npm install

# packages/lib: build + full spec-conformance test suite
cd packages/lib
npm run build
npm test

# packages/server: typecheck + its own test suite
cd packages/server
npx tsc --noEmit
npm test
```

Both suites need to pass before a PR will be considered. If you're changing anything in `packages/lib`, add or update a test referencing the relevant `REQ-*` identifier from the spec (see `website/content/docs/did-guardian-spec-v0.2.0/index.md`) — that's the convention the existing suite follows, and it's how a spec requirement and its test stay traceable to each other.

`packages/server` is a Cloudflare Worker; `npx wrangler dev --config wrangler.jsonc` runs it locally against the generic template config. The live reference deployments (`zzmq.dev`, `guardianspec.org`) are not something a PR should need to touch directly.

## Spec changes

The spec is deliberately kept as three separate documents — an explainer, a formal RFC-2119 method spec, and a registrar API spec — under `website/content/docs/`. If a change affects behavior, it needs to land in the formal spec, not just the explainer, and it needs a corresponding test in `packages/lib`. Changes that would break an already-issued DID's resolution or an existing operation log are treated as breaking changes, not bug fixes — flag these explicitly in the PR description.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue. Anything that looks like it could let an operation be forged, a guardian threshold be bypassed, or an identity be impersonated: see [SECURITY.md](SECURITY.md) instead — please don't file those as public issues.
