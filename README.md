# DID Guardian Method (did:guardian)

DID Guardian is a self-authenticating [DID](https://www.w3.org/TR/did-core/) method for any identity that may need an external party's custodial oversight -- key recovery, revocation, and transfer -- without that oversight ever amounting to impersonation. It generalizes guardianship (a human managing another human's identity, a human managing an autonomous agent's, an organization managing an account on its own behalf) as a single, cryptographically-enforced relationship: transferable, terminable, and governed by configurable, self-governing consensus thresholds rather than any one hardcoded rule.

An example DID is: `did:guardian:acme.com:alice`

The identifier is domain-first, deliberately isomorphic to `did:web`'s own convention (`did:web:<domain>:<path...>`) rather than the reverse-DNS order popularized elsewhere -- did:guardian is that same domain-first shape with at most one flat name segment, which keeps a did:guardian identifier and its equivalent `did:web:acme.com:alice` visually parallel, differing only in the method name. Control over an identity (a "ward") rests with its own ordered, tiered rotation keys: an operational tier the ward rotates itself, and a guardian tier that can recover or nullify the operational tier within a bounded recovery window -- directly adopting [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s own proven ordered-authority mechanism, extended with group guardianship (multiple guardians, configurable M-of-N consensus) that `did:plc` has no equivalent of.

This git repository contains a TypeScript reference implementation (`packages/lib`), a self-hostable registrar + OIDC provider + account dashboard (`packages/server`), a set of interoperability test fixtures (`interop_tests`), and the specification's own website (`website`).

## Motivation

Every identity method examined while designing this either coupled identity to infrastructure that can disappear, or had no native concept of one party holding custodial responsibility for another's keys without that amounting to full impersonation. `did:guardian` was built specifically because an increasing number of identities -- autonomous agents, accounts an organization holds on someone's behalf, a person's own accounts under a domain they don't fully control -- need recoverable, transferable, group-governable custodial oversight as a first-class protocol property, not a convention layered on top.

## How it works

See the [specification](website/content/docs/index.md), or the live copy at [guardianspec.org/docs](https://guardianspec.org/docs/).

## Self-hosting: the bare-domain root identity

Every deployment of `packages/server` auto-provisions one bare-domain identity (`did:guardian:<your-domain>`, e.g. `did:guardian:acme.com`) the first time anything resolves it -- it's never registered the way a named ward is, since there's exactly one per deployment and it belongs to whoever legitimately operates the domain, by construction. It attests every other ward's own genesis operation (the `registrar` field on `custodial_create`), and -- once given a login credential -- is otherwise a fully usable identity like any other: it can log in, rotate its own operational key, deactivate itself, and so on (everything except email forwarding, which needs a real local-part address this identity doesn't have).

A fresh deployment generates its own keypair for this identity automatically. An operator who wants to bring their own key material instead (migrating from somewhere, or managing it outside this registrar's own custodial encryption) sets both `ROOT_WARD_PUBLIC_KEY` and `ROOT_WARD_PRIVATE_KEY` via `wrangler secret put` -- both or neither.

**To actually log in as this identity**, set `ROOT_WARD_LOGIN_SECRET` (also via `wrangler secret put`) to a password of your choosing -- there's no registration flow to set one through otherwise. This takes effect the next time the root identity is accessed, whether that's its first creation on a brand-new deployment or a one-time lazy upgrade on one that's already running (no redeploy or migration needed beyond setting the secret). Sign in with the name field left as `_`, or your bare domain, or `@your-domain` -- all three mean the same thing.

See `packages/server/src/env.ts` for the complete list of environment variables this registrar reads.

## Self-hosting: open vs. closed registration, and the admin console

Two deployment shapes this registrar supports:

- **Open** -- public self-service: anyone can `POST /register` and create an account, no prior authorization needed. This is how this project's own reference registrars (zzmq.dev, guardianspec.org) are deployed. The default; same as leaving `REGISTRATION_MODE` unset.
- **Closed** -- for an operator who controls the whole domain, personally or as a business, and wants their own root identity usable everywhere did:guardian/did:web is accepted (see above) without exposing that same open door to the public. Set `REGISTRATION_MODE` to `"closed"` (a `vars` entry, not a secret -- see `wrangler.jsonc`'s own commented example). This blocks anonymous self-service at `/register` specifically; a Managed Identity API bearer token still works either way, since that's already gated by real authentication rather than a bare name.

A closed deployment's own root identity creates accounts for other people or agents instead, through the **admin console** (`/admin`, `/admin/create-account`) -- available on every deployment regardless of `REGISTRATION_MODE`, gated to a session authenticated as the root identity specifically. Lists every account on the registrar and offers the same generated-secret-or-set-your-own-password choice self-service registration does, plus an optional initial guardian DID. A family deploying this on a personal domain creates an account for a spouse this way (`wife@calebhailey.com`); a business creates accounts for its whole team and for any agents it manages, the same way, on its own domain.

## License

This project is dual-licensed under MIT and Apache 2.0 terms:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

Downstream projects and users may choose either license, or both, at their discretion.
