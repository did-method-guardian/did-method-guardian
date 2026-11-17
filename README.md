# DID Guardian Method (did:guardian)

DID Guardian is a self-authenticating [DID](https://www.w3.org/TR/did-core/) method for any identity that needs an external party's custodial oversight: key recovery, revocation, transfer, and ongoing authorization for things the identity can't approve on its own. It generalizes guardianship (a human managing another human's identity, a human managing an autonomous agent's, an organization managing an account on its own behalf) as a single, cryptographically-enforced relationship: transferable, terminable, and governed by configurable, self-governing consensus thresholds rather than any one hardcoded rule.

An example DID is: `did:guardian:acme.com:alice`

The identifier is domain-first, deliberately isomorphic to `did:web`'s convention (`did:web:<domain>:<path...>`) rather than the reverse-DNS order popularized elsewhere -- did:guardian is that same domain-first shape with at most one flat name segment, which keeps a did:guardian identifier and its equivalent `did:web:acme.com:alice` visually parallel, differing only in the method name. Control over an identity (a "ward") rests with its ordered, tiered rotation keys: an operational tier the ward rotates itself, and a guardian tier that can recover or nullify the operational tier within a bounded recovery window -- directly adopting [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s proven ordered-authority mechanism, extended with group guardianship (multiple guardians, configurable M-of-N consensus) that `did:plc` has no equivalent of.

This git repository contains a TypeScript reference implementation (`packages/lib`), a self-hostable registrar + OIDC provider + account dashboard (`packages/server`), a set of interoperability test fixtures (`interop_tests`), and the specification's website (`website`).

## Motivation

Each identity method examined while designing this either coupled identity to infrastructure that can disappear, or had no native concept of one party holding standing custodial responsibility for another's keys -- recovering them, or acting on that identity's behalf. `did:guardian` was built specifically because an increasing number of identities -- autonomous agents, accounts an organization holds on someone's behalf, a person's accounts under a domain they don't fully control -- need recoverable, transferable, group-governable custodial oversight as a first-class protocol property.

## How it works

See the [guide](website/content/docs/index.md) for an introduction, or the [formal specification](website/content/docs/did-guardian-spec-v0.2.0/index.md) for the normative method definition -- both are also live at [guardianspec.org/docs](https://guardianspec.org/docs/).

## Versioning

Four different things in this repository are versioned independently, on purpose, because they're different artifacts that change for different reasons:

- **The method specification** (`v0.2.0`): the normative definition of `did:guardian` -- identifier syntax, the operation log, every operation and signature rule. Changes here mean the method's rules changed.
- **`packages/lib` and `packages/server`** (`0.1.0`): this reference implementation's semver, tracking code changes. Many releases of either can happen without the method specification changing at all.
- **The registrar API** (`v1`): the reference registrar's HTTP surface, [documented separately](website/content/docs/registrar/index.md) and explicitly versioned apart from the method -- a different registrar implementation is free to expose none of it and remain fully conformant.
- `website/site.yaml`'s `version` field is unrelated to all of the above -- it's the static site generator's config-schema version, not a product version.

A stable `/docs/spec/latest/` alias always points at whichever method specification version is current.

## Self-hosting: the bare-domain root identity

Every deployment of `packages/server` auto-provisions one bare-domain identity (`did:guardian:<your-domain>`, e.g. `did:guardian:acme.com`) the first time anything resolves it -- it's never registered the way a named ward is, since there's exactly one per deployment and it belongs to whoever legitimately operates the domain, by construction. It attests every other ward's genesis operation (the `registrar` field on `custodial_create`), and -- once given a login credential -- is a fully usable identity like any other: it can log in, rotate its operational key, deactivate itself, and set up email forwarding too -- `_` is its reserved local part everywhere a named ward would use its name, for both login (`_`, your bare domain, `@your-domain`, or `_@your-domain` all work) and mail (`_@your-domain`).

A fresh deployment generates a keypair for this identity automatically. An operator who wants to bring their own key material instead (migrating from somewhere, or managing it outside this registrar's custodial encryption) sets both `ROOT_WARD_PUBLIC_KEY` and `ROOT_WARD_PRIVATE_KEY` via `wrangler secret put` -- both or neither.

**To actually log in as this identity**, set `ROOT_WARD_LOGIN_SECRET` (also via `wrangler secret put`) to a password of your choosing -- there's no registration flow to set one through otherwise. This takes effect the next time the root identity is accessed, whether that's its first creation on a brand-new deployment or a one-time lazy upgrade on one that's already running (no redeploy or migration needed beyond setting the secret). Sign in with the name field left as `_`, your bare domain, `@your-domain`, or `_@your-domain` -- all four mean the same thing. The last one matters in practice: a relying party that forces a `name@domain` shape on its login form (Tailscale's custom-OIDC login does) leaves `_@your-domain` as the only way to reach the root identity through that form at all.

**If you forget this password**, there's no self-service recovery flow for it (it's the one credential with no guardian or admin-console path back in) -- reset it directly:

1. Generate a new secret and its stored hash, matching `hashPassword`'s scheme (`packages/server/src/secretBox.ts`): PBKDF2-HMAC-SHA256, 100,000 iterations, a random 16-byte salt, stored as `pbkdf2$<iterations>$<salt b64>$<hash b64>`. Any language with PBKDF2 support works; this doesn't have to run inside the Worker.
2. `UPDATE wards SET login_secret_hash = '<the stored hash>' WHERE name = ''` against your D1 database (`wrangler d1 execute <your-db> --remote --command "..."`).
3. Save the new secret somewhere durable immediately -- a password manager, not a browser's save-password prompt, since this credential has no recovery path if it's lost again. `ROOT_WARD_LOGIN_SECRET` doesn't need to change for this to work; the stored hash is independent of it once the one-time lazy upgrade has already happened.

See `packages/server/src/env.ts` for the complete list of environment variables this registrar reads.

## Self-hosting: open vs. closed registration, and the admin console

Two deployment shapes this registrar supports:

- **Open** -- public self-service: anyone can `POST /register` and create an account, no prior authorization needed. This is how this project's reference registrar (guardianspec.org) is deployed. The default; same as leaving `REGISTRATION_MODE` unset.
- **Closed** -- for an operator who controls the whole domain, personally or as a business, and wants a root identity usable everywhere did:guardian/did:web is accepted (see above) without exposing that same open door to the public. Set `REGISTRATION_MODE` to `"closed"` (a `vars` entry, not a secret -- see `wrangler.jsonc`'s commented example). This blocks anonymous self-service at `/register` specifically; a Managed Identity API bearer token still works either way, since that's already gated by real authentication rather than a bare name.

A closed deployment's root identity creates accounts for other people or agents instead, through the **admin console** (`/admin`, `/admin/create-account`) -- available on every deployment regardless of `REGISTRATION_MODE`, gated to a session authenticated as the root identity specifically. Lists every account on the registrar and offers the same generated-secret-or-set-your-own-password choice self-service registration does, plus an optional initial guardian DID. A family deploying this on a personal domain creates an account for a spouse this way (`wife@calebhailey.com`); a business creates accounts for its whole team and for any agents it manages, the same way, on its domain.

## License

This project is dual-licensed under MIT and Apache 2.0 terms:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

Downstream projects and users may choose either license, or both, at their discretion.
