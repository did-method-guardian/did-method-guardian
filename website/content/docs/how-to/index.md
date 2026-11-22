---
layout: docs-sidebar
title: "Get Started"
description: "A CLI quickstart (create an identity, resolve it, add a guardian), plus task-oriented how-to guides for specific things you can do with did:guardian."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Get Started",
  "description": "A CLI quickstart (create an identity, resolve it, add a guardian), plus task-oriented how-to guides for specific things you can do with did:guardian.",
  "url": "https://guardianspec.org/docs/how-to/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Get Started

For an introduction to the method, see the [guide](/docs/) first -- this page assumes you already know what a ward and a guardian are, and gets straight to running things.

## Quickstart

Create an identity, resolve it, and add a guardian, using [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli):

```text {linenos=false}
npm install -g @did-guardian/cli
```

**Create an identity:**

```text {linenos=false}
did-guardian register alice --registrar guardianspec.org
```

```text {linenos=false}
Created did:guardian:guardianspec.org:alice

Login secret (shown once -- save it now, there's no recovery path if you lose it):
<secret>

This identity has no guardian yet -- register a guardian the same way, log in as them, and run "did-guardian guardian adopt did:guardian:guardianspec.org:alice" (this registrar still holds both keys, so that's the one step a bare key can't do). See "did-guardian guardian adopt --help", or https://guardianspec.org/docs/how-to/ for the full walkthrough.
```

**Resolve it.** No authentication needed -- this works for anyone, anywhere:

```text {linenos=false}
did-guardian resolve did:guardian:guardianspec.org:alice
```

```text {linenos=false}
L3 (Live). First resolution of did:guardian:guardianspec.org:alice -- pinned anchor <cid> and registrar key (did:guardian:guardianspec.org).
{ "...": "an ordinary W3C DID Core document" }
```

That pin is the CLI's record that this is the same `alice` it saw before -- a later resolution with a different anchor gets reported loudly, not silently accepted (spec [§12](/docs/did-guardian-spec-v0.2.0/#12-authority-and-trust-model)).

**Add a guardian.** Register a second identity for whoever's becoming the guardian, log in as them, and adopt:

```text {linenos=false}
did-guardian register bob --registrar guardianspec.org
did-guardian login did:guardian:guardianspec.org:bob --login-secret <bob's secret>
did-guardian guardian adopt did:guardian:guardianspec.org:alice
```

Adopting a guardian this way is did:guardian's session-based path for establishing a `guardian_add` (the registrar API's `.../adopt`): the caller is the *incoming guardian*, logged in, and the registrar produces both halves of the required signature since it still holds both keys. It's also the one step in this walkthrough a bare `curl` call can't do -- a guardian relationship exists only when that guardian's key actually signs for it, and here that signature comes from an authenticated session, not a key you typed into a request body.

Every command above has a plain HTTP equivalent too (`POST /register`, `GET /.well-known/guardian/alice`, `POST /guardian-login` + `POST .../adopt`) -- see the [registrar API doc](/docs/registrar/) for the exact requests, or pass `--json` to any `did-guardian` command (or point it through a local HTTP proxy) to see exactly what it sent and got back.

### Holding a key yourself instead

Everything above leaves the registrar holding both keys, encrypted. If you'd rather hold a key yourself, log back in as `alice` specifically first -- the session above is `bob`'s, and `take-custody` acts as whichever identity is actually logged in, never the identity named in the command itself:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:alice --login-secret <alice's secret>
did-guardian key take-custody did:guardian:guardianspec.org:alice
```

That `take-custody` command ends the registrar's custody of `alice`'s key -- `did-guardian guardian add`/`recover`/`tombstone` then sign and submit directly with keys you hold, no session needed. This still refuses without `--force` here, for a less obvious reason than "no guardian at all": `alice` already has a guardian (`bob`, from the step above), but the registrar still custodies `bob`'s key too, and `bob` alone already satisfies `alice`'s default `recovery_threshold` ("any") -- so this registrar could still rotate `alice`'s key at any time by signing as `bob` instead, even after `alice`'s own key moves to self-custody. The refusal is the CLI surfacing that real fact about the trust model, not a bug; `--force` proceeds once you've actually considered it. (A ward with literally no guardian refuses for the more familiar reason: losing a self-held key with nothing to recover it is unrecoverable by anyone, ever.)

For a brand-new identity, `did-guardian create <name> --registrar <domain>` builds a genesis operation with a key you generate yourself and never hand to any registrar, then submits it for real -- genesis submission is part of the method now (formal spec [REQ-8-2](/docs/did-guardian-spec-v0.2.0/#req-8-2)), not a registrar-specific convenience, so this works against any conformant registrar's `.../operations` endpoint, not just one that happens to support it. `create <name> --domain <domain>` (no `--registrar`) builds the same operation fully offline instead, with no network call at all -- useful for understanding the mechanics or embedding [`@did-guardian/lib`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/lib) directly, but the result is a draft until something actually accepts it.

See the CLI's README for the full command list, including `verify` (offline, against a pinned anchor) and `--save-log-head`/`--log-head` (offline freshness, spec §12.2's L2).

## How-to guides

Each of these walks through one specific task, start to finish, with commands you can run directly.

- [Give an AI agent an identity a human can revoke](/docs/how-to/ai-agent-identity/)
- [Sign in via custom OIDC](/docs/how-to/custom-oidc-login/)
- [Self-host a registrar](/docs/how-to/self-host/)
- [Recover after a lost key](/docs/how-to/recover-lost-key/)
