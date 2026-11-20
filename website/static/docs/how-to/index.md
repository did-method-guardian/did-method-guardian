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

```
npm install -g @did-guardian/cli
```

**Create an identity:**

```
did-guardian register alice --registrar guardianspec.org
```

```
Created did:guardian:guardianspec.org:alice

Login secret (shown once -- save it now, there's no recovery path if you lose it):
<secret>
```

**Resolve it.** No authentication needed -- this works for anyone, anywhere:

```
did-guardian resolve did:guardian:guardianspec.org:alice
```

```
L3 (Live). First resolution of did:guardian:guardianspec.org:alice -- pinned anchor <cid> and registrar key (did:guardian:guardianspec.org).
{ "...": "an ordinary W3C DID Core document" }
```

That pin is the CLI's record that this is the same `alice` it saw before -- a later resolution with a different anchor gets reported loudly, not silently accepted (spec [§12](/docs/did-guardian-spec-v0.2.0/#12-authority-and-trust-model)).

**Add a guardian.** Register a second identity for whoever's becoming the guardian, log in as them, and adopt:

```
did-guardian register bob --registrar guardianspec.org
did-guardian login did:guardian:guardianspec.org:bob --login-secret <bob's secret>
did-guardian guardian adopt did:guardian:guardianspec.org:alice
```

This is the session-based path (the registrar API's `.../adopt`): the caller is the *incoming guardian*, logged in, and the registrar produces both halves of the `guardian_add` signature since it still holds both keys. It's also the one step a bare `curl` call can't do -- a guardian relationship exists only when that guardian's key actually signs for it, and here that signature comes from an authenticated session, not a key you typed into a request body.

Every command above has a plain HTTP equivalent too (`POST /register`, `GET /.well-known/guardian/alice`, `POST /guardian-login` + `POST .../adopt`) -- see the [registrar API doc](/docs/registrar/) for the exact requests, or run any `did-guardian` command with the registrar's domain in your browser's network tab to watch them happen.

### Holding a key yourself instead

Everything above leaves the registrar holding both keys, encrypted. If you'd rather hold a key yourself from the start:

```
did-guardian key take-custody did:guardian:guardianspec.org:alice
```

ends the registrar's custody of `alice`'s key -- `did-guardian guardian add`/`recover`/`tombstone` then sign and submit directly with keys you hold, no session needed. Refuses without `--force` if `alice` has no guardian yet, since losing a self-held key with nothing to recover it is unrecoverable by anyone, ever. `did-guardian create <name> --domain <domain>` builds a genesis operation fully offline, with a key you generate yourself and never hand to any registrar -- but the result is a **draft**: no registrar accepts a self-held genesis yet ([tracked as a gap](https://github.com/did-method-guardian/did-method-guardian/issues/4)), so this is for understanding the mechanics or embedding [`@did-guardian/lib`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/lib) directly, not for getting a live identity today.

See the CLI's README for the full command list, including `verify` (offline, against a pinned anchor) and `--save-log-head`/`--log-head` (offline freshness, spec §12.2's L2).

## How-to guides

Each of these walks through one specific task, start to finish, with commands you can run directly.

- [Give an AI agent an identity a human can revoke](/docs/how-to/ai-agent-identity/)
- [Sign in via custom OIDC](/docs/how-to/custom-oidc-login/)
- [Self-host a registrar](/docs/how-to/self-host/)
- [Recover after a lost key](/docs/how-to/recover-lost-key/)
