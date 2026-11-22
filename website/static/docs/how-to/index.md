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
```

**Resolve it.** No authentication needed -- this works for anyone, anywhere:

```text {linenos=false}
did-guardian resolve did:guardian:guardianspec.org:alice
```

```text {linenos=false}
First resolution of did:guardian:guardianspec.org:alice -- pinned anchor <anchor>.
{ "...": "an ordinary W3C DID Core document" }
```

That pin is the CLI's own record that this is the same `alice` it saw before -- a later resolution with a different anchor gets reported loudly, not silently accepted.

**Add a guardian.** Register a second identity for whoever's becoming the guardian, log in as them, and adopt -- two steps, each its own identity:

```text {linenos=false}
did-guardian register bob --registrar guardianspec.org
did-guardian login did:guardian:guardianspec.org:bob --login-secret <bob's secret>
did-guardian guardian adopt did:guardian:guardianspec.org:alice
```

That prints a pending id. Whoever controls `alice` (here, the same person, for this walkthrough) logs in as `alice` and finishes it:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:alice --login-secret <alice's secret>
did-guardian guardian confirm-adopt did:guardian:guardianspec.org:alice <pending id>
```

A guardian relationship exists only once both sides have signed for it -- `bob`'s own consent to take on the role, and `alice`'s own approval of `bob` as its guardian.

Every command above has a plain HTTP equivalent too -- see the [registrar API doc](/docs/registrar/) for the exact requests, or pass `--json` to any `did-guardian` command (or point it through a local HTTP proxy) to see exactly what it sent and got back.

### Holding a key yourself instead

Everything above leaves the registrar holding both keys, encrypted. If you'd rather hold a key yourself, log back in as `alice` specifically first -- the session above is `bob`'s, and `take-custody` acts as whichever identity is actually logged in, never the identity named in the command itself:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:alice --login-secret <alice's secret>
did-guardian key take-custody did:guardian:guardianspec.org:alice
```

That `take-custody` command ends the registrar's custody of `alice`'s key for good -- `did-guardian guardian add`/`recover`/`deactivate` then sign and submit directly with keys you hold, no session needed.

For a brand-new identity, `did-guardian create <name> --registrar <domain>` builds a create operation with a key you generate yourself and never hand to any registrar, then submits it for real. `create <name> --domain <domain>` (no `--registrar`) builds the same operation fully offline instead, with no network call at all -- useful for understanding the mechanics or embedding [`@did-guardian/lib`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/lib) directly, but the result is a draft until something actually accepts it.

See the CLI's README for the full command list, including `verify` (offline, §8 only) and `operation propose`/`operation sign` (the generic path for an operation needing more approvals than one command can produce).

## How-to guides

Each of these walks through one specific task, start to finish, with commands you can run directly.

- [Give an AI agent an identity a human can revoke](/docs/how-to/ai-agent-identity/)
- [Sign in via custom OIDC](/docs/how-to/custom-oidc-login/)
- [Self-host a registrar](/docs/how-to/self-host/)
- [Recover after a lost key](/docs/how-to/recover-lost-key/)
