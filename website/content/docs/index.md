---
path: /docs/
canonical_url: 'https://guardianspec.org/docs/'
layout: docs-sidebar
title: 'did:guardian'
description: >-
  A distributed identity built around guardianship: a group of other identities
  with the power to recover, deactivate, or act on behalf of an identity,
  under rules its owner sets in advance.
stage: published
updated_at: '2026-11-22T00:00:00.000Z'
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "did:guardian",
  "description": "A distributed identity built around guardianship: a group of other identities with the power to recover, deactivate, or act on behalf of an identity, under rules its owner sets in advance.",
  "url": "https://guardianspec.org/docs/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# did:guardian

**did:guardian is a distributed identity built around the concept of guardianship.** In most identity systems, control lives in a single keypair, and losing it means losing the identity for good. A did:guardian identity can have a group of guardians, which are other identities that have the power to recover it or deactivate it. Guardianship is optional, and its exact rules for how the guardianship works are set by the identity's owner in advance.

## Why this exists

Three situations come up often enough to need a standard answer:


**You lose access to your own identity.** A lost device, a forgotten key, a compromised laptop. Most identity systems have no support path for this, or have minimal support via recovery keys. Fundamentally, the key is the identity, and no key means no identity. `did:guardian` lets you name people (or other identities) in advance who can jointly restore access, the same way a family member could help you recover a bank account, but can't spend the money in it.



**Someone needs standing authority to act for an identity.** The word "guardian" comes from family law, where a guardian makes important decisions (e.g. medical, financial, legal), for someone who can't make them for themselves. did:guardian carries that same idea into a digital identity. A company might not want the AI agent it runs to have full authority over certain actions on its own. Its guardian can act on its behalf for those specific actions instead, via the reference registrar's own [delegation-chain token exchange](/docs/registrar/#10-delegation-chain-tokens-token-exchange) -- a registrar-profile mechanism, not something the method itself defines a dedicated operation for. Acting on an identity's behalf this way is one of guardianship's primary uses.



**Responsibility for an identity needs to change hands.** A board member's term ends. A shared agent gets reassigned to a new team, or the team membership changes. did:guardian treats adding and removing a guardian as its own signed, auditable operation.


## How it works


By default, a `did:guardian` identity functions no differently than a standard DID, controlling its keys directly. However, an identity can optionally have one or more **guardians**, becoming a **ward** of those guardians. Guardians are other identities (people, organizations, or other wards) granted the power to recover it, deactivate it, or act on its behalf, under a policy that any verifier checks by replaying the log. \
\
A simple example of this is a human that manages an agent. The agent has a fully functional id, and the human has a separate id, but the human can be assigned as the agent's *guardian*.


A few rules hold regardless of how many guardians there are or who they are:

- **Guardianship is explicit and consensual.** A guardian has to sign to accept the role; nobody can be named a guardian without agreeing to it. Adding or removing a guardian is also a signed, auditable action, visible in the identity's history afterward.
- **A guardian can act on the ward's behalf for things the ward can't authorize alone.** This covers recovery, but also ongoing authorization, similar to how a legal guardian already can act on behalf of a dependent, like a minor child.
- **A threshold decides how many guardians need to act together.** A ward can require any one guardian, a majority, all of them, or a specific count, choosing the appropriate policy for the level of trust the situation calls for.
- **Each guardian action is signed with that specific guardian's key.** Whether a guardian is recovering a ward, authorizing something on its behalf, or removing another guardian, the action stays traceable to whichever guardian performed it, in the identity's history.
- **Guardianship is temporary by design.** It can be handed off, shared among several guardians, reduced to none at all, or re-established later, similar to how a legal guardianship relationship starts for a reason, and is expected to end at some point (e.g. when a minor child is no longer a minor).

See the [formal specification](/docs/did-guardian-spec-v0.2.0/) for precise definitions of each operation and signature.


## Where it comes from


`did:guardian` combines two existing, proven DID methods, `did:plc` and `did:web`, and adds the guardianship concept on top of that.



**From [did:plc](https://github.com/did-method-plc/did-method-plc):** the *operation log*. An identity's history is an append-only, signed log of changes instead of a single mutable record. This is the same design Bluesky's `did:plc` runs for tens of millions of identities. This is also where *key rotation* comes from -- a guardian replaces a lost or compromised key by rotating forward to a new one.



**From [did:web](https://w3c-ccg.github.io/did-method-web/):** resolution by domain. For both `did:web` and `did:guardian`, there's no single central directory to query or depend on. An identity resolves through the domain that issued it. `did:guardian`'s identifier grammar deliberately mirrors `did:web`'s grammar (e.g. `did:guardian:acme.com:alice` vs `did:web:acme.com:alice`), so the two stay easy to read side by side.



**did:guardian's contribution:** group guardianship as a first-class part of the method. A configurable group of other identities can hold standing authority over a ward -- recovering it, acting on its behalf, with membership that can change hands over time -- verified the same way any other operation in the log is, with no separate credential, smart contract, or external system required. Neither `did:plc` nor `did:web` nor the W3C DID Core spec builds this in natively; `did:guardian` does.



**Compatibility.** Resolving a `did:guardian` identifier returns an ordinary [W3C DID Core](https://www.w3.org/TR/did-core/) document. Any tool that already understands DID documents understands this one. The guardian relationship lives in the method's operation log, which keeps the document shape fully ordinary.


## The identifier

```text {linenos=false}
did:guardian:acme.com:alice
did:guardian:acme.com
```




A `did:guardian` identifier is the domain that issued it, optionally followed by a name. `did:guardian:acme.com:alice` is Alice's identity at Acme's registrar. `did:guardian:acme.com` (no name at all) is Acme's own root organizational identity -- one per registrar, created the first time its registrar accepts any other identity.



Names are scoped to the registrar that issued them. The same name can exist, as two entirely unrelated identities, under two different domains, e.g. `did:guardian:acme.com:alice` and `did:guardian:fandom.com:alice` share nothing but a string. The full grammar, including the exact characters a name may contain, is in the [formal spec's §4](/docs/did-guardian-spec-v0.2.0/#4-identifier).



## What you can do with it


**Sign in to an app with your Guardian ID.** The reference registrar also runs as a standard OpenID Connect provider. A third-party app's "sign in with your identity provider" option works against it same way that "Log in w/ Google" or Okta works. [guardianspec.org](https://guardianspec.org) is a running example: create an identity there, then use it to sign in anywhere that accepts a custom OIDC login.


**Set up a group-governed identity for a team or an AI agent.** A company can issue an identity for an agent it runs, name itself (or a specific set of people) as guardian, and set a threshold matching how much oversight the situation needs. The guardians can authorize actions the agent isn't allowed to approve on its own, recover it if its key is lost or compromised, or deactivate it once it's retired.


**Recover an identity after losing access to it.** If a ward's key is lost, a group of its guardians (meeting the threshold configured in its policy) can issue it a fresh key. Without a guardian, there's no recovery -- a deliberate difference from `did:plc`'s ordered recovery-key list, not a gap: `did:guardian` uses guardianship for this instead of a second key, and a guardian doesn't have to be a separate person. Naming a cold-storage identity (a key generated once and kept offline) as its guardian covers the same need with nobody else involved.


**Hand off responsibility cleanly.** Adding a guardian, removing one, or dissolving guardianship entirely is each its own signed operation, recorded permanently in the identity's history.

## The parts of this project


**The method.** The abstract rules, such as identifier syntax, the operation log, guardianship, signature requirements, which are independent of any specific server. Defined in the [formal specification](/docs/did-guardian-spec-v0.2.0/).



**The reference library** (`packages/lib`). A portable implementation of the method's cryptographic and verification logic, such as signing and verifying operations, replaying a log into current state, checking threshold rules. Implemented in JavaScript so it runs in Node, in a browser, or for example, serverless infrastructure like Cloudflare Workers.



**The reference registrar** (`packages/server`). A self-hostable server implementing the method, plus a working identity provider built on top of it: standard OpenID Connect (dynamic client registration, PKCE, refresh tokens, a full consent screen), an account dashboard, an admin console for an operator managing accounts on behalf of others, and an agent-identity API for a platform that creates and manages identities programmatically. All of this is documented separately in the [registrar API spec](/docs/registrar/). A custom registrar could implement only the method and remain fully conformant.



**The running reference deployment.** [guardianspec.org](https://guardianspec.org) is a live instance of the reference registrar. Consider running the registrar on your domain, and see how separate registrars operate independently -- names are scoped per domain, so nothing overlaps between them. Creating an identity is the fastest way to see the method work end to end.



## Learn more

- [**Get Started**](/docs/how-to/): a quickstart (create an identity, resolve it, add a guardian) plus task-oriented how-to guides -- give an AI agent a revocable identity, sign in via custom OIDC, self-host a registrar, recover after a lost key.
- [**Prior art and comparisons**](/docs/prior-art/): how did:guardian relates to did:webvh, KERI's delegated AIDs, the Sovrin Guardianship Task Force's work, and ERC-4337 social recovery -- and when each fits better.
- [**The formal specification**](/docs/did-guardian-spec-v0.2.0/): the normative, complete definition of the method. It contains each operation and signature rule, and the edge cases around them.
- [**The registrar API spec**](/docs/registrar/): everything the reference registrar adds beyond the method, including the OIDC provider, the account dashboard, the agent-identity API, etc.
- [**The GitHub repository**](https://github.com/did-method-guardian/did-method-guardian): source for the method's reference library, the reference registrar, and this website.
