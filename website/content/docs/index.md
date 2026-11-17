---
layout: docs-sidebar
title: "did:guardian"
description: "A distributed identity built around guardianship: a group of other identities with the power to recover, revoke, transfer, or act on behalf of an identity, under rules its owner sets in advance."
---
# did:guardian

**did:guardian is a distributed identity built around guardianship.** An identity can have a group of guardians, which are other identities that have the power to recover, revoke, or transfer it. Guardianship is optional, and its exact rules are set by the identity's own owner in advance.

Most identity systems have no equivalent. Control lives in a single keypair, and losing it means losing the identity for good.

## Why this exists

Three situations come up often enough to need a standard answer:

**You lose access to your own identity.** A lost device, a forgotten key, a compromised laptop. Most identity systems have no support path for this -- the key is the identity, and no key means no identity. did:guardian lets you name people (or other identities) in advance who can jointly restore access, the same way a family member can already help you recover a bank account without being able to spend your money while you're perfectly fine.

**Someone needs standing authority to act for an identity.** The word "guardian" comes from family law, where a guardian makes decisions -- medical, financial, legal -- for someone who can't make them alone. did:guardian carries that same idea into a digital identity. A company might not want the AI agent it runs to have full authority over certain actions on its own. Its guardian can authorize those specific actions instead. Acting on an identity's behalf this way is one of guardianship's primary uses.

**Responsibility for an identity needs to change hands.** A board member's term ends. An agent gets reassigned to a new team. did:guardian treats this as an ordinary, signed, auditable operation.

## How it works

A did:guardian identity -- called a **ward** -- controls itself with its own keys, the same as any DID. A ward can optionally have one or more **guardians**: identities (people, organizations, or other wards) granted the power to recover, revoke, or transfer it, and to act on its behalf, under a policy the ward's own registrar enforces.

A few rules hold regardless of how many guardians there are or who they are:

- **Guardianship is explicit and consensual.** A guardian has to sign to accept the role; nobody can be named a guardian without agreeing to it. Adding or removing a guardian is itself a signed, auditable action, visible in the identity's history afterward.
- **A guardian can act on the ward's behalf for things the ward can't authorize alone.** This covers recovery, but also ongoing authorization -- the same role a legal guardian already plays for a dependent.
- **A threshold decides how many guardians need to act together.** A ward can require any one guardian, a majority, all of them, or a specific count -- whatever level of trust the situation calls for.
- **Each guardian action is signed with that guardian's own key.** Whether a guardian is recovering a ward, authorizing something on its behalf, or removing another guardian, the action stays traceable to the specific guardian who performed it in the identity's own history.
- **Guardianship is temporary by design.** It can be handed off, shared among several guardians, reduced to none at all, or re-established later -- the same way a legal guardianship relationship starts for a reason and is meant to end.

The [formal specification](/docs/did-guardian-spec-v0.2.0/) defines each operation and signature rule precisely. This page stays at the level of what each piece is for.

## Where it comes from

did:guardian combines two existing, proven DID methods and adds one new idea on top.

**From [did:plc](https://github.com/did-method-plc/did-method-plc):** the operation log. An identity's history is an append-only, signed log of changes instead of a single mutable record -- the same design Bluesky's did:plc runs at tens of millions of identities. This is also where key rotation and a recovery window come from: if a key is stolen and used to rotate an identity, that rotation can be undone within 72 hours -- did:plc already protects against exactly this.

**From [did:web](https://w3c-ccg.github.io/did-method-web/):** resolution by domain. There's no single central directory to query or depend on -- an identity resolves through the domain that issued it, much like a website's own identity is tied to the domain serving it. did:guardian's identifier grammar deliberately mirrors did:web's own (`did:guardian:acme.com:alice` next to `did:web:acme.com:alice`), so the two stay easy to read side by side.

**did:guardian's own contribution: group guardianship as a first-class relationship.** Neither did:plc nor did:web nor the W3C DID Core spec itself has a concept of a group of other parties with standing authority to manage an identity -- recovering it, acting on its behalf, or having that membership change hands over time while the identity itself stays the same. did:guardian adds that as a configurable property of the method itself.

**Compatibility.** Resolving a did:guardian identifier returns an ordinary [W3C DID Core](https://www.w3.org/TR/did-core/) document -- any tool that already understands DID documents understands this one. The guardian relationship itself lives in the method's own operation log, which keeps the document shape itself fully ordinary.

## The identifier

```
did:guardian:acme.com:alice
did:guardian:acme.com
```

A did:guardian identifier is the domain that issued it, optionally followed by a name. `did:guardian:acme.com:alice` is Alice's identity at Acme's registrar. `did:guardian:acme.com` -- no name at all -- is Acme's own organizational identity, auto-provisioned for the domain itself.

Names are scoped to the registrar that issued them. The same name can exist, as two entirely unrelated identities, under two different domains -- `did:guardian:acme.com:alice` and `did:guardian:fandom.com:alice` share nothing but a string. The full grammar, including the exact characters a name may contain, is in the [formal spec's §2](/docs/did-guardian-spec-v0.2.0/#2-identifier-syntax).

## What you can do with it

**Sign in to an app with your Guardian ID.** Any registrar also runs as a standard OpenID Connect provider -- a third-party app's "sign in with your identity provider" option works against it no differently than it would against Google or Okta. [guardianspec.org](https://guardianspec.org) is a running example: create an identity there, then use it to sign in anywhere that accepts a custom OIDC login.

**Set up a group-governed identity for a team or an AI agent.** A company can issue an identity for an agent it runs, name itself (or a specific set of people) as guardian, and set a threshold matching how much oversight the situation needs. The guardians can authorize actions the agent isn't allowed to approve on its own, recover it if its key is lost or compromised, or deactivate it once it's retired.

**Recover an identity after losing access to it.** If a ward's own key is lost, enough of its guardians (meeting whatever threshold the ward set) can issue it a fresh key. If a key was stolen and already used, the same guardians can undo that specific change within the 72-hour recovery window, exactly as did:plc already supports.

**Hand off responsibility cleanly.** Moving guardianship from one party to another, adding a second guardian, or dissolving guardianship entirely are each a single signed operation, recorded permanently in the identity's own history.

## The parts of this project

**The method.** The abstract rules -- identifier syntax, the operation log, guardianship, signature requirements -- independent of any specific server. Defined in the [formal specification](/docs/did-guardian-spec-v0.2.0/).

**The reference library** (`packages/lib`). A portable implementation of the method's own cryptographic and verification logic -- signing and verifying operations, replaying a log into current state, checking threshold rules. Runs in Node, in a browser, or in a Cloudflare Worker, so a new registrar implementation can start from it rather than from the spec's prose alone.

**The reference registrar** (`packages/server`). A self-hostable server implementing the method, plus a working identity provider built on top of it: standard OpenID Connect (dynamic client registration, PKCE, refresh tokens, a full consent screen), an account dashboard, an admin console for an operator managing accounts on behalf of others, and an agent-identity API for a platform that creates and manages identities programmatically. All of this is the registrar's own choice, documented separately in the [registrar API spec](/docs/registrar/) -- a different registrar can implement only the method itself and remain fully conformant.

**The running reference deployments.** [guardianspec.org](https://guardianspec.org) and zzmq.dev are both live instances of the reference registrar, independently operated, each resolving their own did:guardian identities today. Creating an identity on either one is the fastest way to see the method work end to end.

## Where to go deeper

- **[The formal specification](/docs/did-guardian-spec-v0.2.0/)** -- the normative, complete definition of the method: each operation, each signature rule, the edge cases around them. Read it for anything this page only summarizes.
- **[The registrar API spec](/docs/registrar/)** -- everything the reference registrar adds beyond the method itself: the OIDC provider, the account dashboard, the agent-identity API, and the rest.
- **[The GitHub repository](https://github.com/did-method-guardian/did-method-guardian)** -- source for the method's reference library, the reference registrar, and this site.
