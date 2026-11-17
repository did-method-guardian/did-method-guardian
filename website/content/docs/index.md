---
layout: docs-sidebar
title: "did:guardian"
description: "A DID method where a group of guardians can recover, revoke, or transfer an identity -- without ever being able to act as it."
---
# did:guardian

**did:guardian is a DID method for identities that need more than one key to stay recoverable.** Most self-sovereign identity systems put all control in a single keypair: lose it, and the identity is gone for good. did:guardian adds an optional second layer -- a group of **guardians** who can step in to recover, revoke, or transfer the identity when something goes wrong, under rules the identity's own owner sets in advance. A guardian can always help recover an identity. A guardian can never act as it.

## Why this exists

Three situations come up often enough to need a standard answer:

**You lose access to your own identity.** A lost device, a forgotten key, a compromised laptop. Most self-sovereign systems have no support path for this -- the key is the identity, and no key means no identity. did:guardian lets you name people (or other identities) in advance who can jointly restore access, the same way a family member can already help you recover a bank account, without any of them being able to spend your money while you're perfectly fine.

**An organization needs to manage identities it doesn't fully own.** A company gives its employees logins. A platform issues identities to the AI agents it runs. In both cases, someone leaves, a role changes, or a key leaks, and someone else needs the power to recover or shut down that identity -- ideally without being able to quietly impersonate the person or agent behind it.

**Responsibility for an identity needs to change hands.** A board member's term ends. An agent gets reassigned to a new team. did:guardian treats this as an ordinary, signed, auditable operation.

## How it works

Every did:guardian identity -- called a **ward** -- controls itself with its own keys, the same as any DID. A ward can optionally have one or more **guardians**: identities (people, organizations, or other wards) granted the ability to recover, revoke, or transfer it under a policy the ward's own registrar enforces.

A few rules hold regardless of how many guardians there are or who they are:

- **Guardianship is explicit and consensual.** A guardian has to sign to accept the role; nobody can be named a guardian without agreeing to it. Adding or removing a guardian is itself a signed, auditable action, visible in the identity's history afterward.
- **A threshold decides how many guardians need to act together.** A ward can require any one guardian, a majority, all of them, or a specific count -- whatever level of trust the situation calls for.
- **Guardians act with their own keys, never the ward's.** A recovery action is signed by the guardian who performed it, so it's always traceable to them specifically. A guardian helping recover a ward and the ward acting on its own always look different in the identity's history.
- **Guardianship is temporary by design.** It can be handed off, shared among several guardians, reduced to none at all, or re-established later -- the same way a legal guardianship relationship starts for a reason and is meant to end.

The [formal specification](/docs/did-guardian-spec-v0.2.0/) defines every operation and signature rule precisely. This page stays at the level of what each piece is for.

## Where it comes from

did:guardian combines two existing, proven DID methods and adds one new idea on top.

**From [did:plc](https://github.com/did-method-plc/did-method-plc):** the operation log. Every identity is defined by an append-only, signed history of changes rather than a single mutable record -- the same design Bluesky's did:plc runs at tens of millions of identities. This is also where key rotation and a recovery window come from: if a key is stolen and used to rotate an identity, that rotation can be undone within 72 hours -- did:plc already protects against exactly this.

**From [did:web](https://w3c-ccg.github.io/did-method-web/):** resolution by domain. There's no single central directory to query or depend on -- an identity resolves through the domain that issued it, much like a website's own identity is tied to the domain serving it. did:guardian's identifier grammar deliberately mirrors did:web's own (`did:guardian:acme.com:alice` next to `did:web:acme.com:alice`), so the two stay easy to read side by side.

**did:guardian's own contribution: group guardianship as a first-class relationship.** Neither did:plc nor did:web nor the W3C DID Core spec itself has a concept of an external party recovering an identity without being able to impersonate it. did:guardian adds that as a configurable, cryptographically-enforced property of the method itself.

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

**Set up a group-governed identity for a team or an AI agent.** A company can issue an identity for an agent it runs, name itself (or a specific set of people) as guardian, and set a threshold matching how much oversight the situation needs. If the agent's key is ever compromised, the guardians recover it. If the agent is retired, the guardians deactivate it. Neither action requires the agent's own cooperation.

**Recover an identity after losing access to it.** If a ward's own key is lost, enough of its guardians (meeting whatever threshold the ward set) can issue it a fresh key. If a key was stolen and already used, the same guardians can undo that specific change within the 72-hour recovery window, exactly as did:plc already supports.

**Hand off responsibility cleanly.** Moving guardianship from one party to another, adding a second guardian, or dissolving guardianship entirely are each a single signed operation, recorded permanently in the identity's own history.

## The parts of this project

**The method.** The abstract rules -- identifier syntax, the operation log, guardianship, signature requirements -- independent of any specific server. Defined in the [formal specification](/docs/did-guardian-spec-v0.2.0/).

**The reference library** (`packages/lib`). A portable implementation of the method's own cryptographic and verification logic -- signing and verifying operations, replaying a log into current state, checking threshold rules. Runs in Node, in a browser, or in a Cloudflare Worker, so a new registrar implementation can start from it rather than from the spec's prose alone.

**The reference registrar** (`packages/server`). A self-hostable server implementing the method, plus a working identity provider built on top of it: standard OpenID Connect (dynamic client registration, PKCE, refresh tokens, a full consent screen), an account dashboard, an admin console for an operator managing accounts on behalf of others, and an agent-identity API for a platform that creates and manages identities programmatically. All of this is the registrar's own choice, documented separately in the [registrar API spec](/docs/registrar/) -- a different registrar can implement only the method itself and remain fully conformant.

**The running reference deployments.** [guardianspec.org](https://guardianspec.org) and zzmq.dev are both live instances of the reference registrar, independently operated, each resolving their own did:guardian identities today. Creating an identity on either one is the fastest way to see the method work end to end.

## Where to go deeper

- **[The formal specification](/docs/did-guardian-spec-v0.2.0/)** -- the normative, complete definition of the method: every operation, every signature rule, every edge case. Read it for anything this page only summarizes.
- **[The registrar API spec](/docs/registrar/)** -- everything the reference registrar adds beyond the method itself: the OIDC provider, the account dashboard, the agent-identity API, and the rest.
- **[The GitHub repository](https://github.com/did-method-guardian/did-method-guardian)** -- source for the method's reference library, the reference registrar, and this site.
