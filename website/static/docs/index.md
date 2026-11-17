---
path: /docs/
canonical_url: 'https://guardianspec.org/docs/'
layout: docs-sidebar
title: 'did:guardian'
description: >-
  A distributed identity built around guardianship: a group of other identities
  with the power to recover, revoke, transfer, or act on behalf of an identity,
  under rules its owner sets in advance.
stage: published
updated_at: '2026-11-17T08:27:06.596Z'
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "did:guardian",
  "description": "A distributed identity built around guardianship: a group of other identities with the power to recover, revoke, transfer, or act on behalf of an identity, under rules its owner sets in advance.",
  "url": "https://guardianspec.org/docs/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# did:guardian

**did:guardian is a distributed identity built around the concept of guardianship.** In most identity systems, control lives in a single keypair, and losing it means losing the identity for good. A did:guardian identity can have a group of guardians, which are other identities that have the power to recover, revoke, or transfer it. Guardianship is optional, and its exact rules for how the guardianship works are set by the identity's owner in advance.

## Why this exists

Three situations come up often enough to need a standard answer:


**You lose access to your own identity.** A lost device, a forgotten key, a compromised laptop. Most identity systems have no support path for this, or have minimal support via recovery keys. Fundamentally, the key is the identity, and no key means no identity. `did:guardian` lets you name people (or other identities) in advance who can jointly restore access, the same way a family member could help you recover a bank account, but can't spend the money in it.



**Someone needs standing authority to act for an identity.** The word "guardian" comes from family law, where a guardian makes important decisions (e.g. medical, financial, legal), for someone who can't make them for themselves. did:guardian carries that same idea into a digital identity. A company might not want the AI agent it runs to have full authority over certain actions on its own. Its guardian can authorize those specific actions instead. Acting on an identity's behalf this way is one of guardianship's primary uses.



**Responsibility for an identity needs to change hands.** A board member's term ends. A shared agent gets reassigned to a new team, or the team membership changes. did:guardian treats this as an ordinary, signed, auditable operation.


## How it works


By default, a `did:guardian` identity functions no differently than a standard DID. It controls itself with its own keys. However, an identity can optionally have one or more **guardians**, becoming a **ward** of those guardians. Guardians are other identities (people, organizations, or other wards) granted the power to recover, revoke, or transfer it, and to act on its behalf, under a policy the ward's own registrar enforces. \
\
A simple example of this is a human that manages an agent. The agent has its own fully functional id, and the human also has its own id, but the human can be assigned as the agent's *guardian*.


A few rules hold regardless of how many guardians there are or who they are:

- **Guardianship is explicit and consensual.** A guardian has to sign to accept the role; nobody can be named a guardian without agreeing to it. Adding or removing a guardian is itself a signed, auditable action, visible in the identity's history afterward.
- **A guardian can act on the ward's behalf for things the ward can't authorize alone.** This covers recovery, but also ongoing authorization, similar to how a legal guardian already can act on behalf of a dependent, like a minor child.
- **A threshold decides how many guardians need to act together.** A ward can require any one guardian, a majority, all of them, or a specific count, choosing the appropriate policy for the level of trust the situation calls for.
- **Each guardian action is signed with that guardian's own key.** Whether a guardian is recovering a ward, authorizing something on its behalf, or removing another guardian, the action stays traceable to the specific guardian who performed the action, in the ward identity's own history.
- **Guardianship is temporary by design.** It can be handed off, shared among several guardians, reduced to none at all, or re-established later, similar to how a legal guardianship relationship starts for a reason, and is expected to end at some point (e.g. when a minor child is no longer a minor).

See the [formal specification](/docs/did-guardian-spec-v0.2.0/) for precise definitions of each operation and signature.


## Where it comes from


`did:guardian` combines two existing, proven DID methods, `did:plc` and `did:web`, and adds the guardianship concept on top of that.



**From [did:plc](https://github.com/did-method-plc/did-method-plc):** the *operation log*. An identity's history is an append-only, signed log of changes instead of a single mutable record. This is the same design Bluesky's `did:plc` runs for tens of millions of identities. This is also where *key rotation* and the *recovery window* come from. If a key is stolen and used to rotate an identity, that rotation can be undone within 72 hours.



**From [did:web](https://w3c-ccg.github.io/did-method-web/):** resolution by domain. For both `did:web` and `did:guardian`, there's no single central directory to query or depend on. An identity resolves through the domain that issued it. `did:guardian`'s identifier grammar deliberately mirrors `did:web`'s grammar (e.g. `did:guardian:acme.com:alice` vs `did:web:acme.com:alice`), so the two stay easy to read side by side.



**did:guardian's contribution:** group guardianship as a first-class part of the method itself. A configurable group of other identities can hold standing authority over a ward -- recovering it, acting on its behalf, with membership that can change hands over time -- verified the same way any other operation in the log is, with no separate credential, smart contract, or external system required. Neither `did:plc` nor `did:web` nor the W3C DID Core spec itself builds this in natively; `did:guardian` does.



**Compatibility.** Resolving a `did:guardian` identifier returns an ordinary [W3C DID Core](https://www.w3.org/TR/did-core/) document. Any tool that already understands DID documents understands this one. The guardian relationship itself lives in the method's own operation log, which keeps the document shape itself fully ordinary.


## The identifier

```
did:guardian:acme.com:alice
did:guardian:acme.com
```




A `did:guardian` identifier is the domain that issued it, optionally followed by a name. `did:guardian:acme.com:alice` is Alice's identity at Acme's registrar. `did:guardian:acme.com` (no name at all) is Acme's root organizational identity, auto-provisioned for the domain itself.



Names are scoped to the registrar that issued them. The same name can exist, as two entirely unrelated identities, under two different domains, e.g. `did:guardian:acme.com:alice` and `did:guardian:fandom.com:alice` share nothing but a string. The full grammar, including the exact characters a name may contain, is in the [formal spec's §2](/docs/did-guardian-spec-v0.2.0/#2-identifier-syntax).



## What you can do with it


**Sign in to an app with your Guardian ID.** The reference registrar also runs as a standard OpenID Connect provider. A third-party app's "sign in with your identity provider" option works against it same way that "Log in w/ Google" or Okta works. [guardianspec.org](https://guardianspec.org) is a running example: create an identity there, then use it to sign in anywhere that accepts a custom OIDC login.


**Set up a group-governed identity for a team or an AI agent.** A company can issue an identity for an agent it runs, name itself (or a specific set of people) as guardian, and set a threshold matching how much oversight the situation needs. The guardians can authorize actions the agent isn't allowed to approve on its own, recover it if its key is lost or compromised, or deactivate it once it's retired.


**Recover an identity after losing access to it.** If a ward's key is lost, a group of its guardians (meeting the threshold configured in its policy) can issue it a fresh key. If a key was stolen and already used, the same guardians can undo that specific change within the 72-hour recovery window, exactly as `did:plc` already supports.


**Hand off responsibility cleanly.** Moving guardianship from one party to another, adding a second guardian, or dissolving guardianship entirely are each a single signed operation, recorded permanently in the identity's own history.

## Quickstart

The "Try it" widget above does this interactively. Here's the same thing in plain `curl` and a short script, if you'd rather run it yourself.

**Create an identity.** Any registrar's `/register` endpoint takes just a name:

```
curl -X POST https://guardianspec.org/register \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'
```

```json
{
  "did": "did:guardian:guardianspec.org:alice",
  "document": { "...": "a W3C DID Core document" },
  "login_secret": "shown once -- save it, there's no recovery path if you lose it"
}
```

**Resolve it.** No authentication needed -- this works for anyone, anywhere:

```
curl https://guardianspec.org/.well-known/guardian/alice
```

That returns the current DID document. The full signed operation history behind it is at `/.well-known/guardian/alice/log`.

**Add a guardian.** This is the one step `curl` alone can't do, and that reflects something true about guardianship itself. The registrar holds your identity's key in custody, encrypted, so it can sign ordinary logins and rotations for you, but it deliberately can't produce a guardian's own signature on your behalf -- a guardian relationship exists only when the guardian's own key signs for it. Using [`@did-guardian/lib`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/lib) directly, with two keypairs you hold yourself:

```js
import { generateKeypair } from "@did-guardian/lib/dist/src/crypto.js";
import { signCustodialCreate, signGuardianAdd, cidFor } from "@did-guardian/lib/dist/src/operations.js";
import { replay, toDidDocument } from "@did-guardian/lib/dist/src/document.js";

const alice = await generateKeypair();
const bob = await generateKeypair();
const aliceDid = "did:guardian:example.com:alice";
const bobDid = "did:guardian:example.com:bob";

// Genesis can't name a guardian directly (REQ-7.1-1) -- guardianship is
// always a separate, later operation.
const genesis = await signCustodialCreate({
  type: "custodial_create", name: "alice",
  operationalKeys: [alice.publicKey], verificationMethods: { "key-1": alice.publicKey },
  services: {}, outgoing: [], incoming: [], prev: null,
}, {});
const genesisCid = await cidFor(genesis);

// Zero-to-one guardian_add (REQ-7.2-5): both bob's own key and alice's own
// key have to sign -- a guardian relationship starting without the
// guardian's own consent isn't one.
const addOp = await signGuardianAdd(
  { type: "guardian_add", incoming: bobDid, prev: genesisCid },
  { [bobDid]: bob.privateKey, [aliceDid]: alice.privateKey },
  [bobDid, aliceDid],
);

const log = [{ cid: genesisCid, op: genesis }, { cid: await cidFor(addOp), op: addOp }];
const state = replay(aliceDid, log);
console.log(state.guardians);          // [ "did:guardian:example.com:bob" ]
console.log(toDidDocument(state));     // an ordinary DID document -- bob never appears in it
```

That log is exactly what you'd submit to a registrar (`POST /.well-known/guardian/alice/operations`) to make it live. The [registrar API doc](/docs/registrar/) covers the asynchronous version of this -- proposing an operation and collecting the second signature over separate requests, for when both signers aren't available in the same process.

## The parts of this project


**The method.** The abstract rules, such as identifier syntax, the operation log, guardianship, signature requirements, which are independent of any specific server. Defined in the [formal specification](/docs/did-guardian-spec-v0.2.0/).



**The reference library** (`packages/lib`). A portable implementation of the method's own cryptographic and verification logic, such as signing and verifying operations, replaying a log into current state, checking threshold rules. Implemented in JavaScript so it runs in Node, in a browser, or for example, serverless infrastructure like Cloudflare Workers.



**The reference registrar** (`packages/server`). A self-hostable server implementing the method, plus a working identity provider built on top of it: standard OpenID Connect (dynamic client registration, PKCE, refresh tokens, a full consent screen), an account dashboard, an admin console for an operator managing accounts on behalf of others, and an agent-identity API for a platform that creates and manages identities programmatically. All of this is documented separately in the [registrar API spec](/docs/registrar/). A custom registrar could implement only the method itself and remain fully conformant.



**The running reference deployment.** [guardianspec.org](https://guardianspec.org) is a live instance of the reference registrar. Consider running the registrar on your domain, and see how separate registrars operate independently, each resolving their own `did:guardian` identities. Creating an identity is the fastest way to see the method work end to end.



## Learn more

- [**How-to guides**](/docs/how-to/): task-oriented walkthroughs -- give an AI agent a revocable identity, sign in via custom OIDC, self-host a registrar, recover after a lost key.
- [**Prior art and comparisons**](/docs/prior-art/): how did:guardian relates to did:webvh, KERI's delegated AIDs, the Sovrin Guardianship Task Force's work, and ERC-4337 social recovery -- and when each fits better.
- [**The formal specification**](/docs/did-guardian-spec-v0.2.0/): the normative, complete definition of the method. It contains each operation and signature rule, and the edge cases around them.
- [**The registrar API spec**](/docs/registrar/): everything the reference registrar adds beyond the method itself, including the OIDC provider, the account dashboard, the agent-identity API, etc.
- [**The GitHub repository**](https://github.com/did-method-guardian/did-method-guardian): source for the method's reference library, the reference registrar, and this website.
