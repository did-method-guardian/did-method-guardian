---
layout: docs-sidebar
title: "Give an AI agent an identity a human can revoke"
description: "Register an identity for an agent, make a human its guardian, and let that human authorize, recover, or shut it down -- without ever holding the agent's key."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Give an AI agent an identity a human can revoke",
  "description": "Register an identity for an agent, make a human its guardian, and let that human authorize, recover, or shut it down -- without ever holding the agent's key.",
  "url": "https://guardianspec.org/docs/how-to/ai-agent-identity/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Give an AI agent an identity a human can revoke

In did:guardian, an AI agent gets its own identity, with its own key. A human (or a team) becomes that agent's guardian: a did:guardian group with the power to recover the agent's identity if its key is compromised, shut it down when it's retired, and -- via the reference registrar's own [delegation-chain token exchange](/docs/registrar/#10-delegation-chain-tokens-token-exchange), a registrar-profile feature, not something the did:guardian method itself defines -- act as the agent for things it can't approve alone. By default, this reference registrar holds both the agent's key and the human guardian's key, encrypted, and produces whichever signature a command needs on their behalf; neither recovery nor shutdown requires the guardian to personally hold or see the agent's key either way, but as long as the registrar holds both, it can also still act as either party on its own, for anything either could authorize alone -- taking custody of a key (covered below, under "Make a human its guardian") is what actually changes that. Commands below use [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) (`npm install -g @did-guardian/cli`); see the [registrar API doc](/docs/registrar/) for the plain HTTP underneath any of them.

## Register the agent's identity

```text {linenos=false}
did-guardian register support-bot-7 --registrar guardianspec.org
```

```text {linenos=false}
Created did:guardian:guardianspec.org:support-bot-7

Login secret (shown once -- save it now, there's no recovery path if you lose it):
<secret>

This identity has no guardian yet -- register a guardian the same way, log in as them, and run "did-guardian guardian adopt did:guardian:guardianspec.org:support-bot-7" (this registrar still holds both keys, so that's the one step a bare key can't do). See "did-guardian guardian adopt --help", or https://guardianspec.org/docs/how-to/ for the full walkthrough.
```

Store that secret with the agent's own operator, not with the human who's about to become its guardian -- the whole point of the next step is that the guardian shouldn't need it.

## Make a human its guardian

A guardian can also be established directly at registration now ([REQ-7.1-1](/docs/did-guardian-spec-v0.2.0/#req-7.1-1)), via `create --guardian <did> --guardian-key <label>` -- but that needs the agent's key held locally, which `register` (above) deliberately avoids. The ordinary path below works regardless of who holds what, and is the one `register`-based setups need: a separate, signed `guardian_add`, needing both the agent's key and the incoming guardian's key to agree. The human guardian needs a did:guardian identity too -- register one if they don't already have one:

```text {linenos=false}
did-guardian register priya --registrar guardianspec.org
```

Then log in as the human and adopt the agent:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:priya --login-secret <priya's secret>
did-guardian guardian adopt did:guardian:guardianspec.org:support-bot-7
```

`adopt` is session-based (the registrar API's `.../adopt`): the caller is the *incoming guardian*, and since the registrar still holds both the agent's and the human's keys, it produces both signatures once the human is authenticated. Nobody outside the registrar ever sees either private key -- but in this default registrar-held mode, the registrar itself still can, since it's the one producing both signatures: it can sign as the agent, or as the human guardian, for any operation either of them could authorize alone, including recovering or tombstoning the agent without the human's own session ever being involved (formal spec [§12.4](/docs/did-guardian-spec-v0.2.0/#124-key-custody-modes)). Taking custody of a key (below) is what actually removes the registrar from that part of the trust model, not merely not seeing the key afterward.

**If you'd rather hold a key yourself** for one or both parties -- the agent, say, if you don't want the registrar able to sign on its behalf at all -- `did-guardian key take-custody <did>` ends the registrar's custody of that identity's key, and `did-guardian guardian add <agent-did> <guardian-did> --ward-key <label> --guardian-key <label> --submit` signs and submits the same `guardian_add` directly, once both parties hold keys locally.

## What the guardian can do afterward

**Recover it, if its key is lost or compromised.** A guardian-initiated `custodial_rotate`, signed with the guardian's key (never the agent's) -- see [Recover after a lost key](/docs/how-to/recover-lost-key/) for the exact steps; the same mechanics apply whether the ward is a person or an agent.

**Shut it down.** `custodial_tombstone`, signed by enough of the guardian set to meet `tombstone_threshold` (`any` by default, so a single guardian suffices unless configured otherwise). There's no one-call convenience endpoint for *a guardian* to tombstone a ward it guards the way there is for a ward tombstoning itself, so which command to run depends on whether the human guardian holds a key directly:

- **Guardian took custody of a key** (see above): sign and submit directly --
  ```
  did-guardian guardian tombstone did:guardian:guardianspec.org:support-bot-7 did:guardian:guardianspec.org:priya --guardian-key <label> --submit
  ```
- **Guardian still registrar-held**: use the asynchronous proposal flow (`.../propose` then `.../pending/<id>/sign-as-self`, logged in as the guardian) -- see the [registrar API doc](/docs/registrar/)'s §3. `tombstone_threshold`'s default of `any` means this reaches `satisfied`, and finalizes, the moment the guardian signs.

Either way this deactivates the agent's identity permanently -- its log stays public and readable, but no further operation on it is accepted. If you want the agent's authority limited more narrowly than "the guardian can shut the whole thing down," set a `GuardianPolicy` with a higher `tombstone_threshold` (requiring more than one guardian to agree) at registration, or with a later `policy_update`.

## Short-lived agents

A long-lived guardian managing a fleet of agents that come and go doesn't need a human name for each one -- a generated name like `"agent-$(openssl rand -hex 3)"` (or any generator producing a valid one, REQ-2-1) works fine. Naming the fleet's guardian directly at creation, in the same call, needs `create --registrar <domain> --guardian <guardian-did> --guardian-key <label>` (above) instead of `register` -- the guardian's key has to be held locally to co-sign genesis, which `register`'s server-generated keys deliberately avoid. Either way, this replaces a separate `guardian_add` per agent with one call.

Retiring one is the same `custodial_tombstone` described above, signed by the guardian -- there's no bulk-retirement operation, each agent is tombstoned individually. Names and logs are permanent by design (REQ-9-1/9-2): a retired agent's name is never freed for reuse, and its full history stays resolvable forever, even deactivated. This isn't optional cleanup debt -- a guardian's historical keys have to stay verifiable for as long as anything it ever signed might need checking, which means nothing it guarded can be deleted out from under that either. Running many short-lived agents through one registrar does mean that registrar's storage grows without bound; that's the cost of this design, not a bug to work around.
