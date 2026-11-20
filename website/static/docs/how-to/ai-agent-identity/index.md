---
layout: docs-sidebar
title: "Give an AI agent an identity a human can revoke"
description: "Register an identity for an agent, make a human its guardian, and let that human authorize, recover, or shut it down -- without ever holding the agent's key."
---
# Give an AI agent an identity a human can revoke

An agent gets an identity, with a key. A human (or a team) becomes its guardian, with the power to authorize things the agent can't approve alone, recover it if its key is compromised, and shut it down when it's retired. Neither of those actions requires the guardian to hold, or ever see, the agent's key. Commands below use [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) (`npm install -g @did-guardian/cli`); see the [registrar API doc](/docs/registrar/) for the plain HTTP underneath any of them.

## Register the agent's identity

```text {linenos=false}
did-guardian register support-bot-7 --registrar guardianspec.org
```

```text {linenos=false}
Created did:guardian:guardianspec.org:support-bot-7

Login secret (shown once -- store it with the agent, not with the human guardian):
<secret>
```

## Make a human its guardian

Guardianship can't be set at registration (genesis never names a guardian directly -- that's REQ-7.1-1). It's a separate, signed `guardian_add`, needing both the agent's key and the incoming guardian's key to agree. The human guardian needs a did:guardian identity too -- register one if they don't already have one:

```text {linenos=false}
did-guardian register priya --registrar guardianspec.org
```

Then log in as the human and adopt the agent:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:priya --login-secret <priya's secret>
did-guardian guardian adopt did:guardian:guardianspec.org:support-bot-7
```

`adopt` is session-based (the registrar API's `.../adopt`): the caller is the *incoming guardian*, and since the registrar still holds both the agent's and the human's keys, it produces both signatures once the human is authenticated. Nobody outside the registrar ever sees either private key.

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
