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

In did:guardian, an AI agent gets its own identity, with its own key. A human (or a team) becomes that agent's guardian -- a did:guardian group with the power to recover the agent's identity if its key is compromised, and to shut it down when it's retired. A conformant registrar can also let that guardian act as the agent for things it can't approve alone; the reference registrar does this through [delegation-chain token exchange](/docs/registrar/#10-delegation-chain-tokens-token-exchange), a registrar-profile feature, not something the did:guardian method itself defines.

By default, the reference registrar holds both the agent's key and the human guardian's key, encrypted, and produces whichever proof a command needs on their behalf. Neither recovery nor shutdown requires the guardian to personally hold or see the agent's key. As long as the registrar holds both keys, it can also act as either party for anything either could authorize alone -- taking custody of a key (covered below, under "Make a human its guardian") is what changes that.

Commands below use [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) (`npm install -g @did-guardian/cli`); see the [registrar API doc](/docs/registrar/) for the plain HTTP underneath any of them.

## Register the agent's identity

```text {linenos=false}
did-guardian register support-bot-7 --registrar guardianspec.org
```

```text {linenos=false}
Created did:guardian:guardianspec.org:support-bot-7

Login secret (shown once -- save it now, there's no recovery path if you lose it):
<secret>
```

Store that secret with the agent's own operator, not with the human who's about to become its guardian -- the whole point of the next step is that the guardian shouldn't need it.

## Make a human its guardian

Adding a guardian is a signed operation on both sides -- the agent's own create carries no initial guardian, since establishing one needs that guardian's own signature, which a brand-new identity can't have collected yet. The human guardian needs a did:guardian identity too -- register one if they don't already have one:

```text {linenos=false}
did-guardian register priya --registrar guardianspec.org
```

Then log in as the human and accept the agent as a ward:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:priya --login-secret <priya's secret>
did-guardian guardian adopt did:guardian:guardianspec.org:support-bot-7
```

That prints a pending id. Whoever controls the agent's own identity (its operator, holding the login secret from the step above) logs in as it and finishes the other half:

```text {linenos=false}
did-guardian login did:guardian:guardianspec.org:support-bot-7 --login-secret <agent's secret>
did-guardian guardian confirm-adopt did:guardian:guardianspec.org:support-bot-7 <pending id>
```

Nobody outside the registrar ever sees either private key -- but in this default held mode, the registrar itself still can, since it's the one producing both proofs: it can sign as the agent, or as the human guardian, for any operation either of them could authorize alone, including recovering or deactivating the agent without the human's own session ever being involved. Taking custody of a key (below) is what actually removes the registrar from that part of the trust model, not merely not seeing the key afterward.

**If you'd rather hold a key yourself** for one or both parties -- the agent, say, if you don't want the registrar able to sign on its behalf at all -- `did-guardian key take-custody <did>` ends the registrar's custody of that identity's key, and `did-guardian guardian add <agent-did> <guardian-did> --ward-key <label> --guardian-key <label>` signs and submits the same guardian relationship directly, once both parties hold keys locally. Doing this before the guardian relationship exists, as above, is safe -- but taking custody of a key that already guards something else (a human running more than one agent, say) breaks that other relationship's own standing the moment it succeeds, since it was recorded with the old key; see the [registrar doc](/docs/registrar/#2-self-contained-convenience-endpoints) for why, and the fix.

## What the guardian can do afterward

**Recover it, if its key is lost or compromised.** A guardian-initiated `update`, signed with the guardian's key (never the agent's) -- see [Recover after a lost key](/docs/how-to/recover-lost-key/) for the exact steps; the same mechanics apply whether the ward is a person or an agent.

**Shut it down.**

```text {linenos=false}
did-guardian guardian deactivate did:guardian:guardianspec.org:support-bot-7 did:guardian:guardianspec.org:priya --guardian-key <label> --submit
```

This works in one call whenever `policy.deactivation` lets a guardian approve alone (`by: "guardians"` or `"either"`, with `priya`'s own signature meeting `policy.deactivation.threshold`) -- the default policy (`by: "both"`) also needs the agent's own key, so with no change to policy this command reports what else is needed instead of succeeding; the generic multi-signer path (`did-guardian operation propose`/`operation sign`, [registrar API doc](/docs/registrar/) §3) collects whatever that turns out to be.

Either way this deactivates the agent's identity permanently -- its log stays public and readable, but no further operation on it is accepted. Registration always starts an identity on the default policy; if you want deactivation to need more than one guardian to agree, change `policy.deactivation` afterward with `setPolicy` (through the generic multi-signer path -- there's no dedicated command for it yet).

## Short-lived agents

A long-lived guardian managing a fleet of agents that come and go doesn't need a human name for each one -- a generated name like `"agent-$(openssl rand -hex 3)"` (or any generator producing a valid one) works fine. Each agent still needs its own `guardian add`/`guardian adopt`-`confirm-adopt` to establish the fleet's own guardian -- there's no way to name a guardian directly at creation.

Retiring one is the same `deactivate` described above, approved by the guardian. There's no bulk-retirement operation, each agent is deactivated individually. Names and logs are permanent by design: a retired agent's name is never reused, and its full history stays resolvable forever, even deactivated. This isn't optional cleanup debt -- a guardian's historical keys have to stay verifiable for as long as anything it ever signed might need checking, which means nothing it guarded can be deleted out from under that either. Running many short-lived agents through one registrar does mean that registrar's storage grows without bound; that's the cost of this design, not a bug to work around.
