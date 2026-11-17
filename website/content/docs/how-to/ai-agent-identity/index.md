---
layout: docs-sidebar
title: "Give an AI agent an identity a human can revoke"
description: "Register an identity for an agent, make a human its guardian, and let that human authorize, recover, or shut it down -- without ever holding the agent's key."
---
# Give an AI agent an identity a human can revoke

An agent gets an identity, with a key. A human (or a team) becomes its guardian, with the power to authorize things the agent can't approve alone, recover it if its key is compromised, and shut it down when it's retired. Neither of those actions requires the guardian to hold, or ever see, the agent's key.

## Register the agent's identity

```
curl -X POST https://guardianspec.org/register \
  -H "Content-Type: application/json" \
  -d '{"name": "support-bot-7"}'
```

```json
{
  "did": "did:guardian:guardianspec.org:support-bot-7",
  "document": { "...": "..." },
  "login_secret": "the agent's custodied-key credential -- store it with the agent, not the guardian"
}
```

## Make a human its guardian

Guardianship can't be set at registration (genesis never names a guardian directly -- that's REQ-7.1-1). It's a separate, signed `guardian_add`, and it needs both the agent's key and the incoming guardian's key to agree. If you hold both keys yourself (the common case when you're setting this up for an agent you run), [`@did-guardian/lib`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/lib) does it directly:

```js
import { generateKeypair } from "@did-guardian/lib/dist/src/crypto.js";
import { signCustodialCreate, signGuardianAdd, cidFor } from "@did-guardian/lib/dist/src/operations.js";
import { replay } from "@did-guardian/lib/dist/src/document.js";

const agentKey = await generateKeypair();
const humanKey = await generateKeypair();
const agentDid = "did:guardian:example.com:support-bot-7";
const humanDid = "did:guardian:example.com:priya";

const genesis = await signCustodialCreate({
  type: "custodial_create", name: "support-bot-7",
  operationalKeys: [agentKey.publicKey], verificationMethods: { "key-1": agentKey.publicKey },
  services: {}, outgoing: [], incoming: [], prev: null,
}, {});
const genesisCid = await cidFor(genesis);

const addOp = await signGuardianAdd(
  { type: "guardian_add", incoming: humanDid, prev: genesisCid },
  { [humanDid]: humanKey.privateKey, [agentDid]: agentKey.privateKey },
  [humanDid, agentDid],
);

const addCid = await cidFor(addOp);
const log = [{ cid: genesisCid, op: genesis }, { cid: addCid, op: addOp }];
console.log(replay(agentDid, log).guardians); // [ "did:guardian:example.com:priya" ]
```

Submit each operation to the registrar as it's signed (`POST /.well-known/guardian/support-bot-7/operations`), or use the [asynchronous proposal flow](/docs/registrar/) if the agent and the guardian aren't both available in the same process.

## What the guardian can do afterward

**Recover it, if its key is lost or compromised.** A guardian-initiated `custodial_rotate`, signed with the guardian's key (never the agent's) -- see [Recover after a lost key](/docs/how-to/recover-lost-key/) for the exact steps; the same mechanics apply whether the ward is a person or an agent.

**Shut it down.** `custodial_tombstone`, signed by enough of the guardian set to meet `tombstone_threshold` (`any` by default, so a single guardian suffices unless you've configured otherwise):

```js
import { signCustodialTombstone, cidFor } from "@did-guardian/lib/dist/src/operations.js";

const tombstoneOp = await signCustodialTombstone(
  { type: "custodial_tombstone", prev: addCid },
  { [humanDid]: humanKey.privateKey },
  [humanDid],
);
```

This deactivates the agent's identity permanently -- its log stays public and readable, but no further operation on it is accepted. If you want the agent's authority limited more narrowly than "the guardian can shut the whole thing down," set a `GuardianPolicy` with a higher `tombstone_threshold` (requiring more than one guardian to agree) at registration, or with a later `policy_update`.
