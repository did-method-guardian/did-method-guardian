---
layout: docs-sidebar
title: "Recover after a lost key"
description: "A guardian-initiated custodial_rotate replaces a ward's lost operational key -- signed by enough guardians to meet recovery_threshold, never by the ward's own (now-inaccessible) key."
---
# Recover after a lost key

If a ward's own operational key is lost, enough of its guardians (meeting whatever `recovery_threshold` its policy sets, `any` by default) can issue it a fresh one. The ward's own old key is never needed, and never recovered -- it's replaced.

This assumes the ward already has at least one guardian. If it doesn't, there's nothing that can help -- [set one up](/docs/how-to/ai-agent-identity/) while you still have the chance.

## The recovery itself

```js
import { generateKeypair } from "@did-guardian/lib/dist/src/crypto.js";
import { signCustodialRotateByGuardians, cidFor } from "@did-guardian/lib/dist/src/operations.js";
import { replay } from "@did-guardian/lib/dist/src/document.js";

const newKey = await generateKeypair(); // the ward's replacement operational key
const wardDid = "did:guardian:example.com:alice";
const guardianDid = "did:guardian:example.com:bob";

// `prev` is the cid of whatever the current head of alice's own log is --
// fetch it from GET /.well-known/guardian/alice/log if you don't already
// have it.
const rotateOp = await signCustodialRotateByGuardians(
  {
    type: "custodial_rotate",
    operationalKeys: [newKey.publicKey],
    verificationMethods: { "key-1": newKey.publicKey },
    services: {},
    prev: currentHeadCid,
  },
  { [guardianDid]: guardianPrivateKey },
  [guardianDid], // enough guardians to meet recovery_threshold -- just bob, if recovery_threshold is "any"
);
```

Submit it: `POST /.well-known/guardian/alice/operations` with `rotateOp` as the body. If more than one guardian's signature is needed to meet `recovery_threshold`, collect them the same way any multi-party operation is collected -- see the [registrar API doc](/docs/registrar/)'s own section on proposing and contributing signatures over separate requests.

## If the lost key was already used by whoever took it

A key that's lost to theft, not just misplaced, might already have been used to rotate the identity before a guardian ever gets involved. The same guardian-signed `custodial_rotate` above still works -- but within 72 hours of that fraudulent rotation (the nullification window), it can specifically undo it, rolling back to the state just before, rather than just adding another rotation on top of a compromised one. Point `prev` at the cid immediately before the fraudulent rotation, not the current head, and the registrar's own replay logic (REQ-6-8/6-9) handles the rest. Past 72 hours, that specific undo is no longer available -- only an ordinary forward rotation is.

## After recovering

The ward's guardian set is untouched by this -- `custodial_rotate` only ever replaces keys, never guardianship (REQ-7.2-2). Nothing else needs to change.
