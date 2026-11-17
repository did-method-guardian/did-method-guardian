---
layout: docs-sidebar
title: "Get Started"
description: "A plain-curl-and-script quickstart (create an identity, resolve it, add a guardian), plus task-oriented how-to guides for specific things you can do with did:guardian."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Get Started",
  "description": "A plain-curl-and-script quickstart (create an identity, resolve it, add a guardian), plus task-oriented how-to guides for specific things you can do with did:guardian.",
  "url": "https://guardianspec.org/docs/how-to/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Get Started

For an introduction to the method itself, see the [guide](/docs/) first -- this page assumes you already know what a ward and a guardian are, and gets straight to running things.

## Quickstart

Create an identity, resolve it, and add a guardian -- in plain `curl` and a short script.

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

## How-to guides

Each of these walks through one specific task, start to finish, with commands you can run directly.

- [Give an AI agent an identity a human can revoke](/docs/how-to/ai-agent-identity/)
- [Sign in via custom OIDC (e.g. Tailscale)](/docs/how-to/custom-oidc-login/)
- [Self-host a registrar](/docs/how-to/self-host/)
- [Recover after a lost key](/docs/how-to/recover-lost-key/)
