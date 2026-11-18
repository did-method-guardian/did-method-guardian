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

For an introduction to the method, see the [guide](/docs/) first -- this page assumes you already know what a ward and a guardian are, and gets straight to running things.

## Quickstart

Create an identity, resolve it, and add a guardian -- in plain `curl` and a short script. Prefer a CLI over curl? [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) wraps the same operations (`did-guardian register`, `did-guardian resolve`, `did-guardian guardian adopt`), plus key management, offline verification against a pinned anchor, and taking custody of a registrar-held key -- see its README for the full command list.

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

**Add a guardian.** This is the one step `curl` alone can't do, and that reflects something true about guardianship: a guardian relationship exists only when that guardian's key actually signs for it. On the reference registrar, `alice`'s key from `/register` above is held in custody, encrypted -- establishing a guardian for her goes through a session-authenticated endpoint (`.../adopt`, see the [registrar API doc](/docs/registrar/)), where the registrar signs with the key it already holds once you're logged in, not through raw signing with a key you hold yourself.

The example below shows the same operation's underlying mechanics with two keypairs generated and held entirely outside any registrar, using [`@did-guardian/lib`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/lib) directly. It's accurate cryptography and a good way to see exactly what a `guardian_add` signature requires, but it isn't a live flow against guardianspec.org or any deployment of `packages/server` as it stands today: a registrar's only path for creating a new identity is `/register`, and that path always generates the operational key on the server, never accepts one you supply. ([Tracked as a gap](https://github.com/did-method-guardian/did-method-guardian/issues/4) -- self-held-key genesis isn't implemented yet.) This code is for embedding `packages/lib` directly: building your own registrar, or working with a log you already have in hand.

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

// Zero-to-one guardian_add (REQ-7.2-5): both bob's key and alice's key
// have to sign -- a guardian relationship starting without the
// guardian's consent isn't one.
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

That's the same `guardian_add` a real registrar accepts, but getting it onto a live, registrar-custodied `alice` means calling `.../adopt` with both parties authenticated, not submitting a locally-built log: `.../operations` only accepts new operations appended to a ward that already exists there, and genesis is never one of the operation types it takes. The [registrar API doc](/docs/registrar/) covers `.../adopt` for the zero-to-one case shown here, `.../propose` plus pending-signature collection for a non-empty guardian set or signers who aren't available in the same session, and the cross-registrar case where the incoming guardian is hosted somewhere else entirely.

## How-to guides

Each of these walks through one specific task, start to finish, with commands you can run directly.

- [Give an AI agent an identity a human can revoke](/docs/how-to/ai-agent-identity/)
- [Sign in via custom OIDC](/docs/how-to/custom-oidc-login/)
- [Self-host a registrar](/docs/how-to/self-host/)
- [Recover after a lost key](/docs/how-to/recover-lost-key/)
