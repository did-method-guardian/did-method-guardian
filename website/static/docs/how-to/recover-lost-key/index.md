---
layout: docs-sidebar
title: "Recover after a lost key"
description: "A guardian-initiated custodial_rotate replaces a ward's lost operational key -- signed by enough guardians to meet recovery_threshold, never by the ward's now-inaccessible key."
---
# Recover after a lost key

If a ward's operational key is lost, enough of its guardians (meeting whatever `recovery_threshold` its policy sets, `any` by default) can issue it a fresh one. The old key is never needed, and never recovered -- it's replaced.

This assumes the ward already has at least one guardian. If it doesn't, there's nothing that can help -- [set one up](/docs/how-to/ai-agent-identity/) while you still have the chance.

## The recovery itself

```
did-guardian guardian recover did:guardian:example.com:alice did:guardian:example.com:bob --guardian-key bob --submit
```

This needs `bob` (the guardian) to hold a key [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) can sign with directly -- if bob is still registrar-held, run `did-guardian key take-custody did:guardian:example.com:bob` first, or use the asynchronous proposal flow (`.../propose` then `.../pending/<id>/sign-as-self`, logged in as bob) described in the [registrar API doc](/docs/registrar/)'s §3 instead. Without `--submit`, the command prints the signed operation and stops there -- useful for checking it before it goes live, or for collecting more signatures by hand if `recovery_threshold` needs more than just bob.

A fresh operational key is generated and saved automatically (as `<ward-did>-recovered`); pass `--new-key <label>` to install one you already hold instead.

## If the lost key was already used by whoever took it

A key that's lost to theft, not just misplaced, might already have been used to rotate the identity before a guardian ever gets involved. The same guardian-signed `custodial_rotate` above still works -- but within 72 hours of that fraudulent rotation (the nullification window), `--prev <cid>` can point it at the cid immediately *before* the fraudulent rotation instead of the current head, specifically undoing it and rolling back to the state just before, rather than just adding another rotation on top of a compromised one:

```
did-guardian guardian recover did:guardian:example.com:alice did:guardian:example.com:bob --guardian-key bob --prev <cid-before-the-fraudulent-rotation> --submit
```

The registrar's replay logic (REQ-6-8/6-9) handles the rest. Past 72 hours, that specific undo is no longer available -- only an ordinary forward rotation is, which still replaces the compromised key, just without erasing it from the log's history.

## After recovering

The ward's guardian set is untouched by this -- `custodial_rotate` only ever replaces keys, never guardianship (REQ-7.2-2). Nothing else needs to change.
