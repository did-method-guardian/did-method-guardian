---
layout: docs-sidebar
title: "Recover after a lost key"
description: "A guardian-initiated custodial_rotate replaces a ward's lost operational key -- signed by enough guardians to meet recovery_threshold, never by the ward's now-inaccessible key."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Recover after a lost key",
  "description": "A guardian-initiated custodial_rotate replaces a ward's lost operational key -- signed by enough guardians to meet recovery_threshold, never by the ward's now-inaccessible key.",
  "url": "https://guardianspec.org/docs/how-to/recover-lost-key/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Recover after a lost key

If a ward's operational key is lost, enough of its guardians (meeting whatever `recovery_threshold` its policy sets, `any` by default) can issue it a fresh one. The old key is never needed, and never recovered -- it's replaced.

This assumes the ward already has at least one guardian, and that its key is actually lost -- held by no one, not even the registrar. If both are true, there's nothing that can help: without a guardian, there is no recovery path, full stop -- a self-held key, with no guardian, that's actually gone, is unrecoverable by anyone, ever. did:guardian deliberately works this way instead of `did:plc`'s ordered recovery-key list: a guardian can be a person, a committee, or another identity entirely, not just a second key you happen to hold.

A registrar-held ward is a different case: the registrar still custodies the key behind it, so what's actually "lost" is usually just your own login credential, not the key itself -- that's an account-recovery problem (see the registrar API doc's own login/account-recovery flows), separate from this page's own guardian-signed `custodial_rotate`.

That last option -- a guardian that is another identity you control, rather than a separate person -- is the usual answer when there's no one else to name: a cold-storage identity (a key you generate once, keep offline, and never use for anything else) named as `alice`'s guardian covers exactly this case, with no second party involved at all. [Set one up](/docs/how-to/ai-agent-identity/) while you still have the chance -- either the ordinary way afterward (`guardian add`/`adopt`), or directly at genesis with `create --guardian <cold-storage-did> --guardian-key <label>` if you're creating `alice` for the first time and already hold both keys.

## The recovery itself

```text {linenos=false}
did-guardian guardian recover did:guardian:example.com:alice did:guardian:example.com:bob --guardian-key bob --submit
```

This needs `bob` (the guardian) to hold a key [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) can sign with directly -- if bob is still registrar-held, run `did-guardian key take-custody did:guardian:example.com:bob` first, or use the asynchronous proposal flow (`.../propose` then `.../pending/<id>/sign-as-self`, logged in as bob) described in the [registrar API doc](/docs/registrar/)'s §3 instead. Without `--submit`, the command prints the signed operation and stops there -- useful for checking it before it goes live, or for collecting more signatures by hand if `recovery_threshold` needs more than just bob.

A fresh operational key is generated and saved automatically (as `<ward-did>-recovered`); pass `--new-key <label>` to install one you already hold instead.

## If the lost key was already used by whoever took it

A key that's lost to theft, not just misplaced, might already have been used to rotate the identity before a guardian ever gets involved. The same guardian-signed `custodial_rotate` above still works -- but within 72 hours of that fraudulent rotation (the nullification window), `--prev <cid>` can point it at the cid immediately *before* the fraudulent rotation instead of the current head, specifically undoing it and rolling back to the state just before, rather than just adding another rotation on top of a compromised one:

```text {linenos=false}
did-guardian guardian recover did:guardian:example.com:alice did:guardian:example.com:bob --guardian-key bob --prev <cid-before-the-fraudulent-rotation> --submit
```

The registrar's replay logic (REQ-6-8/6-9) handles the rest. Past 72 hours, that specific undo is no longer available -- only an ordinary forward rotation is, which still replaces the compromised key, just without erasing it from the log's history.

## After recovering

The ward's guardian set is untouched by this -- `custodial_rotate` only ever replaces keys, never guardianship (REQ-7.2-2). Nothing else needs to change.
