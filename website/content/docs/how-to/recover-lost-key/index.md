---
layout: docs-sidebar
title: "Recover after a lost key"
description: "A guardian-initiated update replaces a ward's lost key -- approved under its policy's own recovery setting, never by the ward's now-inaccessible key."
---
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Recover after a lost key",
  "description": "A guardian-initiated update replaces a ward's lost key -- approved under its policy's own recovery setting, never by the ward's now-inaccessible key.",
  "url": "https://guardianspec.org/docs/how-to/recover-lost-key/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

# Recover after a lost key

Two separate cases share the name "recovery," and need different things.

**A backup key.** An identity can hold up to 8 keys at once ([REQ-6-1](/docs/did-guardian-spec-v0.2.0/#req-6-1)). If `alice` still holds even one of hers, that one key alone can sign an `update` installing a fresh one -- no guardian needed at all. This is the simplest case, and worth setting up ahead of time: a second key, kept somewhere separate from the first, turns "lost a key" into an ordinary self-service rotation.

**Guardian-approved recovery**, this page's main topic: if `alice` has lost every key she held, enough of her guardians (meeting whatever `policy.recovery` sets, `majority` by default) can issue her a fresh one instead. The old key is never needed, and never recovered -- it's replaced. Without a backup key of her own and without a guardian, there's genuinely nothing that can help: did:guardian uses guardianship for this, deliberately, rather than `did:plc`'s ordered recovery-key list -- set one up (see below) before this happens, not after.

A held ward is a different case from either of these: the registrar still custodies the key behind it, so what's actually "lost" is usually just your own login credential, not the key itself -- that's an account-recovery problem (see [self-host](/docs/how-to/self-host/)'s own login flow), separate from this page's own guardian-signed `update`.

A did:guardian guardian doesn't have to be a separate person -- [REQ-6-2](/docs/did-guardian-spec-v0.2.0/#req-6-2) makes a guardian an identity, which `alice` herself can control: a cold-storage identity (a key generated once, kept offline, and never used for anything else) named as `alice`'s own guardian covers the case where there's no one else to name, with no second party involved. Set one up while `alice` still holds a key herself -- `did-guardian create <name> --registrar <domain>` builds the cold-storage identity with its own self-held key (never `register`, which generates a registrar-held one, the opposite of what a cold-storage guardian needs), then add it as a guardian ([`guardian add`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli), if both keys are self-held).

## The recovery itself

```text {linenos=false}
did-guardian guardian recover did:guardian:example.com:alice did:guardian:example.com:bob --guardian-key bob --submit
```

This `guardian recover` command needs `bob` (the guardian) to hold a key [`@did-guardian/cli`](https://github.com/did-method-guardian/did-method-guardian/tree/main/packages/cli) can sign with directly. With `--submit`, it sends the operation immediately and reports whether `alice`'s own `policy.recovery` was satisfied by bob's approval alone; without it, the command only prints what it built.

If bob's own key is still held by a registrar rather than local, don't run `key take-custody` to work around that -- bob's existing entry in `alice`'s own `guardians` list names bob's key as the registrar still custodies it, and taking custody changes that key out from under it, costing bob his standing to approve anything for `alice` at all (it would need its own `updateGuardian` to re-seat, which a sole, registrar-held guardian has no way to produce either). Use `did-guardian operation propose`/`did-guardian operation sign` instead: propose the operation, then have bob log in and approve the pending operation through his own account dashboard, where the registrar signs with the key it already holds for him, once he's reviewed and confirmed exactly what it's for. The same path covers more than one required guardian too, each signing in turn against the same pending id.

A fresh key is generated and saved automatically (as `<ward-did>-recovered`); pass `--new-key <label>` to install one you already hold instead.

## If the lost key was already used by whoever took it

A key that's lost to theft, not just misplaced, might already have been used to rotate the identity before a guardian ever gets involved. There's no way to undo that rotation -- an accepted operation is permanent, by design, so there's nothing for a guardian to point at and roll back. The same guardian-signed `update` above still works, and still replaces the compromised key; it just adds a new operation on top of the compromised one rather than erasing it. The compromised rotation stays visible in the identity's own history, for anyone who resolves it to see.

## After recovering

The ward's guardian set is untouched by this -- `update` only ever replaces keys, never guardianship. Nothing else needs to change.
