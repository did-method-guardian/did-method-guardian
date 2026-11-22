---
layout: docs-sidebar
title: "Prior art and comparisons"
description: "How did:guardian relates to did:webvh, did:plc, KERI's delegated AIDs, the Sovrin Guardianship Task Force's work, and ERC-4337 social recovery -- and when one of those fits better."
---
# Prior art and comparisons

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Prior art and comparisons",
  "description": "How did:guardian relates to did:webvh, did:plc, KERI's delegated AIDs, the Sovrin Guardianship Task Force's work, and ERC-4337 social recovery -- and when one of those fits better.",
  "url": "https://guardianspec.org/docs/prior-art/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

did:guardian's contribution is group guardianship as a first-class part of a DID method: a configurable group of other identities, with changeable membership, that can recover, revoke, transfer, or act on behalf of a ward, verified the same way any other operation in the method's log is. Five other projects cover related ground, each from a different angle. None of them do exactly this; some do something better for a narrower need.

## did:webvh

[did:webvh](https://identity.foundation/didwebvh/v1.0/) ("did:web with Verifiable History", formerly did:tdw) extends `did:web` with a self-certifying identifier, a verifiable hash-chained history of every DID document version, pre-rotation (committing to the next key's hash in advance, so a compromised current key can't redirect control to an attacker-chosen one), and optional third-party witnesses who attest they observed an update.

**Comparable:** witnesses are a multi-party mechanism, closer in shape than most of the others here to did:guardian's group concept.

**Different:** a witness attests that an update happened; it has no authority to make one. did:webvh has no concept of a group that can recover, revoke, or act on behalf of the identity -- control stays with whoever holds the (pre-rotated) key, full stop. If you need a tamper-evident document history and nothing more -- no recovery path if the key is lost, no standing oversight -- did:webvh is a lighter-weight fit than did:guardian for exactly that. did:webvh's identifier is also self-certifying and portable in a way did:guardian's isn't: a did:webvh identifier can move to a new location (its own `#updateDomain` mechanism) without losing its identity, since the identifier's own hash is what anchors trust, not where it currently resolves. A did:guardian identifier is location-bound to the registrar's own domain for the life of the identifier -- domain migration is explicitly out of scope for this version (formal spec [§9](/docs/did-guardian-spec-v0.2.0/#9-deactivation-and-data-permanence)), with "link, don't move" (a new identifier plus mutual `alsoKnownAs`) as the documented alternative.

## did:plc

[did:plc](https://github.com/did-method-plc/did-method-plc) (Bluesky/AT Protocol's method) is the closest structural relative here: an append-only, hash-chained operation log, replayed to derive current state, with a two-tier key model (a rotation-key set and an operational key) and a 72-hour nullification window for recovering from a compromised key -- did:guardian's own operation log, replay model, and nullification window are deliberately the same shape.

**Comparable:** the log/replay/nullification mechanics are close enough that did:guardian is best understood as did:plc's model plus group guardianship, not a wholly separate design.

**Different:** did:plc's rotation-key tier is a single, ordered list of keys -- whichever one, in order, is willing and able to sign, authorizes recovery. did:guardian's guardian tier is a configurable, unordered M-of-N group instead, where a guardian can itself be a person, a committee, or another identity entirely, not just a second key one party happens to hold -- a deliberate difference from did:plc's own mechanism, not an extension of it. did:plc is also directory-resolved (a single, centrally-operated PLC directory), where did:guardian follows `did:web`'s own domain-scoped resolution instead -- any number of independent registrars, never one shared directory.

## KERI delegated AIDs

In [KERI](https://trustoverip.github.io/kswg-keri-specification/), a delegated identifier is established through mutual, cooperative seals -- both the delegator and the delegate cryptographically commit in their own key event logs, so neither can unilaterally impose or dissolve the relationship. Delegation composes recursively into trees (a root authority delegating to several others, each of those delegating further).

**Comparable:** the mutual-consent requirement is philosophically close to did:guardian's "guardianship is explicit and consensual."

**Different:** KERI delegation is structurally delegator-to-delegate, not a configurable M-of-N peer group. There's no native concept of several guardians, with changeable membership, jointly overseeing one identity under a threshold -- nesting builds a hierarchy, not a flat guardian set. If a hierarchical chain of authority (a root issuer delegating down through several tiers) is the actual shape you need, KERI's delegation model fits that directly; did:guardian's group model doesn't represent hierarchy at all.

## The Sovrin Guardianship Task Force

Sovrin's Guardianship Task Force published whitepapers (2019, a revised v2 in 2023) modeling guardianship -- specifically for people who can't act for themselves: children, people with cognitive disabilities, refugees without personal devices -- using **W3C Verifiable Credentials** issued on top of an existing DID method (`did:sov`/`did:indy`).

**Comparable:** of everything here, this is the closest in motivation -- it's explicitly about guardianship for people who need someone else able to act on their behalf, the same case did:guardian is built around.

**Different:** a guardianship credential is revocable and verifiable as a credential, but the underlying DID method has no native awareness of it -- enforcing it is up to whatever application checks the credential, not the method's resolution or operation log. If guardianship needs scoping per relationship into fine-grained categories (medical decisions, financial decisions, digital-account access, each a separate issuable credential type), a verifiable-credential layer like this is more flexible than did:guardian's single, uniform, method-level relationship -- did:guardian doesn't distinguish *what kind* of authority a guardian holds, only how many of them need to agree.

## ERC-4337 social recovery wallets

Ethereum's account abstraction standard lets a smart-contract wallet designate other addresses as guardians, with an M-of-N threshold of their approval able to replace the wallet's controlling key -- logic that lives in the contract, increasingly modularized under ERC-7579.

**Comparable:** the M-of-N guardian-set mechanic is structurally close to a `GuardianPolicy` threshold.

**Different:** ERC-4337's guardian logic lives entirely at the smart-contract/application layer, tied to one chain's execution environment, not in did:guardian's own method-level operation log -- a DID layered on top of such a wallet wouldn't inherit guardianship as a property of the DID method itself the way a did:guardian identity does. If the identity in question *is* a crypto wallet, and on-chain enforcement of recovery logic matters more than portability across chains or off-chain use, ERC-4337's own pattern fits that directly.

## When did:guardian fits, and when it doesn't

did:guardian fits when guardianship needs to be a property of the identity -- verifiable by replaying a log, with no dependency on a specific credential issuer, smart contract platform, or application staying alive to enforce it. It doesn't fit as well when you need a self-certifying, portable identifier instead of a domain-bound one (did:webvh), a single ordered recovery-key list with no group concept (did:plc), hierarchical delegation (KERI), fine-grained per-relationship authority types (a verifiable-credential layer), or on-chain enforcement tied to one execution environment (ERC-4337).
