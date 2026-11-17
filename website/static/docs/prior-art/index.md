---
layout: docs-sidebar
title: "Prior art and comparisons"
description: "How did:guardian relates to did:webvh, KERI's delegated AIDs, the Sovrin Guardianship Task Force's work, and ERC-4337 social recovery -- and when one of those fits better."
---
# Prior art and comparisons

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Prior art and comparisons",
  "description": "How did:guardian relates to did:webvh, KERI's delegated AIDs, the Sovrin Guardianship Task Force's work, and ERC-4337 social recovery -- and when one of those fits better.",
  "url": "https://guardianspec.org/docs/prior-art/",
  "about": { "@type": "SoftwareSourceCode", "name": "did:guardian", "codeRepository": "https://github.com/did-method-guardian/did-method-guardian", "programmingLanguage": "TypeScript" }
}
</script>

did:guardian's own contribution is group guardianship as a first-class part of a DID method itself: a configurable group of other identities, with changeable membership, that can recover, revoke, transfer, or act on behalf of a ward, verified the same way any other operation in the method's own log is. Four other projects cover related ground, each from a different angle. None of them do exactly this; some do something better for a narrower need.

## did:webvh

[did:webvh](https://identity.foundation/didwebvh/v1.0/) ("did:web with Verifiable History", formerly did:tdw) extends `did:web` with a self-certifying identifier, a verifiable hash-chained history of every DID document version, pre-rotation (committing to the next key's hash in advance, so a compromised current key can't redirect control to an attacker-chosen one), and optional third-party witnesses who attest they observed an update.

**Comparable:** witnesses are a multi-party mechanism, closer in shape than most of the others here to did:guardian's own group concept.

**Different:** a witness attests that an update happened; it has no authority to make one. did:webvh has no concept of a group that can recover, revoke, or act on behalf of the identity -- control stays with whoever holds the (pre-rotated) key, full stop. If you need a tamper-evident document history and nothing more -- no recovery path if the key is lost, no standing oversight -- did:webvh is a lighter-weight fit than did:guardian for exactly that.

## KERI delegated AIDs

In [KERI](https://trustoverip.github.io/kswg-keri-specification/), a delegated identifier is established through mutual, cooperative seals -- both the delegator and the delegate cryptographically commit in their own key event logs, so neither can unilaterally impose or dissolve the relationship. Delegation composes recursively into trees (a root authority delegating to several others, each of those delegating further).

**Comparable:** the mutual-consent requirement is philosophically close to did:guardian's own "guardianship is explicit and consensual."

**Different:** KERI delegation is structurally delegator-to-delegate, not a configurable M-of-N peer group. There's no native concept of several guardians, with changeable membership, jointly overseeing one identity under a threshold -- nesting builds a hierarchy, not a flat guardian set. If a hierarchical chain of authority (a root issuer delegating down through several tiers) is the actual shape you need, KERI's delegation model fits that directly; did:guardian's own group model doesn't represent hierarchy at all.

## The Sovrin Guardianship Task Force

Sovrin's Guardianship Task Force published whitepapers (2019, a revised v2 in 2023) modeling guardianship -- specifically for people who can't act for themselves: children, people with cognitive disabilities, refugees without their own devices -- using **W3C Verifiable Credentials** issued on top of an existing DID method (`did:sov`/`did:indy`).

**Comparable:** of everything here, this is the closest in motivation -- it's explicitly about guardianship for people who need someone else able to act on their behalf, the same case did:guardian is built around.

**Different:** a guardianship credential is revocable and verifiable as a credential, but the underlying DID method has no native awareness of it -- enforcing it is up to whatever application checks the credential, not the method's own resolution or operation log. If guardianship needs to be scoped per-relationship with its own fine-grained categories (medical decisions, financial decisions, digital-account access, each a separate issuable credential type), a verifiable-credential layer like this is more flexible than did:guardian's single, uniform, method-level relationship -- did:guardian doesn't distinguish *what kind* of authority a guardian holds, only how many of them need to agree.

## ERC-4337 social recovery wallets

Ethereum's account abstraction standard lets a smart-contract wallet designate other addresses as guardians, with an M-of-N threshold of their approval able to replace the wallet's own controlling key -- logic that lives in the contract itself, increasingly modularized under ERC-7579.

**Comparable:** the M-of-N guardian-set mechanic is structurally close to a `GuardianPolicy` threshold.

**Different:** this lives entirely at the smart-contract/application layer, tied to one chain's execution environment, not in a portable, method-level operation log -- a DID layered on top of such a wallet wouldn't inherit guardianship as a property of the DID method itself. If the identity in question *is* a crypto wallet, and on-chain enforcement of recovery logic matters more than portability across chains or off-chain use, this pattern fits that directly.

## When did:guardian fits, and when it doesn't

did:guardian fits when guardianship needs to be a property of the identity itself -- portable, verifiable by replaying a log, with no dependency on a specific credential issuer, smart contract platform, or application staying alive to enforce it. It doesn't fit as well when you need hierarchical delegation (KERI), fine-grained per-relationship authority types (a verifiable-credential layer), on-chain enforcement tied to one execution environment (ERC-4337), or nothing more than a tamper-evident document history with no multi-party oversight at all (did:webvh).
