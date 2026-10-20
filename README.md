# DID Guardian Method (did:guardian)

DID Guardian is a self-authenticating [DID](https://www.w3.org/TR/did-core/) method for any identity that may need an external party's custodial oversight -- key recovery, revocation, and transfer -- without that oversight ever amounting to impersonation. It generalizes guardianship (a human managing another human's identity, a human managing an autonomous agent's, an organization managing an account on its own behalf) as a single, cryptographically-enforced relationship: transferable, terminable, and governed by configurable, self-governing consensus thresholds rather than any one hardcoded rule.

An example DID is: `did:guardian:alice:acme:example`

The identifier is name-first and domain-qualified, read left to right the way an email address is (`alice`, at `acme.example`) rather than in reverse-DNS order -- deliberately chosen for readability, since resolution is already domain-partitioned by construction and gets nothing from reverse-DNS's prefix-grouping. Control over an identity (a "ward") rests with its own ordered, tiered rotation keys: an operational tier the ward rotates itself, and a guardian tier that can recover or nullify the operational tier within a bounded recovery window -- directly adopting [`did:plc`](https://github.com/did-method-plc/did-method-plc)'s own proven ordered-authority mechanism, extended with group guardianship (multiple guardians, configurable M-of-N consensus) that `did:plc` has no equivalent of.

This git repository contains a TypeScript reference implementation (`packages/lib`), a set of interoperability test fixtures (`interop_tests`), and the specification's own website (`website`).

## Motivation

Every identity method examined while designing this either coupled identity to infrastructure that can disappear, or had no native concept of one party holding custodial responsibility for another's keys without that amounting to full impersonation. `did:guardian` was built specifically because an increasing number of identities -- autonomous agents, accounts an organization holds on someone's behalf, a person's own accounts under a domain they don't fully control -- need recoverable, transferable, group-governable custodial oversight as a first-class protocol property, not a convention layered on top.

## How it works

See the [specification](website/content/spec/v1/index.md).

## License

This project is dual-licensed under MIT and Apache 2.0 terms:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

Downstream projects and users may choose either license, or both, at their discretion.
