# Security Policy

`did:guardian` is a cryptographic identity protocol with a reference registrar implementation. Vulnerabilities here can affect real identities and real recovery guarantees, so please report them privately rather than opening a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the [Security tab](https://github.com/did-method-guardian/did-method-guardian/security) on this repository and select **Report a vulnerability**. This opens a private advisory visible only to maintainers until a fix is ready.

If you can't use that for some reason, open a GitHub issue asking for a private contact and a maintainer will follow up — please don't post vulnerability details publicly even in that initial issue.

Please include:
- The affected component (`packages/lib`, `packages/server`, or a specific deployed registrar)
- Steps to reproduce, or a minimal proof of concept
- What you believe the impact is (e.g., unauthorized operation signing, guardian-threshold bypass, impersonation, key material exposure)

## Scope

In scope:
- The `did:guardian` method itself (`packages/lib`) — operation validation, guardian threshold logic, signature verification, DID/document resolution
- The reference registrar (`packages/server`) — authentication, session handling, OIDC/OAuth flows, the pending-operations signature-collection machine, cross-registrar relay
- The two live reference deployments, `zzmq.dev` and `guardianspec.org`

Out of scope:
- Third-party dependencies (report upstream, though we'd appreciate a heads-up)
- Denial-of-service findings that rely purely on sending high volumes of traffic, as opposed to an amplification or resource-exhaustion bug in the application logic itself

## Response

This is a small, early-stage open-source project without a dedicated security team or a bug bounty program. We'll acknowledge reports as quickly as we can and aim to have a fix or mitigation plan before any public disclosure. If you don't hear back within a reasonable time, following up is welcome.
