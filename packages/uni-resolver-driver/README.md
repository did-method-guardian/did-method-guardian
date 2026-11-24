# @did-guardian/uni-resolver-driver

A [Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
driver for `did:guardian`. Not published to npm (`private: true`) -- built
directly from this monorepo's own `packages/lib`, and shipped only as the
Docker image `ghcr.io/did-method-guardian/driver-did-guardian`.

## What it does

`GET /1.0/identifiers/<did>` resolves any `did:guardian:<domain>[:<name>]` by
fetching that domain's own log and independently re-verifying it with
`@did-guardian/lib`'s own `resolve()` -- not just relaying whatever document
the target registrar happens to answer with. See `src/resolveDriver.ts` for
the actual logic; `src/server.ts` is the thin HTTP wrapper.

## Running it

```bash
npm run build
npm start                          # listens on :8080
curl http://localhost:8080/1.0/identifiers/did:guardian:guardianspec.org
```

## Building the image

Build context is the **repo root**, not this directory -- the image needs
`packages/lib` alongside it:

```bash
docker build -f packages/uni-resolver-driver/Dockerfile -t driver-did-guardian .
docker run -p 8080:8080 driver-did-guardian
```

The `publish-driver.yml` workflow does this automatically on a `v1.0.0` tag
or manual dispatch, and pushes the result to
`ghcr.io/did-method-guardian/driver-did-guardian`.

## Testing

`npm test` resolves the live `did:guardian:guardianspec.org` root identity
and a freshly-registered test identity against the real registrar, and
checks that a log tampered with after signing is refused rather than
relayed -- see `tests/resolveDriver.test.ts`.
