# @did-guardian/cli

A command-line tool for `did:guardian`: generate keys, create and register identities, resolve and verify them offline, and manage guardianship.

## Install

```
npm install -g @did-guardian/cli
```

Or, inside this monorepo: `npm install && npm run build --workspace=packages/cli`, then run `node packages/cli/dist/src/index.js` (or `npm link` it).

## Conventions

Matches the shape other identity-tooling CLIs use (`age-keygen`, `ssh-keygen`, `gh`):

- **Keys live in a config directory** under your home (`$XDG_CONFIG_HOME/did-guardian`, or `~/.config/did-guardian` if that's unset), one JSON file per label, written with owner-only permissions (`0600`). No passphrase encryption in this first pass -- the same posture `age-keygen` ships with. Use `--keychain` (macOS and Linux only right now) to store a key in the OS keychain instead.
- **Subcommands, not flags-only**: `did-guardian key generate`, `did-guardian guardian add`, and so on.
- **Non-destructive by default**: an irreversible action (`key take-custody`, `guardian tombstone --submit`) asks for confirmation unless you pass `-y`/`--yes`, and most operations print what *would* happen rather than acting until you pass `--submit`.
- **`--json`** on commands where a machine-readable response is useful.

## Two ways a key can be held

A `did:guardian` identity's operational key is either:

- **Registrar-held** -- the registrar generated it and still holds it, encrypted. This is what `register` produces. Day-to-day operations (`login`, `guardian adopt`) go through a session; the registrar signs on the identity's behalf.
- **Self-held** -- you hold the key, the registrar holds nothing usable. Either `create` (with `--registrar`, publishes for real; with `--domain` alone, stays an offline draft) or `key take-custody` (ends a registrar's custody of an existing identity) gets you here. Once self-held, `guardian add`/`recover`/`tombstone` sign and submit directly with your key -- no session needed.

Spec reference: [§12, Authority and trust model](https://guardianspec.org/docs/did-guardian-spec-v0.2.0/#12-authority-and-trust-model) and [§12.4, Key custody modes](https://guardianspec.org/docs/did-guardian-spec-v0.2.0/#124-key-custody-modes).

## Commands

### Keys

```
did-guardian key generate <label> [--keychain]
did-guardian key show <label> [--keychain]
did-guardian key list
did-guardian key take-custody <ward-did> [--new-key <label>] [-f/--force] [-y/--yes]
```

### Create and register

```
did-guardian create <name> --registrar <domain> [--key <label>] [--guardian <did> --guardian-key <label>]
did-guardian create <name> --domain <domain> [--key <label>] [--guardian <did> --guardian-key <label>]
```
Builds a self-held genesis operation with a key you generate yourself and never hand to any registrar. With `--registrar`, submits it for real -- genesis submission is part of the method (formal spec REQ-8-2), so this works against any conformant registrar, including the reference one in this repository. With `--domain` alone, stays entirely offline instead -- no network call at all, and the result is a **draft** until something actually accepts it. Useful for understanding the mechanics, or for embedding `packages/lib` in your own registrar.

`--guardian <did>` establishes that DID as a guardian directly at genesis (formal spec REQ-7.1-1) instead of via a later `guardian add`/`adopt` -- halves the operations needed for an identity that's always born with a guardian (a long-lived guardian managing an ephemeral agent fleet, say). Requires `--guardian-key <label>`, a saved key for that same DID, since a guardian established this way must co-sign genesis; that DID must also already be a resolvable identity (create it first if it doesn't exist yet). Only works when the same operator holds both keys locally -- for any other guardian relationship, create the identity guardian-less and add one afterward.

```
did-guardian register <name> --registrar <domain> [--json]
```
Creates a registrar-held identity the ordinary way (`POST /register`) -- the registrar-held path. `create --registrar <domain>` above is the self-held path: both publish a real, live identity on any conformant registrar (formal spec REQ-8-2), differing only in who holds the resulting key.

### Resolve and verify

```
did-guardian resolve <did> [--log] [--save-log-head <file>] [--json]
did-guardian verify <did> --log <file> [--log-head <file>] [--max-age <seconds>]
```
`resolve` always talks to the registrar live (L3) and pins the identity's anchor and the registrar's public key the first time it sees that DID -- a later mismatch is reported loudly, not silently accepted. `--save-log-head` also fetches a signed, timestamped statement about the current log head (spec §12.2's L2) and saves it to a file.

`verify` checks a log you already have *offline*: L0 (internally consistent) on its own, L1 if it matches a pin from an earlier `resolve`, or L2 if you also pass `--log-head` with a statement that verifies against the pinned registrar key and is newer than `--max-age` seconds (default 300) -- never a bare "valid".

### Session (for registrar-held identities)

```
did-guardian login <did> --login-secret <secret>
did-guardian guardian adopt <ward-did>
```
`login` starts a session (stored in the config directory, one at a time). `guardian adopt` is the session-based zero-to-one `guardian_add`: log in as the *incoming guardian*, then run it against the ward -- the registrar produces both signatures since it still holds both keys.

### Guardianship (local-key signing, for self-held identities)

```
did-guardian guardian add <ward-did> <guardian-did> --ward-key <label> --guardian-key <label> [--submit]
did-guardian guardian recover <ward-did> <guardian-did> --guardian-key <label> [--new-key <label>] [--prev <cid>] [--submit]
did-guardian guardian tombstone <ward-did> <guardian-did> --guardian-key <label> [--submit] [-y]
```
These sign directly with keys you hold and only touch the network with `--submit`. `add` needs *both* parties to hold a key directly (via `create` or `key take-custody`) -- for a ward that's still registrar-held, use `guardian adopt` instead. `recover` and `tombstone` only ever need the guardian's key, so they work regardless of the ward's custody mode. `recover --prev <cid>` is nullification (spec REQ-6-8): point it at the cid immediately before a fraudulent rotation, within 72 hours of that rotation, to roll it back instead of just rotating forward from it.

## What this doesn't do yet

- No OAuth device-code login -- `login` uses a login secret or password directly. A device-code flow is worth adding once the registrar's OAuth surface supports it.
- No `--keychain` support on Windows.
- No propose/sign-individual flow for a guardian relationship that's partly self-held and partly registrar-held, or for a non-empty guardian set -- see the [registrar API spec](https://guardianspec.org/docs/registrar/)'s §3 for the asynchronous collection endpoints this would wrap.
