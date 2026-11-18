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
- **Self-held** -- you hold the key, the registrar holds nothing usable. Either `create` (fully offline -- but see the note below) or `key take-custody` (ends a registrar's custody of an existing identity) gets you here. Once self-held, `guardian add`/`recover`/`tombstone` sign and submit directly with your key -- no session needed.

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
did-guardian create <name> --domain <domain> [--key <label>]
```
Builds a self-held genesis operation entirely offline -- no network call at all. The result is a **draft**: nothing makes the identifier real until some registrar accepts it, and the reference registrar in this repository doesn't accept a self-held genesis yet ([issue #4](https://github.com/did-method-guardian/did-method-guardian/issues/4)). Useful today for understanding the mechanics, or for embedding `packages/lib` in your own registrar.

```
did-guardian register <name> --registrar <domain> [--json]
```
Creates a registrar-held identity the ordinary way (`POST /register`). This is the only way to get a real, live identity on the current reference registrar.

### Resolve and verify

```
did-guardian resolve <did> [--log] [--json]
did-guardian verify <did> --log <file>
```
`resolve` always talks to the registrar live (L3) and pins the identity's anchor (genesis CID) the first time it sees that DID -- a later mismatch is reported loudly, not silently accepted. `verify` checks a log you already have *offline*, reporting L0 (internally consistent) or L1 (matches a pin from an earlier `resolve`) -- never a bare "valid".

### Session (for registrar-held identities)

```
did-guardian login <did> --login-secret <secret>
did-guardian guardian adopt <ward-did>
```
`login` starts a session (stored in the config directory, one at a time). `guardian adopt` is the session-based zero-to-one `guardian_add`: log in as the *incoming guardian*, then run it against the ward -- the registrar produces both signatures since it still holds both keys.

### Guardianship (local-key signing, for self-held identities)

```
did-guardian guardian add <ward-did> <guardian-did> --ward-key <label> --guardian-key <label> [--submit]
did-guardian guardian recover <ward-did> <guardian-did> --guardian-key <label> [--new-key <label>] [--submit]
did-guardian guardian tombstone <ward-did> <guardian-did> --guardian-key <label> [--submit] [-y]
```
These sign directly with keys you hold and only touch the network with `--submit`. `add` needs *both* parties to hold a key directly (via `create` or `key take-custody`) -- for a ward that's still registrar-held, use `guardian adopt` instead. `recover` and `tombstone` only ever need the guardian's key, so they work regardless of the ward's custody mode.

## What this doesn't do yet

- No bring-your-own-key genesis against a live registrar ([issue #4](https://github.com/did-method-guardian/did-method-guardian/issues/4)) -- `create` produces a draft only.
- No OAuth device-code login -- `login` uses a login secret or password directly. A device-code flow is worth adding once the registrar's OAuth surface supports it.
- No `--keychain` support on Windows.
- No propose/sign-individual flow for a guardian relationship that's partly self-held and partly registrar-held, or for a non-empty guardian set -- see the [registrar API spec](https://guardianspec.org/docs/registrar/)'s §3 for the asynchronous collection endpoints this would wrap.
