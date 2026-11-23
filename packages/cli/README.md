# @did-guardian/cli

A command-line tool for `did:guardian`: generate keys, create and register identities, resolve them with their mutuality and ward reports, and manage guardianship.

## Install

```
npm install -g @did-guardian/cli
```

Or, inside this monorepo: `npm install && npm run build --workspace=packages/cli`, then run `node packages/cli/dist/src/index.js` (or `npm link` it).

## Conventions

Matches the shape other identity-tooling CLIs use (`age-keygen`, `ssh-keygen`, `gh`):

- **Keys live in a config directory** under your home (`$XDG_CONFIG_HOME/did-guardian`, or `~/.config/did-guardian` if that's unset), one JSON file per label, written with owner-only permissions (`0600`). No passphrase encryption in this first pass -- the same posture `age-keygen` ships with. Use `--keychain` (macOS and Linux only right now) to store a key in the OS keychain instead.
- **Subcommands, not flags-only**: `did-guardian key generate`, `did-guardian guardian add`, and so on.
- **Non-destructive by default**: an irreversible action (`key take-custody`, `guardian deactivate --submit`) asks for confirmation unless you pass `-y`/`--yes`, and a guardian-signed operation prints what it built rather than acting until you pass `--submit`.
- **`--json`** on commands where a machine-readable response is useful.

## Two ways a key can be held

A `did:guardian` identity's key is either:

- **Held** -- the registrar generated it and still holds it, encrypted. This is what `register` produces. Day-to-day operations (`login`, `guardian adopt`/`confirm-adopt`) go through a session; the registrar signs on the identity's behalf.
- **Self-held** -- you hold the key, the registrar holds nothing usable. Either `create` (with `--registrar`, publishes for real; with `--domain` alone, stays an offline draft) or `key take-custody` (ends a registrar's custody of an existing identity) gets you here. Once self-held, `guardian add`/`recover`/`deactivate` sign and submit directly with your key -- no session needed.

Spec reference: [§7, Operations](https://guardianspec.org/docs/did-guardian-spec-v0.2.0/#7-operations) and [§10, Registrar](https://guardianspec.org/docs/did-guardian-spec-v0.2.0/#10-registrar).

## Commands

### Keys

```
did-guardian key generate <label> [--keychain]
did-guardian key show <label> [--keychain]
did-guardian key list
did-guardian key take-custody <ward-did> [--new-key <label>] [-y/--yes]
```

### Create and register

```
did-guardian create <name> --registrar <domain> [--key <label>]
did-guardian create <name> --domain <domain> [--key <label>]
```
Builds a self-held create operation with a key you generate yourself and never hand to any registrar. With `--registrar`, submits it for real. With `--domain` alone, stays entirely offline instead -- no network call at all, and the result is a **draft** until something actually accepts it. No initial guardian: a `create` naming one needs that guardian's own signature too (§7.6), which a single offline command can't get from a guardian it doesn't already control -- add one afterward with `guardian add`/`adopt`.

```
did-guardian register <name> --registrar <domain> [--json]
```
Creates a held identity the ordinary way (`POST /register`) -- the held path. `create --registrar <domain>` above is the self-held path; both publish a real, live identity, differing only in who holds the resulting key.

### Resolve and verify

```
did-guardian resolve <did> [--log] [--json] [--version-id <hash>]
did-guardian verify <did> --log <file>
```
`resolve` fetches a DID's current log live and runs §11 resolution: its document, plus (outside `--json`) a mutuality report for every guardian and successor (`mutual`, `keys out of date`, `withdrawn`, `deactivated`, `different identity`, or `unavailable`) and a ward report for everything it's itself a guardian or successor of. `--version-id <hash>` resolves as of a past operation instead of the log's own current end (REQ-9-5).

Every log this command fetches -- the target, and every guardian's, successor's, or attestation root's log resolution touches along the way -- is pinned by anchor *and* version (REQ-11-3), in every mode including `--json`: a later fetch reporting a different anchor is a different identity, and one whose log no longer contains a previously-recorded version is a rollback or fork (REQ-11-4). Either one is reported loudly and exits non-zero, never silently accepted.

`verify` checks a log you already have *offline*, §8 only (signatures and structure, no cross-log or attestation check, since those need the network) -- reports valid, invalid, or unsupported.

### Session (for held identities)

```
did-guardian login <did> --login-secret <secret>
did-guardian guardian adopt <ward-did>
did-guardian guardian confirm-adopt <ward-did> <pending-id>
```
`login` starts a session (stored in the config directory, one at a time). Adopting a guardian is two steps, each its own identity: `guardian adopt`, logged in as the incoming guardian, accepts the ward into the guardian's own log and drafts the matching entry; `guardian confirm-adopt`, logged in as the ward, finishes adding it.

### Guardianship (local-key signing, for self-held identities)

```
did-guardian guardian add <ward-did> <guardian-did> --ward-key <label> --guardian-key <label> [--guardian-key <label> ...]
did-guardian guardian recover <ward-did> <guardian-did> --guardian-key <label> [--new-key <label>] [--submit]
did-guardian guardian deactivate <ward-did> <guardian-did> --guardian-key <label> [--ward-key <label>] [--submit] [-y]
```
These sign directly with keys you hold. `add` needs *both* parties to hold a key directly (via `create` or `key take-custody`) -- for a ward that's still held by a registrar, use `guardian adopt`/`confirm-adopt` instead. Repeat `--guardian-key` once per key for a guardian with more than one current key -- a proof is needed from every one of them. `recover` only ever needs the guardian's key, so it works regardless of the ward's own custody. `deactivate` needs `--ward-key` too whenever `policy.deactivation.by` is `"both"` (the default) or `"self"` -- the command says so up front if it's missing rather than submitting something doomed to be rejected.

### The generic multi-signer path

```
did-guardian operation propose <did> --file <op.json> --key <label>
did-guardian operation sign <pending-id> --registrar <domain> --key <label>
did-guardian operation status <pending-id> --registrar <domain>
```
For any operation whose required approvals one signature can't satisfy -- removing a guardian by vote of the others, a policy change, or a ward whose recovery/deactivation policy needs more than one guardian. Build the operation's own fields (without `proof`) as JSON, propose it with your own key, and have every other required signer run `operation sign` against the same pending id.

## What this doesn't do yet

- No OAuth device-code login -- `login` uses a login secret or password directly.
- No `--keychain` support on Windows.
- No dedicated command for `setPolicy`, `updateGuardian`, or `releaseWard` -- build the operation's own JSON by hand and use `operation propose`/`operation sign`.
