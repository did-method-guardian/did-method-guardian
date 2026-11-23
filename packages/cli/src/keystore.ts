// Local key storage, matching the convention established tools in this space
// use (age-keygen, ssh-keygen, the gh CLI): a config directory under the
// user's home, private-key files written with owner-only permissions, and
// an opt-in --keychain flag for the OS credential store rather than
// keychain-by-default. No passphrase-based encryption in this first pass --
// the same posture age-keygen ships with (an unencrypted key file,
// protected by filesystem permissions); someone needing more than that
// should reach for --keychain or full-disk encryption, not a hand-rolled
// KDF here.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, chmodSync, readdirSync, existsSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

export interface StoredKey {
  did?: string;
  publicKey: string; // Multikey ('z'-prefixed base58btc)
  privateKey: string; // base64url PKCS8
}

const SERVICE_NAME = "did-guardian";

export function configDir(): string {
  if (process.env.XDG_CONFIG_HOME) return join(process.env.XDG_CONFIG_HOME, "did-guardian");
  if (platform() === "win32" && process.env.APPDATA) return join(process.env.APPDATA, "did-guardian");
  return join(homedir(), ".config", "did-guardian");
}

function keysDir(): string {
  return join(configDir(), "keys");
}

/**
 * C-1 (audit): a label reaches here from a command-line argument or a
 * DID, and becomes a filename (keyFilePath) or a keychain account name
 * -- it must never be interpreted as a path (`../other-user/keys` or
 * an absolute path escaping keysDir), and `:` is invalid in a filename
 * on Windows (a did:guardian DID contains it verbatim, e.g. a
 * `<ward-did>-self-held` default label). Substituting `_` for all
 * three neutralizes traversal outright (no `/` or `\` survives) without
 * refusing the DID- and domain-derived labels this CLI generates
 * itself; only a label that's empty, or still just "." or ".." after
 * substitution (neither of which contains any of those characters to
 * begin with), is actually rejected.
 */
function sanitizeLabel(label: string): string {
  const safe = label.replace(/[:/\\]/g, "_");
  if (safe === "" || safe === "." || safe === "..") {
    throw new Error(`"${label}" isn't a valid key label -- use a plain name instead.`);
  }
  return safe;
}

function keyFilePath(label: string): string {
  return join(keysDir(), `${sanitizeLabel(label)}.json`);
}

export interface KeyStoreOptions {
  keychain?: boolean;
  force?: boolean;
}

/**
 * C-1 (audit, CRITICAL): this used to overwrite an existing key under
 * the same label with no check at all -- a repeat `create`, `recover`
 * (even print-only, before this fix), or `take-custody` run silently
 * replaced a key you might still need, with nothing printed about it.
 * `wx` fails with EEXIST rather than truncating if the file is already
 * there; `opts.force` is the explicit, deliberate override.
 */
export async function saveKey(label: string, key: StoredKey, opts: KeyStoreOptions = {}): Promise<void> {
  if (opts.keychain) return saveKeyToKeychain(label, key, opts);
  mkdirSync(keysDir(), { recursive: true, mode: 0o700 });
  const path = keyFilePath(label);
  try {
    writeFileSync(path, JSON.stringify(key, null, 2), { mode: 0o600, flag: opts.force ? "w" : "wx" });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`a key is already saved under the label "${label}" (${path}) -- pass --force to overwrite it, or choose a different label. Overwriting loses access to whatever that key currently controls unless you have it saved elsewhere.`);
    }
    throw e;
  }
  chmodSync(path, 0o600); // belt and suspenders -- writeFileSync's mode is masked by umask on some platforms
}

export async function loadKey(label: string, opts: KeyStoreOptions = {}): Promise<StoredKey> {
  if (opts.keychain) return loadKeyFromKeychain(label);
  const path = keyFilePath(label);
  if (!existsSync(path)) {
    throw new Error(`no local key named "${label}" (looked in ${path}). Run "did-guardian key generate ${label}" first, or pass --keychain if it was saved there.`);
  }
  return JSON.parse(readFileSync(path, "utf8")) as StoredKey;
}

export function listLocalKeys(): string[] {
  const dir = keysDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -".json".length));
}

// --- OS keychain, opt-in via --keychain ---
//
// macOS: the `security` CLI, always present. Linux: `secret-tool` (part of
// libsecret), present on most GNOME-based desktops but not a given on a
// headless server -- fails with a clear error if it's missing, rather than
// silently falling back to a file (that would surprise anyone who asked
// for --keychain specifically expecting the key NOT to land in a plain
// file). Windows keychain support isn't implemented in this first pass --
// errors out clearly instead of pretending to succeed.
//
// Every call here uses execFileSync with an explicit argv array, never a
// shell string -- a label or key value containing shell metacharacters
// must never be interpretable as anything but literal data.

function keychainEntryExists(label: string): boolean {
  const os = platform();
  try {
    if (os === "darwin") {
      execFileSync("security", ["find-generic-password", "-s", SERVICE_NAME, "-a", label], { stdio: "ignore" });
    } else if (os === "linux") {
      execFileSync("secret-tool", ["lookup", "service", SERVICE_NAME, "account", label], { stdio: "ignore" });
    } else {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function saveKeyToKeychain(label: string, key: StoredKey, opts: KeyStoreOptions = {}): void {
  // C-1: this used to unconditionally delete-then-overwrite any
  // existing keychain entry under the same label with no check at
  // all.
  if (!opts.force && keychainEntryExists(label)) {
    throw new Error(`a key is already saved in the OS keychain under the label "${label}" -- pass --force to overwrite it, or choose a different label. Overwriting loses access to whatever that key currently controls unless you have it saved elsewhere.`);
  }
  const secret = JSON.stringify(key);
  const os = platform();
  if (os === "darwin") {
    try {
      execFileSync("security", ["delete-generic-password", "-s", SERVICE_NAME, "-a", label], { stdio: "ignore" });
    } catch {
      // No existing entry to delete -- fine, this is the common case.
    }
    execFileSync("security", ["add-generic-password", "-s", SERVICE_NAME, "-a", label, "-w", secret, "-U"]);
    return;
  }
  if (os === "linux") {
    execFileSync(
      "secret-tool",
      ["store", "--label", `${SERVICE_NAME}:${label}`, "service", SERVICE_NAME, "account", label],
      { input: secret },
    );
    return;
  }
  throw new Error(
    `--keychain isn't implemented on this platform (${os}) yet. Save without --keychain to use a local key file instead.`,
  );
}

function loadKeyFromKeychain(label: string): StoredKey {
  const os = platform();
  let secret: string;
  if (os === "darwin") {
    secret = execFileSync("security", ["find-generic-password", "-s", SERVICE_NAME, "-a", label, "-w"], {
      encoding: "utf8",
    }).trim();
  } else if (os === "linux") {
    secret = execFileSync("secret-tool", ["lookup", "service", SERVICE_NAME, "account", label], {
      encoding: "utf8",
    }).trim();
  } else {
    throw new Error(
      `--keychain isn't implemented on this platform (${os}) yet. Keys saved without --keychain are local files instead.`,
    );
  }
  return JSON.parse(secret) as StoredKey;
}
