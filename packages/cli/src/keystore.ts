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

function keyFilePath(label: string): string {
  return join(keysDir(), `${label}.json`);
}

export interface KeyStoreOptions {
  keychain?: boolean;
}

export async function saveKey(label: string, key: StoredKey, opts: KeyStoreOptions = {}): Promise<void> {
  if (opts.keychain) return saveKeyToKeychain(label, key);
  mkdirSync(keysDir(), { recursive: true, mode: 0o700 });
  const path = keyFilePath(label);
  writeFileSync(path, JSON.stringify(key, null, 2), { mode: 0o600 });
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

function saveKeyToKeychain(label: string, key: StoredKey): void {
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
