// Session (login) and pin-store state -- both live alongside keys under
// the same config directory (keystore.ts's configDir), but aren't key
// material themselves, so they get separate small files rather than
// overloading the keys directory.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parseDid, type Did, type PinRecord, type PinStore } from "@did-guardian/lib";
import { configDir } from "./keystore.js";

// --- session: one active login at a time, v1 scope ---

interface SessionFile {
  did: Did;
  registrar: string;
  cookie: string;
}

function sessionPath(): string {
  return join(configDir(), "session.json");
}

export function saveSession(did: Did, registrar: string, cookie: string): void {
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  writeFileSync(sessionPath(), JSON.stringify({ did, registrar, cookie } satisfies SessionFile, null, 2), { mode: 0o600 });
}

export function loadSession(): SessionFile {
  const path = sessionPath();
  if (!existsSync(path)) throw new Error('not logged in -- run "did-guardian login <did> --login-secret <secret>" first.');
  return JSON.parse(readFileSync(path, "utf8")) as SessionFile;
}

/**
 * C-2 (audit, HIGH): loadSession alone doesn't check WHERE the session
 * cookie is actually valid before a caller sends it somewhere. A
 * command that sends `session.cookie` to whatever registrar `did`
 * happens to name (take-custody, adopt, confirm-adopt -- the DID is
 * nearly always someone else's, not the logged-in identity's own) used
 * to send the cookie there unconditionally, so `guardian adopt
 * did:guardian:evil.test:victim` posted a real, 7-day session cookie
 * to evil.test. This is the one place that check belongs, since every
 * such command needs the identical check.
 */
export function requireSessionFor(did: Did): SessionFile {
  const session = loadSession();
  const domain = parseDid(did).domain;
  if (domain !== session.registrar) {
    throw new Error(`refusing to send your session cookie to ${domain} -- you're logged in against ${session.registrar}, and ${did} names a different registrar. If ${domain} is genuinely where this identity lives, log in there directly first.`);
  }
  return session;
}

// --- pin store: SSH known_hosts for DIDs (REQ-11-3/11-4: anchor AND
// version, so the lib's own checkPin can detect a rollback or fork, not
// only a different identity) ---

export interface Pin extends PinRecord {
  pinnedAt: string;
}

function pinsPath(): string {
  return join(configDir(), "anchors.json");
}

function loadPins(): Record<Did, Pin> {
  const path = pinsPath();
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, "utf8")) as Record<Did, Pin>;
}

export function getPin(did: Did): Pin | undefined {
  return loadPins()[did];
}

export function savePin(did: Did, pin: PinRecord): void {
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  const pins = loadPins();
  pins[did] = { ...pin, pinnedAt: new Date().toISOString() };
  writeFileSync(pinsPath(), JSON.stringify(pins, null, 2), { mode: 0o600 });
}

/** F-14/C-5-6 (audit): the lib's own checkPin, backed by this CLI's local file -- the pluggable-store design means the same checkPin call will serve a registrar's own persistent storage too, if REQ-10-15 (pending the user's approval) requires one. */
export function filePinStore(): PinStore {
  return {
    get: (did) => getPin(did),
    set: (did, record) => savePin(did, record),
  };
}
