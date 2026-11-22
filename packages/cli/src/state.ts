// Session (login) and pin-store state -- both live alongside keys under
// the same config directory (keystore.ts's configDir), but aren't key
// material themselves, so they get separate small files rather than
// overloading the keys directory.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Did } from "@did-guardian/lib";
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

// --- pin store: SSH known_hosts for DIDs (REQ-5-7's anchor, trust on first use) ---

export interface Pin {
  anchor: string;
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

export function savePin(did: Did, pin: Omit<Pin, "pinnedAt">): void {
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  const pins = loadPins();
  pins[did] = { ...pin, pinnedAt: new Date().toISOString() };
  writeFileSync(pinsPath(), JSON.stringify(pins, null, 2), { mode: 0o600 });
}
