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

// --- pin store: SSH known_hosts for DIDs (REQ-12-2) ---

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

// --- registrar-key pin store: keyed by DOMAIN, not by ward DID (WS-2.3,
// audit) -- every ward on the same registrar shares the same registrar
// key, so pinning it once per ward meant N stale, independently-drifting
// copies for N wards on the same registrar instead of one canonical one.

export interface RegistrarKeyPin {
  registrarDid: Did;
  registrarKey: string; // Multikey, exactly as the DID document exposes it -- see resolveRegistrarKey
  pinnedAt: string;
}

function registrarKeyPinsPath(): string {
  return join(configDir(), "registrar-keys.json");
}

function loadRegistrarKeyPins(): Record<string, RegistrarKeyPin> {
  const path = registrarKeyPinsPath();
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, RegistrarKeyPin>;
}

export function getRegistrarKeyPin(domain: string): RegistrarKeyPin | undefined {
  return loadRegistrarKeyPins()[domain];
}

export function saveRegistrarKeyPin(domain: string, pin: Omit<RegistrarKeyPin, "pinnedAt">): void {
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  const pins = loadRegistrarKeyPins();
  pins[domain] = { ...pin, pinnedAt: new Date().toISOString() };
  writeFileSync(registrarKeyPinsPath(), JSON.stringify(pins, null, 2), { mode: 0o600 });
}
