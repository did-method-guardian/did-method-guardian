import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { checkAcceptance, parseGuardianDid, type PinRecord, type PinStore, type RequestContext } from "../src/index.js";
import { MIN_KEYS_EXTENSION } from "../src/testExtensions.js";
import type { Did, Log, LogResolver, Operation } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "cleanroom", "vectors-final");

interface RegistrarVector {
  kind?: "registrar" | "resolve";
  description: string;
  did: Did;
  log: Log;
  op: Operation;
  resolver?: Record<string, Log | null>;
  expect: { result: "accepted" | "rejected" };
  targets: string;
  implemented?: string[];
  segment?: string;
  registrarDomain?: string;
  acceptedCreates?: string[];
  rejectedCreates?: string[];
  pins?: Record<string, [string, string]>;
  request?: { authenticatedAs: Did | null; registrarProofs: Did[] };
}

/** A plain in-memory PinStore, pre-seeded from the vector's own `pins` field (REQ-11-3's own shape: {anchor, version}, here given as the [anchor, version] tuple the README documents). */
function pinStoreFrom(pins: Record<string, [string, string]> | undefined): PinStore {
  const seeded = new Map<Did, PinRecord>();
  for (const [did, [anchor, version]] of Object.entries(pins ?? {})) seeded.set(did as Did, { anchor, version });
  return {
    get: (did) => seeded.get(did),
    set: (did, record) => {
      seeded.set(did, record);
    },
  };
}

/** The path segment a DID implies on its own, used for the two registrar-level checks (domain, root) that live outside lib's own checkAcceptance (registrar.ts owns both there, same split this harness mirrors). */
function segmentOf(did: Did): string | undefined {
  const parsed = parseGuardianDid(did);
  return parsed ? parsed.name ?? "_" : undefined;
}

for (const file of fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))) {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, file), "utf-8")) as RegistrarVector;
  if (vector.kind !== "registrar") continue;

  test(`registrar vector ${file}: ${vector.description}`, async () => {
    const resolver = vector.resolver ?? {};
    const resolveLog: LogResolver = (did) => (Object.prototype.hasOwnProperty.call(resolver, did) ? resolver[did] : undefined);
    // The README's documented default is the toy extension; a vector
    // sets `implemented` explicitly (e.g. `[]`) to simulate a different
    // registrar's own capability set.
    const implemented = new Set(vector.implemented ?? [MIN_KEYS_EXTENSION]);
    const segment = vector.segment ?? segmentOf(vector.did);

    // Two checks that live on the server side of this project's own
    // split (registrar.ts), not inside lib's checkAcceptance: REQ-10-9's
    // domain match, and REQ-10-10's root-create rejection. Both are
    // mechanical enough to mirror directly here rather than re-import
    // server code into a lib test.
    if (vector.op.type === "create" && vector.log.length === 0) {
      const parsed = parseGuardianDid(vector.did);
      const isRoot = parsed !== undefined && parsed.name === null;
      if (isRoot) {
        assert.equal(vector.expect.result, "rejected", `${file} [${vector.targets}]: a create of the root identity is never accepted through REQ-10-1`);
        return;
      }
      if (vector.registrarDomain !== undefined && parsed && parsed.domain !== vector.registrarDomain) {
        assert.equal(vector.expect.result, "rejected", `${file} [${vector.targets}]: REQ-10-9 -- the DID's domain is not this registrar's own domain`);
        return;
      }
    }

    const r = await checkAcceptance(vector.did, vector.log, vector.op, resolveLog, implemented, {
      segment,
      acceptedNames: vector.acceptedCreates ? new Set(vector.acceptedCreates) : undefined,
      pinStore: vector.pins ? pinStoreFrom(vector.pins) : undefined,
      request: vector.request as RequestContext | undefined,
    });
    const expected = vector.expect.result === "accepted";
    assert.equal(r.accepted, expected, `${file} [${vector.targets}]: ${r.reason ?? ""}`);
  });
}
