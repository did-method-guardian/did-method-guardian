// F-12 (audit): the toy extension used to be exported from operations.ts
// and re-exported through index.ts, so it was part of @did-guardian/lib's
// public API -- any consumer could import MIN_KEYS_EXTENSION and mistake
// it for a real, officially-supported extension. It lives in its own,
// deliberately NOT-re-exported-from-index module instead; tests (the
// only legitimate user) import it directly from this file.
import { hasExactMembers, invalid, isPlainObject, VALID, type ShapeResult } from "./operations.js";
import type { Key } from "./types.js";

/**
 * REQ-7-29/REQ-7-33 through 7-35/REQ-8-1: a toy extension, for
 * conformance testing only (README: "the toy extension"). It is not
 * part of the did:guardian method, and production code never
 * implements it -- `verifyLog`/`resolve`/`checkAcceptance` all default
 * to implementing no extensions at all; a caller opts into this one by
 * passing `new Set([MIN_KEYS_EXTENSION])` explicitly, which only tests
 * do.
 */
export const MIN_KEYS_EXTENSION = "https://example.org/ext/min-keys";

/**
 * The toy extension's own rule (REQ-7-33/7-35), checked against a state
 * once `MIN_KEYS_EXTENSION` is in its `critical` (REQ-7-31): the state
 * MUST have at least `k` keys, and removing the configuration is
 * invalid -- so the configuration must still be present, shaped
 * `{"k": <integer 1-8>}`.
 */
export function checkMinKeysExtension(state: { critical: string[]; policy: { extensions?: Record<string, unknown> }; keys: Key[] }): ShapeResult {
  if (!state.critical.includes(MIN_KEYS_EXTENSION)) return VALID;
  const config = state.policy.extensions?.[MIN_KEYS_EXTENSION];
  if (config === undefined) return invalid(`REQ-7-35: ${MIN_KEYS_EXTENSION} -- removing the configuration is invalid`);
  if (!isPlainObject(config) || !hasExactMembers(config, ["k"]) || typeof config.k !== "number" || !Number.isInteger(config.k) || config.k < 1 || config.k > 8) {
    return invalid(`REQ-7-29: ${MIN_KEYS_EXTENSION} configuration must be {"k": <integer 1-8>}`);
  }
  if (state.keys.length < config.k) return invalid(`REQ-7-33: ${MIN_KEYS_EXTENSION} requires at least ${config.k} keys`);
  return VALID;
}
