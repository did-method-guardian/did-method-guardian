import { DEFAULT_GUARDIAN_POLICY } from "./types.js";
import type { Did, LogEntry, ResolvedState } from "./types.js";

/**
 * Replays a full operation log into the current resolved state. Does not
 * itself verify signatures -- callers should validate each operation (see
 * operations.ts) before trusting a log, the same way the spec's own
 * resolution section (§5) separates "replay" from "full validation".
 */
export function replay(did: Did, log: LogEntry[]): ResolvedState {
  if (log.length === 0 || log[0].op.type !== "custodial_create") {
    throw new Error("log must start with a custodial_create operation");
  }

  const genesis = log[0].op;
  const state: ResolvedState = {
    did,
    operationalKeys: [...genesis.operationalKeys],
    verificationMethods: { ...genesis.verificationMethods },
    services: { ...genesis.services },
    guardians: [...genesis.incoming],
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY },
    registrar: genesis.registrar,
    deactivated: false,
  };

  for (const entry of log.slice(1)) {
    const op = entry.op;
    switch (op.type) {
      case "custodial_rotate":
        state.operationalKeys = [...op.operationalKeys];
        state.verificationMethods = { ...op.verificationMethods };
        state.services = { ...op.services };
        break;
      case "guardian_transfer":
        state.guardians = [...op.incoming];
        break;
      case "guardian_relinquish":
        state.guardians = [];
        break;
      case "custodial_tombstone":
        state.deactivated = true;
        break;
      default:
        throw new Error(`unknown operation type in log: ${(op as { type: string }).type}`);
    }
  }

  return state;
}

/** The W3C DID Core document derived from resolved state -- guardians/policy/registrar stay method-internal (spec §3). */
export function toDidDocument(state: ResolvedState) {
  const vmIds = Object.keys(state.verificationMethods).map((id) => `${state.did}#${id}`);
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: state.did,
    verificationMethod: Object.entries(state.verificationMethods).map(([id, key]) => ({
      id: `${state.did}#${id}`,
      type: "Multikey",
      controller: state.did,
      publicKeyMultibase: key,
    })),
    authentication: vmIds,
    assertionMethod: vmIds,
    service: Object.entries(state.services).map(([id, svc]) => ({
      id: `${state.did}#${id}`,
      type: svc.type,
      serviceEndpoint: svc.endpoint,
    })),
    alsoKnownAs: [],
  };
}
