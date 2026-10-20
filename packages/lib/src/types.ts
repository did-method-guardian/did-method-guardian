// Core types for the did:guardian method.
// See website/content/spec/v1/index.md for the full specification these mirror.

export type Did = string; // "did:guardian:<domain>" (bare) or "did:guardian:<name>:<domain>" (named) -- domain is dot-joined, never colon-joined (see spec §2)

/** One of the four consensus thresholds a GuardianPolicy knob may be set to. */
export type Threshold = "any" | "majority" | "unanimous" | { at_least: number };

export interface GuardianPolicy {
  recovery_threshold: Threshold;
  tombstone_threshold: Threshold;
  removal_threshold: Threshold;
  policy_threshold: Threshold;
}

export const DEFAULT_GUARDIAN_POLICY: GuardianPolicy = {
  recovery_threshold: "any",
  tombstone_threshold: "any",
  removal_threshold: "majority",
  policy_threshold: "majority",
};

export interface RegistrarAttestation {
  did: Did;
  sig: string;
}

export interface CustodialCreateOp {
  type: "custodial_create";
  name: string | null; // null for the bare-domain (nameless) identity -- see spec §2.1
  operationalKeys: string[];
  verificationMethods: Record<string, string>;
  services: Record<string, { type: string; endpoint: string }>;
  registrar?: RegistrarAttestation;
  outgoing: []; // always empty at genesis -- nothing to remove
  incoming: Did[]; // initial guardian set, may be empty
  prev: null;
  sigs: Record<Did, string>; // one per `incoming` entry
}

export interface CustodialRotateOp {
  type: "custodial_rotate";
  operationalKeys: string[];
  verificationMethods: Record<string, string>;
  services: Record<string, { type: string; endpoint: string }>;
  prev: string;
  sig: string; // signed by any current operational key
}

export interface GuardianTransferOp {
  type: "guardian_transfer";
  outgoing: Did[];
  incoming: Did[];
  prev: string;
  sigs: Record<Did, string>;
}

export interface GuardianRelinquishOp {
  type: "guardian_relinquish";
  prev: string;
  sigs: Record<Did, string>;
}

export interface CustodialTombstoneOp {
  type: "custodial_tombstone";
  prev: string;
  sigs: Record<Did, string>;
}

export type Operation =
  | CustodialCreateOp
  | CustodialRotateOp
  | GuardianTransferOp
  | GuardianRelinquishOp
  | CustodialTombstoneOp;

export interface LogEntry {
  cid: string;
  op: Operation;
}

/** The method-internal state derived by replaying a log -- a superset of the presented DID Document. */
export interface ResolvedState {
  did: Did;
  operationalKeys: string[];
  verificationMethods: Record<string, string>;
  services: Record<string, { type: string; endpoint: string }>;
  guardians: Did[];
  guardianPolicy: GuardianPolicy;
  registrar?: RegistrarAttestation;
  deactivated: boolean;
}
