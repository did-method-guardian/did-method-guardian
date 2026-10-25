// Core types for the did:guardian method.
// See website/content/spec/v1/index.md for the full specification these mirror.

export type Did = string; // "did:guardian:<domain>" (bare) or "did:guardian:<name>:<domain>" (named) -- domain is dot-joined, never colon-joined (see spec §2)

/** One of the four consensus thresholds a GuardianPolicy knob may be set to. */
export type Threshold = "any" | "majority" | "unanimous" | { at_least: number };

/** Formal spec §5, REQ-5-8: a ward's own standing preference if its guardian set ever becomes empty other than via guardian_relinquish. */
export type OnOrphanPolicy = "sovereign" | "tombstone" | { transfer_to: Did };

export interface GuardianPolicy {
  recovery_threshold: Threshold;
  tombstone_threshold: Threshold;
  removal_threshold: Threshold;
  /** REQ-5-5: governs guardian_add. New in v0.2 -- guardian_transfer's old implicit "no committee approval needed to join" bug is what this field closes. */
  addition_threshold: Threshold;
  policy_threshold: Threshold;
  /** REQ-5-7: non-negative, 0 = no minimum. Enforced on guardian_remove only, never guardian_relinquish. */
  min_guardian_count: number;
  /** REQ-5-8. Declarative only -- see the formal spec's own note on which values a pure verification function can act on. */
  on_orphan: OnOrphanPolicy;
}

export const DEFAULT_GUARDIAN_POLICY: GuardianPolicy = {
  recovery_threshold: "any",
  tombstone_threshold: "any",
  removal_threshold: "majority",
  addition_threshold: "majority",
  policy_threshold: "majority",
  min_guardian_count: 0,
  on_orphan: "sovereign",
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
  incoming: Did[]; // v0.2 (REQ-7.1-1): MUST be `[]` -- runtime-checked, not type-narrowed, since this is exactly the shape a malformed/pre-v0.2 submission needs to be rejected rather than excluded from the type
  prev: null;
  sigs: Record<Did, string>; // one per `incoming` entry -- always `{}` once REQ-7.1-1 is enforced
  /** v0.2, REQ-7.1-4: optional at the type level (a wire payload can omit it); required at the rules-engine level -- see rules.ts. */
  creator?: Did;
  /** v0.2, REQ-7.1-7. */
  policy?: Partial<GuardianPolicy>;
}

export interface CustodialRotateOp {
  type: "custodial_rotate";
  operationalKeys: string[];
  verificationMethods: Record<string, string>;
  services: Record<string, { type: string; endpoint: string }>;
  prev: string;
  sig?: string; // signed by any current operational key -- REQ-7.2-1(a)
  /** v0.2, REQ-7.2-1(b): guardian-initiated recovery rotation, keyed by guardian DID. Mutually exclusive with `sig` in practice, both optional at the type level so either shape is constructible. */
  sigs?: Record<Did, string>;
}

/** v0.2. Adds exactly one new guardian -- REQ-7.2-3/4/5. */
export interface GuardianAddOp {
  type: "guardian_add";
  incoming: Did;
  prev: string;
  sigs: Record<Did, string>;
}

/** v0.2. Removes exactly one current guardian -- REQ-7.2-6/7. */
export interface GuardianRemoveOp {
  type: "guardian_remove";
  outgoing: Did;
  prev: string;
  sigs: Record<Did, string>;
}

/** v0.2. Replaces GuardianPolicy wholesale -- REQ-7.2-9/10. */
export interface PolicyUpdateOp {
  type: "policy_update";
  policy: GuardianPolicy;
  prev: string;
  sigs: Record<Did, string>;
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
  | GuardianTransferOp // v0.1, superseded by GuardianAddOp/GuardianRemoveOp -- kept until task #107 removes it and its callers
  | GuardianAddOp
  | GuardianRemoveOp
  | GuardianRelinquishOp
  | PolicyUpdateOp
  | CustodialTombstoneOp;

export interface LogEntry {
  cid: string;
  op: Operation;
  /** When a registrar accepted this operation -- REQ-6-8/6-9's nullification window is evaluated against this. Optional: a verifier replaying a bare log with no registrar-side acceptance metadata can still resolve state; it just can't itself originate a new nullification. */
  acceptedAt?: string;
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
