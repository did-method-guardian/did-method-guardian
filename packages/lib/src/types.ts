// Core types for the did:guardian method.
// See website/content/docs/did-guardian-spec-v0.2.0/index.md for the normative definitions these mirror.

/** REQ-4-1: "did:guardian:<domain>" (root) or "did:guardian:<domain>:<name>" (named). */
export type Did = string;

/** REQ-5-7: a P-256 public key, encoded as a Multikey. */
export type Key = string;

/** REQ-6-4: the value of `recovery`, `membership` or `removal`, or the value of `deactivation.threshold`. A given policy member's own allowed-values column (REQ-6-4/REQ-6-5) decides whether "any" is valid for it; this type covers every value any of them accepts. */
export type Setting = "any" | "majority" | "all" | number;

/** REQ-6-5: who may approve a `deactivate` operation. */
export type DeactivationBy = "self" | "guardians" | "either" | "both";

/** REQ-6-5. */
export interface DeactivationPolicy {
  by: DeactivationBy;
  threshold: Setting;
}

/** REQ-6-4: every member is optional; an absent member takes its default (DEFAULT_POLICY). */
export interface Policy {
  recovery?: Setting;
  membership?: Setting;
  removal?: Setting;
  deactivation?: DeactivationPolicy;
}

/** REQ-6-4's Default column. */
export const DEFAULT_POLICY: Required<Policy> = {
  recovery: "majority",
  membership: "majority",
  removal: "majority",
  deactivation: { by: "both", threshold: "majority" },
};

/** REQ-6-2. */
export interface Service {
  id: string;
  type: string;
  serviceEndpoint: string;
}

/** REQ-6-1: the state of an identity. */
export interface State {
  keys: Key[];
  guardians: Did[];
  policy: Policy;
  services: Service[];
  alsoKnownAs: string[];
  deactivated: boolean;
}

/** REQ-5-9: exactly these five members, no `created`. */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "ecdsa-jcs-2019";
  verificationMethod: string;
  proofPurpose: "capabilityInvocation";
  proofValue: string;
}

export type OperationType = "create" | "update" | "addGuardian" | "removeGuardian" | "setPolicy" | "deactivate";

/** REQ-7-5/REQ-7-6. */
export interface CreateOp {
  type: "create";
  did: Did;
  keys: Key[];
  guardians: Did[];
  policy: Policy;
  services: Service[];
  alsoKnownAs: string[];
  prev: null;
  proof: DataIntegrityProof[];
}

/** REQ-7-7/REQ-7-8. */
export interface UpdateOp {
  type: "update";
  keys: Key[];
  services: Service[];
  alsoKnownAs: string[];
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-9/REQ-7-11. */
export interface AddGuardianOp {
  type: "addGuardian";
  guardian: Did;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-12/REQ-7-14/REQ-7-15. `evidence` is optional (REQ-7-12). */
export interface RemoveGuardianOp {
  type: "removeGuardian";
  guardian: Did;
  evidence?: string;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-16/REQ-7-17. */
export interface SetPolicyOp {
  type: "setPolicy";
  policy: Policy;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-18/REQ-7-19. */
export interface DeactivateOp {
  type: "deactivate";
  prev: string;
  proof: DataIntegrityProof[];
}

export type Operation = CreateOp | UpdateOp | AddGuardianOp | RemoveGuardianOp | SetPolicyOp | DeactivateOp;

/** The ordered list of all operations of an identity (Section 3, "log"). */
export type Log = Operation[];

/** REQ-8-1 step 5: resolves the log of another DID, for a proof's DID reference (REQ-5-12) or `removeGuardian`'s `evidence` (REQ-7-14). Returns `undefined` if the log cannot be retrieved (REQ-8-4). */
export type LogResolver = (did: Did) => Promise<Log | undefined> | Log | undefined;
