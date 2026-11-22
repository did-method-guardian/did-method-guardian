// Core types for the did:guardian method.
// See website/content/docs/did-guardian-spec-v0.2.0/index.md for the normative definitions these mirror.

/** REQ-4-1: "did:guardian:<domain>" (root) or "did:guardian:<domain>:<name>" (named). */
export type Did = string;

/** REQ-5-8: a P-256 public key, encoded as a Multikey. */
export type Key = string;

/** REQ-6-11: the value of `recovery`, `membership` or `removal`, or the value of `deactivation.threshold`. A given policy member's own allowed-values column (REQ-6-11/REQ-6-12) decides whether "any" is valid for it. */
export type Setting = "any" | "majority" | "all" | number;

/** REQ-6-12: who may approve a `deactivate`. */
export type DeactivationBy = "self" | "guardians" | "either" | "both";

/** REQ-6-12. */
export interface DeactivationPolicy {
  by: DeactivationBy;
  threshold: Setting;
}

/** REQ-6-11: what happens when a `removeGuardian` leaves `guardians` empty (REQ-6-10). */
export type OrphanPolicy = "deactivate" | "independent" | "successor";

/** REQ-6-11: every member is optional; an absent member takes its default (DEFAULT_POLICY). May also contain `extensions` (REQ-5-3). */
export interface Policy {
  recovery?: Setting;
  membership?: Setting;
  removal?: Setting;
  deactivation?: DeactivationPolicy;
  orphan?: OrphanPolicy;
  maxWards?: number;
  extensions?: Record<string, unknown>;
}

/** REQ-6-11's Default column. */
export const DEFAULT_POLICY: Required<Omit<Policy, "maxWards" | "extensions">> = {
  recovery: "majority",
  membership: "majority",
  removal: "majority",
  deactivation: { by: "both", threshold: "majority" },
  orphan: "deactivate",
};

/** REQ-6-2: a guardian or successor entry -- a snapshot of that identity's own log at the time it was recorded. */
export interface Entry {
  did: Did;
  anchor: string;
  keys: Key[];
  consent: string;
}

/** REQ-6-4: a record in `wards`. */
export interface WardRecord {
  did: Did;
  anchor: string;
}

/** REQ-6-6. */
export interface Service {
  id: string;
  type: string;
  serviceEndpoint: string;
}

/** REQ-6-1: the state of an identity. */
export interface State {
  keys: Key[];
  guardians: Entry[];
  successor: Entry | null;
  wards: WardRecord[];
  policy: Policy;
  services: Service[];
  alsoKnownAs: string[];
  deactivated: boolean;
  critical: string[];
}

/**
 * REQ-5-11: exactly these five members. `verificationMethod` is always
 * `did:key:<key>#<key>` for an ordinary proof (REQ-5-14); `attestation`
 * (REQ-7-9) reuses this shape with a looser `cryptosuite` and a
 * `did:guardian:...?versionId=...#key-<n>` verificationMethod instead.
 */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: string;
  verificationMethod: string;
  proofPurpose: "capabilityInvocation";
  proofValue: string;
}

export type OperationType = "create" | "update" | "addGuardian" | "updateGuardian" | "removeGuardian" | "setPolicy" | "acceptWard" | "releaseWard" | "deactivate";

/** REQ-5-3: members every operation type may carry in addition to its own. */
interface ExtensionMembers {
  extensions?: Record<string, unknown>;
}

/** REQ-7-7/REQ-7-8/REQ-7-9. `attestation` is required unless `did` names the root identity. */
export interface CreateOp extends ExtensionMembers {
  type: "create";
  did: Did;
  keys: Key[];
  guardians: Entry[];
  successor: Entry | null;
  policy: Policy;
  services: Service[];
  alsoKnownAs: string[];
  prev: null;
  proof: DataIntegrityProof[];
  attestation?: DataIntegrityProof;
  critical?: string[];
}

/** REQ-7-10/REQ-7-11. */
export interface UpdateOp extends ExtensionMembers {
  type: "update";
  keys: Key[];
  services: Service[];
  alsoKnownAs: string[];
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-12/REQ-7-13/REQ-7-14. */
export interface AddGuardianOp extends ExtensionMembers {
  type: "addGuardian";
  entry: Entry;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-15/REQ-7-16. */
export interface UpdateGuardianOp extends ExtensionMembers {
  type: "updateGuardian";
  guardian: Did;
  keys: Key[];
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-17/REQ-7-18/REQ-7-19. `evidence` is optional. */
export interface RemoveGuardianOp extends ExtensionMembers {
  type: "removeGuardian";
  guardian: Did;
  evidence?: string;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-20/REQ-7-21. */
export interface SetPolicyOp extends ExtensionMembers {
  type: "setPolicy";
  policy: Policy;
  successor: Entry | null;
  prev: string;
  proof: DataIntegrityProof[];
  critical?: string[];
}

/** REQ-7-22/REQ-7-23/REQ-7-24. */
export interface AcceptWardOp extends ExtensionMembers {
  type: "acceptWard";
  ward: WardRecord;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-25/REQ-7-26. */
export interface ReleaseWardOp extends ExtensionMembers {
  type: "releaseWard";
  ward: Did;
  prev: string;
  proof: DataIntegrityProof[];
}

/** REQ-7-27/REQ-7-28. */
export interface DeactivateOp extends ExtensionMembers {
  type: "deactivate";
  prev: string;
  proof: DataIntegrityProof[];
}

export type Operation = CreateOp | UpdateOp | AddGuardianOp | UpdateGuardianOp | RemoveGuardianOp | SetPolicyOp | AcceptWardOp | ReleaseWardOp | DeactivateOp;

/** The ordered list of all operations of an identity (Section 3, "log"). */
export type Log = Operation[];
