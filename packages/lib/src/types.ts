// Core types for the did:guardian method.
// See website/content/docs/did-guardian-spec-v0.2.0/index.md for the full specification these mirror.

export type Did = string; // "did:guardian:<domain>" (bare) or "did:guardian:<domain>:<name>" (named, domain-first -- matches did:web's own convention) -- domain is dot-joined, never colon-joined (see spec §2)

/** One of the four consensus thresholds a GuardianPolicy knob may be set to. */
export type Threshold = "any" | "majority" | "unanimous" | { at_least: number };

/** Formal spec §5, REQ-5-8: a ward's own standing preference if its guardian set ever becomes empty other than via guardian_relinquish. */
export type OnOrphanPolicy = "sovereign" | "tombstone" | { transfer_to: Did };

export interface GuardianPolicy {
  /**
   * v0.4, Fix 6: a verifier that doesn't recognize this version number
   * MUST report that it can't fully verify state governed by this
   * policy, never silently accept it as if every field it understands
   * were the complete picture. "Ignore unknown fields" (this field's own
   * earlier, now-superseded version) is safe for additive fields but not
   * for a *restrictive* one -- a future `witness_threshold` an old
   * verifier doesn't recognize would otherwise accept an operation the
   * policy actually forbids, a real downgrade. Starts at 1; bump it only
   * when a new field can change whether an operation is accepted, never
   * for a field that's purely informational.
   */
  version: number;
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

/** The highest GuardianPolicy.version this library understands -- see its own doc comment (Fix 6). */
export const MAX_SUPPORTED_POLICY_VERSION = 1;

export const DEFAULT_GUARDIAN_POLICY: GuardianPolicy = {
  version: 1,
  recovery_threshold: "any",
  tombstone_threshold: "any",
  removal_threshold: "majority",
  addition_threshold: "majority",
  policy_threshold: "majority",
  min_guardian_count: 0,
  on_orphan: "sovereign",
};

/**
 * v0.4, Fix 5: a W3C Data Integrity proof (ecdsa-jcs-2019 cryptosuite --
 * see operations.ts's createProof/verifyProof for the exact signing
 * input construction, checked directly against the W3C specs rather
 * than assumed). Replaces the old, separate sig/sigs/keySigs/registrar
 * fields every operation type carried before this version -- one proof
 * array, every signer (the declaring party proving key possession, the
 * ward, a guardian, the accepting registrar) contributing one entry,
 * all independent, all covering the same content (the operation with
 * `proof` itself stripped), none nested in signing order. `created` on
 * the registrar's own attestation entry doubles as the signed
 * acceptance timestamp this method previously had no signed record of
 * at all.
 */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "ecdsa-jcs-2019";
  /**
   * A DID URL identifying both who signed and how to resolve their key:
   * `did:key:<multikey>#<multikey>` (self-contained, no resolution --
   * REQ-7.1-8/7.2-12's proof of possession for a declared operational
   * key) or a `did:guardian:...#key-N` DID URL (the ward's own current
   * key, a guardian's, or the accepting registrar's -- resolved live,
   * same as every other signature this method ever checked).
   */
  verificationMethod: string;
  proofPurpose: "assertionMethod";
  created: string; // ISO 8601
  proofValue: string; // multibase base58btc (REQ-6-4), raw P-256 r||s, low-S
}

export interface CustodialCreateOp {
  type: "custodial_create";
  /** v0.4, Fix 2: the full DID this genesis is for, domain included. A registrar MUST reject a genesis whose `did` doesn't match `didFor(name, its own domain)` -- without this, a publicly-visible, already-accepted genesis (keys, keySigs-equivalent proofs, and any guardian consents, all still verifying) could be replayed verbatim at a second registrar under the same free name, becoming a second, distinct identity nobody who signed the original ever intended. */
  did: Did;
  name: string | null; // null for the bare-domain (nameless) identity -- see spec §2.1
  operationalKeys: string[]; // Multikey (Fix 4) -- one verificationMethod entry per entry, derived directly, index-matched (REQ-3-1); there is no separate map to fall out of sync with it (Fix 1)
  services: Record<string, { type: string; endpoint: string }>;
  outgoing: []; // always empty at genesis -- nothing to remove
  incoming: Did[]; // v0.3 (REQ-7.1-1 relaxed): MAY be non-empty if each named DID co-signs genesis (a proof in `proof`, verificationMethod = that DID's own DID URL) -- runtime-checked, not type-narrowed
  prev: null;
  proof: DataIntegrityProof[];
  /** v0.2, REQ-7.1-4: optional at the type level (a wire payload can omit it); required at the rules-engine level -- see rules.ts. */
  creator?: Did;
  /** v0.2, REQ-7.1-7. */
  policy?: Partial<GuardianPolicy>;
}

export interface CustodialRotateOp {
  type: "custodial_rotate";
  operationalKeys: string[]; // Multikey -- see CustodialCreateOp's own comment
  services: Record<string, { type: string; endpoint: string }>;
  prev: string;
  proof: DataIntegrityProof[]; // REQ-7.2-12's proof of possession for each new key, plus either the ward's own current-key proof (REQ-7.2-1a) or enough guardians' (REQ-7.2-1b)
}

/** v0.2. Adds exactly one new guardian -- REQ-7.2-3/4/5. */
export interface GuardianAddOp {
  type: "guardian_add";
  incoming: Did;
  prev: string;
  proof: DataIntegrityProof[];
  /** REQ-12-4, v0.2.1: incoming's genesis CID, so a later L1 check of this specific guardian relationship has something to pin against without a fresh L3 resolution. RECOMMENDED (SHOULD), not required -- a verifier MUST still accept a guardian_add with no anchor, same as any other optional field. */
  anchor?: string;
}

/** v0.2. Removes exactly one current guardian -- REQ-7.2-6/7. */
export interface GuardianRemoveOp {
  type: "guardian_remove";
  outgoing: Did;
  prev: string;
  proof: DataIntegrityProof[];
}

/** v0.2. Replaces GuardianPolicy wholesale -- REQ-7.2-9/10. */
export interface PolicyUpdateOp {
  type: "policy_update";
  policy: GuardianPolicy;
  prev: string;
  proof: DataIntegrityProof[];
}

/** v0.1, superseded by GuardianAddOp/GuardianRemoveOp for new submissions -- kept only so document.ts's replay() can still resolve already-accepted history under the old shape. Never produced or accepted for a new operation, so this keeps its original sig field untouched by the proof-model migration. */
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
  proof: DataIntegrityProof[];
}

export interface CustodialTombstoneOp {
  type: "custodial_tombstone";
  prev: string;
  proof: DataIntegrityProof[];
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
  operationalKeys: string[]; // Multikey -- the presented document's verificationMethod entries derive from this directly (Fix 1), no separate map
  services: Record<string, { type: string; endpoint: string }>;
  guardians: Did[];
  guardianPolicy: GuardianPolicy;
  /** The DID that attested genesis (REQ-7.1-5's registrar proof entry), for L1 anchor/registrar-key pinning -- the attestation itself lives in genesis's own `proof` array within the log, not duplicated here. */
  registrarDid?: Did;
  deactivated: boolean;
}
