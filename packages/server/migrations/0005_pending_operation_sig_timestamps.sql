-- REQ-4-2's own point-in-time guardian key resolution needs to know WHEN
-- this registrar actually collected each signer's own signature, not just
-- what it is -- a signature collected asynchronously (pending_operations
-- can stay open for days) must still verify against whichever key its own
-- signer held at that moment, even if that signer has since rotated. See
-- registrar.ts's makeExternalResolver and rules.ts's
-- VerificationContext.sigTimestamps.

ALTER TABLE pending_operations ADD COLUMN sig_timestamps TEXT NOT NULL DEFAULT '{}';
