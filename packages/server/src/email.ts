import type { Env } from "./env.js";
import { didFor } from "./env.js";
import {
  getWardByName,
  upsertEmailForwarding,
  getEmailForwardingByToken,
  markEmailForwardingVerified,
  getVerifiedForwardingByDid,
  getPendingOperationToken,
  insertPendingOperationToken,
  touchPendingOperationToken,
} from "./db.js";
import { randomSecret } from "./secretBox.js";
import { sendEmail } from "./emailProviders.js";

/**
 * Inbound mail for this registrar's own domain, via Cloudflare Email
 * Routing's `email` binding -- receive-and-forward only (spec: no mailbox
 * storage, no IMAP, this isn't a mail provider). Unknown or unverified
 * recipients are rejected, not silently dropped, so the sending MTA gets a
 * real bounce rather than mail disappearing without a trace.
 */
export async function handleEmail(message: ForwardableEmailMessage, env: Env): Promise<void> {
  const localPart = message.to.split("@")[0];
  const ward = await getWardByName(env, localPart);
  if (!ward) {
    message.setReject(`no such identity "${localPart}" at this registrar`);
    return;
  }
  const forwarding = await getVerifiedForwardingByDid(env, ward.did);
  if (!forwarding) {
    message.setReject(`"${localPart}" has not set up (or verified) mail forwarding`);
    return;
  }
  await message.forward(forwarding.forward_to);
}

/**
 * Starts (or restarts) the double-opt-in verification flow for forwarding
 * `name`'s mail to `forwardTo` -- forwarding stays inactive until the
 * destination address itself confirms it via the emailed link.
 */
export async function requestEmailForwarding(env: Env, name: string, forwardTo: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  const ward = await getWardByName(env, name);
  if (!ward) return { ok: false, reason: `no such identity "${name}"` };

  const token = randomSecret();
  await upsertEmailForwarding(env, { did: ward.did, forward_to: forwardTo, verification_token: token, created_at: new Date().toISOString() });

  const verifyUrl = `https://${env.REGISTRAR_DOMAIN}/verify-email?token=${token}`;
  const result = await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwardTo,
    subject: `Confirm mail forwarding for ${didFor(name, env.REGISTRAR_DOMAIN)}`,
    text: `Someone (hopefully you) asked to forward mail sent to ${name}@${env.REGISTRAR_DOMAIN} to this address.\n\nConfirm: ${verifyUrl}\n\nIf this wasn't you, ignore this message -- forwarding stays off until this link is clicked.`,
  });
  if (!result.ok) {
    return {
      ok: false,
      reason:
        result.status === 0
          ? "this registrar has no email provider configured -- see the registrar operator"
          : `failed to send verification email (status ${result.status})`,
    };
  }
  return { ok: true };
}

export async function confirmEmailForwarding(env: Env, token: string): Promise<{ ok: true; did: string } | { ok: false; reason: string }> {
  const row = await getEmailForwardingByToken(env, token);
  if (!row) return { ok: false, reason: "invalid or already-used verification token" };
  await markEmailForwardingVerified(env, row.did);
  return { ok: true, did: row.did };
}

// --- pending-operation ("voting") notifications ---------------------------
//
// One thread per proposal: every email about the same pending_operation id
// carries the same References/In-Reply-To anchor so clients like Gmail
// group them (Message-ID itself is reserved by MailChannels' own Send API,
// so this is a stable synthetic value, not any real prior message's own
// Message-ID -- threading only needs every email in the thread to agree on
// the same value, not for it to correspond to something that really exists).

function threadHeaders(env: Env, pendingOpId: string): Record<string, string> {
  const anchor = `<pending-op-${pendingOpId}@${env.REGISTRAR_DOMAIN}>`;
  return { References: anchor, "In-Reply-To": anchor };
}

/**
 * The token proving email possession for (pendingOpId, signerDid) -- same
 * trust model as this registrar's own email-verification-link flow above.
 * Issued lazily, the first time this signer is ever notified about this
 * proposal, then reused for every later email about it so earlier links
 * keep working. Always also refreshes last_notified_at, the daily reminder
 * cron's own per-signer clock.
 */
async function getOrIssueToken(env: Env, pendingOpId: string, signerDid: string): Promise<string> {
  const existing = await getPendingOperationToken(env, pendingOpId, signerDid);
  const now = new Date().toISOString();
  if (existing) {
    await touchPendingOperationToken(env, pendingOpId, signerDid, now);
    return existing.token;
  }
  const token = randomSecret();
  await insertPendingOperationToken(env, { pending_op_id: pendingOpId, signer_did: signerDid, token, created_at: now, last_notified_at: now });
  return token;
}

/**
 * One link, to the status page (votingPage.ts) with the token attached --
 * never a link that performs the action itself. A bare GET actions link is
 * a real hazard here: an email client's own security scanner (Safe Links,
 * a corporate proxy, antivirus) prefetches links the instant a message
 * arrives, before anyone reads it -- if that GET itself declined or
 * withdrew, the scanner would be the one voting, not the person it was
 * addressed to. Landing on a page that still needs an explicit button
 * click (a real POST) is the fix.
 */
function voteUrl(env: Env, wardName: string, pendingOpId: string, token: string): string {
  return `https://${env.REGISTRAR_DOMAIN}/.well-known/guardian/${wardName}/pending/${pendingOpId}?token=${token}`;
}

const ACTION_LINKS_BLURB = (link: string) =>
  `Review or change your mind: ${link}\n` +
  `This page lets you sign (if you're signed in as a required signer), veto (blocks it outright, no matter how many others approve), or withdraw (just stop waiting on you -- doesn't block anyone else) -- it works until this is no longer pending; once it finalizes, declines, or expires, there's no undo.`;

/** A signer's own signature is needed -- sent once, when a proposal is created or when it's still collecting and this signer hasn't contributed yet. */
export async function notifyAwaitingSignature(env: Env, wardName: string, signerDid: string, pendingOpId: string, opType: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, signerDid);
  if (!forwarding) return;
  const token = await getOrIssueToken(env, pendingOpId, signerDid);
  const link = voteUrl(env, wardName, pendingOpId, token);
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Your signature is requested: ${opType}`,
    text:
      `A ${opType} operation is waiting on your signature as ${signerDid}.\n\nPending operation id: ${pendingOpId}\n\n` +
      `Use your client to review and contribute your signature.\n\n${ACTION_LINKS_BLURB(link)}\n\n` +
      `If nobody completes this, it expires on its own -- it never passes automatically.`,
    headers: threadHeaders(env, pendingOpId),
  });
}

/** Confirms a signature was recorded, and gives the signer a way to change their mind while this is still pending. */
export async function notifyVoteRecorded(env: Env, wardName: string, signerDid: string, pendingOpId: string, opType: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, signerDid);
  if (!forwarding) return;
  const token = await getOrIssueToken(env, pendingOpId, signerDid);
  const link = voteUrl(env, wardName, pendingOpId, token);
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Your signature was recorded: ${opType}`,
    text: `Your signature as ${signerDid} was recorded for the ${opType} operation (id ${pendingOpId}).\n\n${ACTION_LINKS_BLURB(link)}`,
    headers: threadHeaders(env, pendingOpId),
  });
}

/** Someone else contributed, but the threshold isn't met yet -- tells a still-needed signer they're still being waited on. */
export async function notifyProgress(env: Env, wardName: string, recipientDid: string, pendingOpId: string, opType: string, actorDid: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, recipientDid);
  if (!forwarding) return;
  const token = await getOrIssueToken(env, pendingOpId, recipientDid);
  const link = voteUrl(env, wardName, pendingOpId, token);
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Still waiting on your signature: ${opType}`,
    text:
      `${actorDid} just signed the ${opType} operation (id ${pendingOpId}), but it still needs your own signature as ${recipientDid}.\n\n` +
      `${ACTION_LINKS_BLURB(link)}`,
    headers: threadHeaders(env, pendingOpId),
  });
}

/** A current guardian vetoed the proposal -- notifies everyone else who was involved that it's dead, no undo. */
export async function notifyDeclined(env: Env, _wardName: string, recipientDid: string, pendingOpId: string, opType: string, actorDid: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, recipientDid);
  if (!forwarding) return;
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Declined: ${opType}`,
    text: `${actorDid} declined (vetoed) the ${opType} operation (id ${pendingOpId}). It will not proceed -- a decline blocks it outright, regardless of how many others had already signed.`,
    headers: threadHeaders(env, pendingOpId),
  });
}

/** A signer withdrew (opted out, not a veto) -- tells the others not to wait on that one person, without implying anything is blocked. */
export async function notifyWithdrawn(env: Env, wardName: string, recipientDid: string, pendingOpId: string, opType: string, actorDid: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, recipientDid);
  if (!forwarding) return;
  const token = await getOrIssueToken(env, pendingOpId, recipientDid);
  const link = voteUrl(env, wardName, pendingOpId, token);
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Update: ${opType}`,
    text:
      `${actorDid} withdrew from the ${opType} operation (id ${pendingOpId}) -- they're opting out, not blocking it. It's still pending.\n\n` +
      `${ACTION_LINKS_BLURB(link)}`,
    headers: threadHeaders(env, pendingOpId),
  });
}

/** It passed and is now part of the log. */
export async function notifyFinalized(env: Env, _wardName: string, recipientDid: string, pendingOpId: string, opType: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, recipientDid);
  if (!forwarding) return;
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Finalized: ${opType}`,
    text: `The ${opType} operation (id ${pendingOpId}) collected enough signatures and is now part of the permanent record. No further action is needed.`,
    headers: threadHeaders(env, pendingOpId),
  });
}

/**
 * Daily reminder for a signer who hasn't yet acted on a still-collecting
 * proposal -- plain-language consequences, since expiry only ever means
 * failure (never an automatic pass): if you do nothing, this fails once it
 * expires. The reminder cron (index.ts's own scheduled handler) is what
 * calls this, gated on this signer's own last_notified_at being stale.
 */
export async function notifyReminder(env: Env, wardName: string, signerDid: string, pendingOpId: string, opType: string, expiresAt: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, signerDid);
  if (!forwarding) return;
  const token = await getOrIssueToken(env, pendingOpId, signerDid);
  const link = voteUrl(env, wardName, pendingOpId, token);
  await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Reminder: your signature is still needed: ${opType}`,
    text:
      `This is a reminder -- the ${opType} operation (id ${pendingOpId}) is still waiting on your signature as ${signerDid}.\n\n` +
      `If nobody completes this by ${expiresAt}, it simply expires and fails -- it does not pass automatically, and does not need your signature to fail safely. Doing nothing is a safe default if you don't want this to happen.\n\n` +
      `${ACTION_LINKS_BLURB(link)}`,
    headers: threadHeaders(env, pendingOpId),
  });
}
