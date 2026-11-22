// The account dashboard -- a real page where a person can log in and
// actually see and manage their own identity (activity, guardians,
// connected apps, roll their key, deactivate the account), rather than
// only ever being reachable through a relying party's own API calls.
//
// Session-gated only (gw_session) -- no trusted-client bypass. This page
// is the human looking at their own account directly, not a platform
// acting for them.

import type { Env } from "./env.js";
import { safeFormData } from "./http.js";
import { html, escapeHtml, pageShell, secretBox, policyTable } from "./htmlPage.js";
import type { PolicyField } from "./htmlPage.js";
import { readCookie, resolveSession } from "./login.js";
import { rotateHeldKey, deactivateSelf, reissueLoginSecret } from "./profile.js";
import { RegistrarError } from "./registrarError.js";
import { listPendingForDid } from "./pendingProofs.js";
import { requestEmailForwarding } from "./email.js";
import { getLogWithTimestamps, getNameEntryByDid, getVerifiedForwardingByDid, listOidcConsentsForWard, deleteOidcConsent, revokeRefreshTokensForWardAndClient } from "./db.js";
import { verifyLog, DEFAULT_POLICY, type Did, type Entry, type Operation, type Policy, type Setting, type State } from "@did-guardian/lib";
import { getLog } from "./db.js";

const SESSION_COOKIE = "gw_session";

async function requireSession(request: Request, env: Env): Promise<{ wardDid: Did; name: string } | Response> {
  const sessionId = readCookie(request, SESSION_COOKIE);
  const wardDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!wardDid) {
    return new Response(null, { status: 302, headers: { location: `/guardian-login?return_to=${encodeURIComponent("/account")}` } });
  }
  const nameEntry = await getNameEntryByDid(env, wardDid);
  return { wardDid: wardDid as Did, name: nameEntry?.name ?? "" };
}

/** names' own "" sentinel for root; every URL this page builds uses "_" instead, the same convention the rest of this registrar follows. */
function urlName(name: string): string {
  return name === "" ? "_" : name;
}

function opSummary(op: Operation): string {
  switch (op.type) {
    case "create":
      return "Identity created";
    case "update":
      return "Key rotated or profile updated";
    case "addGuardian":
      return `Guardian added: ${escapeHtml(op.entry.did)}`;
    case "updateGuardian":
      return `Guardian re-seated: ${escapeHtml(op.guardian)}`;
    case "removeGuardian":
      return `Guardian removed: ${escapeHtml(op.guardian)}`;
    case "setPolicy":
      return "Policy updated";
    case "acceptWard":
      return `Accepted ${escapeHtml(op.ward.did)} as a ward`;
    case "releaseWard":
      return `Released ${escapeHtml(op.ward)} as a ward`;
    case "deactivate":
      return "Identity deactivated";
    default:
      return escapeHtml((op as { type: string }).type);
  }
}

function banner(message: string | null, kind: "ok" | "error" = "ok"): string {
  if (!message) return "";
  return `<p class="${kind === "error" ? "error" : "hint"}">${escapeHtml(message)}</p>`;
}

// The canonical formal spec lives on this project's own docs site, not
// necessarily on whichever domain happens to be serving this particular
// registrar (zzmq.dev doesn't host the docs site at all) -- always link to
// the one real copy.
const FORMAL_SPEC_URL = "https://guardianspec.org/docs/did-guardian-spec-v0.2.0/";

function formatSetting(value: Setting): string {
  if (typeof value === "number") return `exactly ${value}`;
  if (value === "any") return "any one guardian";
  return value;
}

/** §6.11: a structured table instead of a bare JSON dump, each row linking to the exact requirement it governs. */
function policySection(policy: Policy): string {
  const effective = { ...DEFAULT_POLICY, ...policy };
  const fields: PolicyField[] = [
    { label: "Recovery (lost-key rotation)", value: formatSetting(effective.recovery), reqAnchor: "req-6-12" },
    { label: "Adding a guardian", value: formatSetting(effective.membership), reqAnchor: "req-6-12" },
    { label: "Removing a guardian", value: formatSetting(effective.removal), reqAnchor: "req-6-12" },
    { label: "Deactivation", value: `${effective.deactivation.by}, ${formatSetting(effective.deactivation.threshold)}`, reqAnchor: "req-6-13" },
    { label: "If orphaned", value: effective.orphan, reqAnchor: "req-6-14" },
    { label: "Maximum wards", value: policy.maxWards === undefined ? "none" : String(policy.maxWards), reqAnchor: "req-6-15" },
  ];
  return policyTable(fields, FORMAL_SPEC_URL);
}

function guardiansList(state: State): string {
  const entries: Array<{ did: string; role: string }> = [...state.guardians.map((g: Entry) => ({ did: g.did, role: "guardian" }))];
  if (state.successor) entries.push({ did: state.successor.did, role: "successor" });
  if (entries.length === 0) return `<p class="hint">No guardians -- fully self-governing.</p>`;
  return `<ul class="signers">${entries.map((e) => `<li>${escapeHtml(e.did)} <span class="hint">(${e.role})</span></li>`).join("")}</ul>`;
}

export async function handleAccountPage(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const { wardDid, name } = session;
  const urlSegment = urlName(name);
  const url = new URL(request.url);
  const message = url.searchParams.get("message");
  const messageKind = url.searchParams.get("kind") === "error" ? "error" : "ok";

  const log = await getLog(env, wardDid);
  if (log.length === 0) return html(pageShell("Error", `<h1>Error</h1><p class="error">Could not find this identity's own log.</p>`), 500);
  const verified = await verifyLog(wardDid, log);
  if (verified.result !== "valid") return html(pageShell("Error", `<h1>Error</h1><p class="error">Could not resolve this identity's own state.</p>`), 500);
  const state = verified.state!;

  const logWithTimestamps = await getLogWithTimestamps(env, wardDid);
  const forwarding = await getVerifiedForwardingByDid(env, wardDid);
  const pending = await listPendingForDid(env, wardDid);
  const consents = await listOidcConsentsForWard(env, wardDid);

  const pendingList = pending.length
    ? `<ul class="signers">${pending
        .map((p) => `<li>${escapeHtml((p.operation as { type: string }).type)} -- <a href="/.well-known/guardian/pending/${p.id}">review and sign</a></li>`)
        .join("")}</ul>`
    : `<p class="hint">Nothing waiting on your own signature right now.</p>`;

  const consentsList = consents.length
    ? `<ul class="signers">${consents
        .map(
          (c) =>
            `<li>${escapeHtml(c.client_name)} <span class="hint">(granted ${escapeHtml(c.granted_at)})</span>
              <form method="post" action="/account/consents/revoke" class="inline"><input type="hidden" name="client_id" value="${escapeHtml(c.client_id)}"><button type="submit" class="danger">Revoke access</button></form></li>`,
        )
        .join("")}</ul>`
    : `<p class="hint">No connected apps.</p>`;

  const activityList = [...logWithTimestamps]
    .reverse()
    .map((entry) => `<li>${opSummary(entry.operation)} <span class="hint">${escapeHtml(entry.acceptedAt)}</span></li>`)
    .join("");

  const body = `
    <h1>Your account</h1>
    <p class="hint">${escapeHtml(wardDid)}</p>
    <form method="post" action="/guardian-logout" class="inline"><button type="submit" class="neutral">Log out</button></form>
    ${banner(message ?? null, messageKind)}
    <dl>
      <dt>Status</dt><dd><span class="state">${state.deactivated ? "Deactivated" : "Active"}</span></dd>
      <dt>Guardians</dt><dd>${guardiansList(state)}</dd>
      <dt>Policy</dt><dd>${policySection(state.policy)}</dd>
      <dt>Needs your signature</dt><dd>${pendingList}</dd>
      <dt>Connected apps</dt><dd>${consentsList}</dd>
      <dt>Activity</dt><dd><ul class="signers">${activityList}</ul></dd>
    </dl>

    <h2>Account actions</h2>
    <form method="post" action="/account/rotate"><button type="submit">Rotate operational key</button></form>
    <form method="post" action="/account/login-secret/reissue"><button type="submit" class="neutral">Get a new generated login secret</button></form>
    <form method="post" action="/account/login-secret/reissue">
      <label>Or set your own password <small>(at least ${MIN_PASSWORD_LENGTH} characters)</small> <input type="password" name="password" autocomplete="new-password" minlength="${MIN_PASSWORD_LENGTH}" required></label>
      <label>Confirm <input type="password" name="password_confirm" autocomplete="new-password" minlength="${MIN_PASSWORD_LENGTH}" required></label>
      <button type="submit" class="neutral">Set password</button>
    </form>
    ${
      forwarding
        ? `<p class="hint">Email forwarding: ${escapeHtml(forwarding.forward_to)} (verified)</p>`
        : `<form method="post" action="/account/email">
             <label>Forwarding email <input name="forward_to" type="email" required></label>
             <button type="submit" class="neutral">Set up email forwarding</button>
           </form>${name === "" ? `<p class="hint">Mail for this identity routes through <code>_@${escapeHtml(env.REGISTRAR_DOMAIN)}</code>, the same reserved local part already used to log in as root.</p>` : ""}`
    }
    ${
      state.guardians.length
        ? `<p class="hint">A guardian steps down under its own authority, not this account's -- see the registrar API's <code>.../remove-self</code> (one guardian, voluntary) in the registrar API doc. Removing a guardian without its own cooperation needs the others' approval, through the asynchronous multi-signer proposal flow.</p>`
        : ""
    }
    ${!state.deactivated ? `<p><a href="/account/tombstone">Deactivate this identity</a></p>` : ""}
  `;
  return html(pageShell(`Account -- ${escapeHtml(urlSegment)}`, body));
}

export async function handleAccountRotate(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  try {
    await rotateHeldKey(env, session.wardDid);
  } catch (e) {
    if (e instanceof RegistrarError) return redirectToAccount(`Couldn't rotate: ${e.message}`, "error");
    throw e;
  }
  return redirectToAccount("Operational key rotated.");
}

const MIN_PASSWORD_LENGTH = 12;

/**
 * Covers both "get me a new generated secret" (the dashboard's own
 * existing bare-button form) and "set my own password instead" (a new
 * sibling form on the same page, same underlying reissueLoginSecret call)
 * -- whichever the submitted form actually included a password field for.
 */
export async function handleAccountReissueLoginSecret(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const form = await safeFormData(request);
  const password = form.get("password") ? String(form.get("password")) : undefined;
  if (password) {
    const confirm = String(form.get("password_confirm") ?? "");
    if (password.length < MIN_PASSWORD_LENGTH) return redirectToAccount(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`, "error");
    if (password !== confirm) return redirectToAccount("Passwords don't match.", "error");
    await reissueLoginSecret(env, session.wardDid, password);
    return redirectToAccount("Password set -- sign in with it next time.");
  }
  const loginSecret = await reissueLoginSecret(env, session.wardDid);
  const body = `
    <h1>New login secret</h1>
    <p class="hint">Shown once, right now -- write it down. You'll need it (with your account's own name) to sign in again.</p>
    <dl><dt>Login secret</dt><dd>${secretBox(loginSecret!)}</dd></dl>
    <p><a href="/account">Back to your account</a></p>
  `;
  return html(pageShell("New login secret", body));
}

export async function handleAccountEmail(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const form = await safeFormData(request);
  const forwardTo = String(form.get("forward_to") ?? "");
  if (!forwardTo) return redirectToAccount("An email address is required.", "error");
  const result = await requestEmailForwarding(env, session.name, forwardTo);
  return result.ok
    ? redirectToAccount("Verification email sent -- check your inbox.")
    : redirectToAccount(`Couldn't set up forwarding: ${result.reason}`, "error");
}

export async function handleAccountTombstoneConfirm(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  // The confirm-by-typing value is the URL form ("_" for root), not the
  // raw storage name -- asking someone to type an empty string to confirm
  // would be meaningless for the bare-domain identity.
  const confirmName = urlName(session.name);
  const body = `
    <h1>Deactivate this identity</h1>
    <p class="hint">This is permanent. The full history stays publicly resolvable forever (it's never deleted), but no further operation will ever be accepted against it again${session.name === "" ? "" : `, and "${escapeHtml(confirmName)}" can never be registered again by anyone, including you`}.</p>
    <form method="post" action="/account/tombstone">
      <label>Type "${escapeHtml(confirmName)}" to confirm <input name="confirm" required></label>
      <button type="submit" class="danger">Permanently deactivate</button>
    </form>
    <p><a href="/account">Cancel, back to your account</a></p>
  `;
  return html(pageShell("Confirm deactivation", body));
}

export async function handleAccountTombstone(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const confirmName = urlName(session.name);
  const form = await safeFormData(request);
  if (String(form.get("confirm") ?? "") !== confirmName) {
    return html(pageShell("Confirm deactivation", `<h1>Confirm deactivation</h1><p class="error">That didn't match "${escapeHtml(confirmName)}" -- nothing was changed.</p><p><a href="/account/tombstone">Try again</a></p>`), 400);
  }
  try {
    await deactivateSelf(env, session.wardDid);
  } catch (e) {
    if (e instanceof RegistrarError) {
      return html(
        pageShell(
          "Couldn't deactivate",
          `<h1>Couldn't deactivate</h1><p class="error">${escapeHtml(e.message)}</p><p class="hint">Your own policy may require guardian cooperation too -- propose a deactivate through the asynchronous multi-signer proposal flow instead.</p><p><a href="/account">Back to your account</a></p>`,
        ),
        e.status,
      );
    }
    throw e;
  }
  return redirectToAccount("This identity has been deactivated.");
}

export async function handleAccountRevokeConsent(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const form = await safeFormData(request);
  const clientId = String(form.get("client_id") ?? "");
  if (!clientId) return redirectToAccount("client_id is required.", "error");
  await deleteOidcConsent(env, session.wardDid, clientId);
  await revokeRefreshTokensForWardAndClient(env, session.wardDid, clientId);
  return redirectToAccount("Access revoked.");
}

function redirectToAccount(message: string, kind: "ok" | "error" = "ok"): Response {
  const qs = new URLSearchParams({ message, kind });
  return new Response(null, { status: 302, headers: { location: `/account?${qs.toString()}` } });
}
