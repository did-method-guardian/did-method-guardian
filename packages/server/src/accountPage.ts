// The account dashboard -- the one piece "Login with Guardian" was
// genuinely missing: a real page where a person can log in and actually
// see and manage their own identity (activity, guardians, connected
// apps, roll their key, deactivate the account), rather than only ever
// being reachable through a relying party's own API calls. Same
// first-party-HTML-page pattern votingPage.ts already established: a
// dedicated handler file reusing htmlPage.ts's shell, calling the same
// registrar.ts/pendingOps.ts/email.ts functions the JSON API already
// uses, never a thin wrapper that bounces a browser form at a JSON
// endpoint and shows the raw response back.
//
// Session-gated only (gw_session) -- no trusted-client bypass. Every
// other self-contained convenience endpoint accepts a trusted OIDC
// client acting on someone else's behalf (zz rotating a managed agent's
// key, say); this page is deliberately simpler, since it's the human
// looking at their own account directly, not a platform acting for them.

import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { html, escapeHtml, pageShell } from "./htmlPage.js";
import { readCookie, resolveSession } from "./login.js";
import {
  resolveState,
  loadLog,
  rotateWard,
  tombstoneWard,
  relinquishWard,
  reissueLoginSecret,
  RegistrarError,
} from "./registrar.js";
import { listPendingForSigner } from "./pendingOps.js";
import { requestEmailForwarding } from "./email.js";
import {
  getWardByDid,
  getVerifiedForwardingByDid,
  listOidcConsentsForWard,
  deleteOidcConsent,
  revokeRefreshTokensForWardAndClient,
  type WardRow,
} from "./db.js";
import type { Did, LogEntry } from "@did-guardian/lib";

const SESSION_COOKIE = "gw_session";

async function requireSession(request: Request, env: Env): Promise<{ wardDid: Did; ward: WardRow } | Response> {
  const sessionId = readCookie(request, SESSION_COOKIE);
  const wardDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!wardDid) {
    return new Response(null, { status: 302, headers: { location: `/guardian-login?return_to=${encodeURIComponent("/account")}` } });
  }
  const ward = await getWardByDid(env, wardDid);
  if (!ward) return html(pageShell("Error", `<h1>Error</h1><p class="error">Your own identity isn't custodied by this registrar.</p>`), 500);
  return { wardDid: wardDid as Did, ward };
}

/** `wards.name` uses `""` for the bare-domain root; every URL this page builds uses "_" instead, the same convention pendingOps.ts/votingPage.ts already follow. */
function urlName(ward: WardRow): string {
  return ward.name === "" ? "_" : ward.name;
}

/**
 * rotate/tombstone/relinquish/login-secret-reissue are all deliberately
 * unreachable for the bare-domain root identity -- the same restriction
 * index.ts's own HTTP routes for these already enforce (see each
 * function's own header comment in registrar.ts: "rotating the domain's
 * own root credential is a different, more sensitive operation"). This
 * page matches that policy rather than exposing a path those routes
 * deliberately withhold.
 */
function requireNamedWard(ward: WardRow): string | Response {
  if (ward.name === "") {
    return html(pageShell("Not available", `<h1>Not available</h1><p class="error">This action isn't available for the domain's own root identity.</p><p><a href="/account">Back to your account</a></p>`), 400);
  }
  return ward.name;
}

function opSummary(entry: LogEntry): string {
  const op = entry.op as { type: string; incoming?: string; outgoing?: string };
  switch (op.type) {
    case "custodial_create":
      return "Identity created";
    case "custodial_rotate":
      return "Operational key rotated";
    case "guardian_add":
      return `Guardian added: ${escapeHtml(op.incoming ?? "")}`;
    case "guardian_remove":
      return `Guardian removed: ${escapeHtml(op.outgoing ?? "")}`;
    case "guardian_relinquish":
      return "All guardians relinquished";
    case "guardian_transfer":
      return "Guardian transferred (legacy)";
    case "policy_update":
      return "Guardian policy updated";
    case "custodial_tombstone":
      return "Identity deactivated";
    default:
      return escapeHtml(op.type);
  }
}

function banner(message: string | null, kind: "ok" | "error" = "ok"): string {
  if (!message) return "";
  return `<p class="${kind === "error" ? "error" : "hint"}">${escapeHtml(message)}</p>`;
}

export async function handleAccountPage(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const { wardDid, ward } = session;
  const name = urlName(ward);
  const url = new URL(request.url);
  const message = url.searchParams.get("message");
  const messageKind = url.searchParams.get("kind") === "error" ? "error" : "ok";

  const resolved = await resolveState(env, ward.name === "" ? null : ward.name);
  if (!resolved) return html(pageShell("Error", `<h1>Error</h1><p class="error">Could not resolve this identity's own state.</p>`), 500);
  const { state } = resolved;

  const log = await loadLog(env, wardDid);
  const forwarding = await getVerifiedForwardingByDid(env, wardDid);
  const pending = await listPendingForSigner(env, wardDid);
  const consents = await listOidcConsentsForWard(env, wardDid);

  const guardiansList = state.guardians.length
    ? `<ul class="signers">${state.guardians.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul>`
    : `<p class="hint">No guardians -- fully self-governing.</p>`;

  const pendingList = pending.length
    ? `<ul class="signers">${pending
        .map((p) => `<li>${escapeHtml(p.op_type)} -- <a href="/.well-known/guardian/${encodeURIComponent(name)}/pending/${p.id}">review and sign</a></li>`)
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

  const activityList = [...log]
    .reverse()
    .map((entry) => `<li>${opSummary(entry)} <span class="hint">${escapeHtml(entry.acceptedAt ?? "")}</span></li>`)
    .join("");

  const body = `
    <h1>Your account</h1>
    <p class="hint">${escapeHtml(wardDid)}</p>
    ${banner(message ?? null, messageKind)}
    <dl>
      <dt>Status</dt><dd><span class="state">${state.deactivated ? "Deactivated" : "Active"}</span></dd>
      <dt>Guardians</dt><dd>${guardiansList}</dd>
      <dt>Policy</dt><dd class="hint">recovery: ${escapeHtml(JSON.stringify(state.guardianPolicy.recovery_threshold))}, removal: ${escapeHtml(JSON.stringify(state.guardianPolicy.removal_threshold))}, addition: ${escapeHtml(JSON.stringify(state.guardianPolicy.addition_threshold))}, tombstone: ${escapeHtml(JSON.stringify(state.guardianPolicy.tombstone_threshold))}</dd>
      <dt>Needs your signature</dt><dd>${pendingList}</dd>
      <dt>Connected apps</dt><dd>${consentsList}</dd>
      <dt>Activity</dt><dd><ul class="signers">${activityList}</ul></dd>
    </dl>

    ${
      ward.name === ""
        ? `<p class="hint">Rotation, login-secret reissue, email forwarding, relinquishing, and deactivation aren't available for the domain's own root identity.</p>`
        : `
    <h2>Account actions</h2>
    <form method="post" action="/account/rotate"><button type="submit">Rotate operational key</button></form>
    <form method="post" action="/account/login-secret/reissue"><button type="submit" class="neutral">Reissue login secret</button></form>
    ${
      forwarding
        ? `<p class="hint">Email forwarding: ${escapeHtml(forwarding.forward_to)} (verified)</p>`
        : `<form method="post" action="/account/email">
             <label>Forwarding email <input name="forward_to" type="email" required></label>
             <button type="submit" class="neutral">Set up email forwarding</button>
           </form>`
    }
    ${
      state.guardians.length
        ? `<form method="post" action="/account/relinquish"><button type="submit" class="danger">Relinquish all guardians</button></form>`
        : ""
    }
    ${!state.deactivated ? `<p><a href="/account/tombstone">Deactivate this identity</a></p>` : ""}
    `
    }
  `;
  return html(pageShell(`Account -- ${escapeHtml(name)}`, body));
}

export async function handleAccountRotate(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const name = requireNamedWard(session.ward);
  if (name instanceof Response) return name;
  try {
    await rotateWard(env, name);
  } catch (e) {
    if (e instanceof RegistrarError) return redirectToAccount(`Couldn't rotate: ${e.message}`, "error");
    throw e;
  }
  return redirectToAccount("Operational key rotated.");
}

export async function handleAccountReissueLoginSecret(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const name = requireNamedWard(session.ward);
  if (name instanceof Response) return name;
  const loginSecret = await reissueLoginSecret(env, name);
  const body = `
    <h1>New login secret</h1>
    <p class="hint">Shown once, right now -- write it down. You'll need it (with your account's own name) to sign in again.</p>
    <dl><dt>Login secret</dt><dd><code>${escapeHtml(loginSecret)}</code></dd></dl>
    <p><a href="/account">Back to your account</a></p>
  `;
  return html(pageShell("New login secret", body));
}

export async function handleAccountEmail(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const name = requireNamedWard(session.ward);
  if (name instanceof Response) return name;
  const form = await request.formData();
  const forwardTo = String(form.get("forward_to") ?? "");
  if (!forwardTo) return redirectToAccount("An email address is required.", "error");
  const result = await requestEmailForwarding(env, name, forwardTo);
  return result.ok
    ? redirectToAccount("Verification email sent -- check your inbox.")
    : redirectToAccount(`Couldn't set up forwarding: ${result.reason}`, "error");
}

export async function handleAccountRelinquish(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const name = requireNamedWard(session.ward);
  if (name instanceof Response) return name;
  try {
    await relinquishWard(env, name);
  } catch (e) {
    if (e instanceof RegistrarError) return redirectToAccount(`Couldn't relinquish: ${e.message}`, "error");
    throw e;
  }
  return redirectToAccount("All guardians relinquished.");
}

export async function handleAccountTombstoneConfirm(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const name = requireNamedWard(session.ward);
  if (name instanceof Response) return name;
  const body = `
    <h1>Deactivate this identity</h1>
    <p class="hint">This is permanent. The full history stays publicly resolvable forever (it's never deleted), but no further operation will ever be accepted against it again, and "${escapeHtml(name)}" can never be registered again by anyone, including you.</p>
    <form method="post" action="/account/tombstone">
      <label>Type "${escapeHtml(name)}" to confirm <input name="confirm" required></label>
      <button type="submit" class="danger">Permanently deactivate</button>
    </form>
    <p><a href="/account">Cancel, back to your account</a></p>
  `;
  return html(pageShell("Confirm deactivation", body));
}

export async function handleAccountTombstone(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  if (session instanceof Response) return session;
  const name = requireNamedWard(session.ward);
  if (name instanceof Response) return name;
  const form = await request.formData();
  if (String(form.get("confirm") ?? "") !== name) {
    return html(pageShell("Confirm deactivation", `<h1>Confirm deactivation</h1><p class="error">That didn't match "${escapeHtml(name)}" -- nothing was changed.</p><p><a href="/account/tombstone">Try again</a></p>`), 400);
  }
  try {
    await tombstoneWard(env, name);
  } catch (e) {
    if (e instanceof RegistrarError) {
      return html(
        pageShell(
          "Couldn't deactivate",
          `<h1>Couldn't deactivate</h1><p class="error">${escapeHtml(e.message)}</p><p class="hint">Your own policy may require more than just your own key for this -- propose a custodial_tombstone through the asynchronous signing flow instead.</p><p><a href="/account">Back to your account</a></p>`,
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
  const form = await request.formData();
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
