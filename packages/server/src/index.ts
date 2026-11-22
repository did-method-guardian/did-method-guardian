import type { Env } from "./env.js";
import type { DataIntegrityProof, Did, Operation, RemoveGuardianOp, UpdateOp } from "@did-guardian/lib";
import { safeFormData } from "./http.js";
import { didFor } from "./env.js";
import { getResourceDocument, getResourceLog, submitOperation } from "./registrar.js";
import { registerIdentity, reissueLoginSecret, rotateHeldKey, takeCustody, deactivateSelf, removeGuardianSelf, removeGuardianWithEvidence, proposeAdopt, confirmAdopt } from "./profile.js";
import { proposeOperation, contributeProof, cancelPendingOperation, getPendingOperationStatus, listPendingForDid, expirePendingOperations } from "./pendingProofs.js";
import { RegistrarError } from "./registrarError.js";
import { handleOidcRequest, verifyAccessToken } from "./oidc.js";
import { handleEmail, requestEmailForwarding, confirmEmailForwarding } from "./email.js";
import { readCookie, resolveSession } from "./login.js";
import { authenticateOidcClient } from "./clientAuth.js";
import { renderPendingOpPage, signAsSelf, withdrawAsSelf, handleDirectLogin, handleLogout } from "./votingPage.js";
import { handleRelaySignPage, handleRelaySignSubmit } from "./relaySign.js";
import { handleRegisterPage, handleRegisterForm } from "./registerPage.js";
import { handleAdminPage, handleAdminCreateAccountPage, handleAdminCreateAccountForm, handleAdminAppsPage, handleAdminAppsNewPage, handleAdminAppsNewForm, handleAdminAppsDelete } from "./adminPage.js";
import { handleAgentCard, handleWebfinger } from "./agentCard.js";
import { checkRateLimit, clientIp } from "./rateLimit.js";
import {
  handleAccountPage,
  handleAccountRotate,
  handleAccountReissueLoginSecret,
  handleAccountEmail,
  handleAccountTombstoneConfirm,
  handleAccountTombstone,
  handleAccountRevokeConsent,
} from "./accountPage.js";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function error(message: string, status: number): Response {
  return json({ error: message }, status);
}

function errorFrom(e: unknown, logLabel: string): Response {
  if (e instanceof RegistrarError) return error(e.message, e.status);
  if (e instanceof SyntaxError) return error("malformed JSON in request body", 400);
  console.error(`${logLabel}:`, e);
  return error("internal error", 500);
}

function html(body: string, status = 200): Response {
  return new Response(`<!doctype html><meta charset="utf-8"><title>did:guardian</title>${body}`, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}

/** The caller authenticated as `did` on this request -- a gw_session for that exact identity, or a trusted OIDC client. Never trusts a route parameter alone. */
async function authenticatedAs(request: Request, env: Env, did: Did): Promise<boolean> {
  const sessionId = readCookie(request, "gw_session");
  const sessionDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (sessionDid === did) return true;
  if (sessionDid) return false; // signed in as someone else -- a trusted client never overrides an existing session's own identity
  const trustedClient = await authenticateOidcClient(request, env);
  return trustedClient !== null;
}

/** The caller's own identity, from a session or (if named explicitly, for a trusted client with no identity of its own) the `did`/`guardian_did` field named in `body`. */
async function callerIdentity(request: Request, env: Env, body: { guardian_did?: string }): Promise<Did | null> {
  const sessionId = readCookie(request, "gw_session");
  const sessionDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (sessionDid) return sessionDid as Did;
  const trustedClient = await authenticateOidcClient(request, env);
  if (!trustedClient) return null;
  return (body.guardian_did as Did) ?? null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      return await route(request, env, url, path);
    } catch (e) {
      if (e instanceof SyntaxError) {
        const accept = request.headers.get("accept") ?? "";
        if (accept.includes("text/html")) return html(`<h1>Bad request</h1><p class="error">The request body isn't valid JSON.</p>`, 400);
        return error("malformed JSON in request body", 400);
      }
      if (e instanceof RegistrarError) return error(e.message, e.status);
      console.error("unhandled route error:", e);
      const accept = request.headers.get("accept") ?? "";
      if (accept.includes("text/html")) return html(`<h1>Something went wrong</h1><p class="error">An unexpected error occurred handling this request.</p>`, 500);
      return error("internal error", 500);
    }
  },

  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    await handleEmail(message, env);
  },

  /** Daily sweep for expired multi-signer proposals. Cron schedule set in each deployment's own wrangler config (triggers.crons). */
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    await expirePendingOperations(env);
  },
};

async function route(request: Request, env: Env, url: URL, path: string): Promise<Response> {
  // REQ-10-1's three resources, plus the profile's own convenience
  // endpoints, all under the one path segment.
  const wellKnownMatch = path.match(
    /^\/\.well-known\/guardian\/([^/]+)(\/log|\/operations|\/propose|\/email|\/login-secret|\/rotate|\/take-custody|\/remove-self|\/remove|\/adopt|\/adopt\/confirm|\/agent-card\.json)?$/,
  );
  if (wellKnownMatch) {
    const [, rawName, suffix] = wellKnownMatch;
    const name = rawName === "_" ? null : rawName;
    const did = didFor(name, env.REGISTRAR_DOMAIN) as Did;
    try {
      // REQ-10-2: every branch below this point, up to /operations, is a
      // plain read.
      if (!suffix && request.method === "GET") {
        const doc = await getResourceDocument(env, rawName);
        return doc ? json(doc) : error("not found", 404);
      }
      if (suffix === "/log" && request.method === "GET") {
        const log = await getResourceLog(env, rawName);
        return log ? json(log) : error("not found", 404);
      }
      if (suffix === "/agent-card.json" && request.method === "GET") {
        return handleAgentCard(env, name);
      }

      if (suffix === "/operations" && request.method === "POST") {
        const op = (await request.json()) as Operation;
        // A create here is a brand-new identity claiming this name --
        // anonymous self-service by construction, so it gets exactly
        // /register's gate: rate-limited per IP, and blocked outright
        // when this deployment has closed public registration.
        if (op.type === "create") {
          if (!(await checkRateLimit(env, "register", clientIp(request), 5, 600))) {
            return error("too many registration attempts from this address -- try again in a few minutes", 429);
          }
          if (env.REGISTRATION_MODE === "closed") {
            return error("this registrar doesn't accept public registration", 403);
          }
        }
        try {
          const accepted = await submitOperation(env, did, op);
          return json({ accepted: true, operation: accepted }, 201);
        } catch (e) {
          if (e instanceof RegistrarError) return error(e.message, e.status);
          throw e;
        }
      }

      if (suffix === "/propose" && request.method === "POST") {
        // No session/trusted-client gate, deliberately -- same trust
        // model as /operations: the operation's own attached proof is
        // the authorization. A required signer with no account here at
        // all must be able to propose or contribute without logging in.
        const body = (await request.json()) as { operation?: Omit<Operation, "proof">; proof?: DataIntegrityProof };
        if (!body.operation || !body.proof) return error("operation and proof are required", 400);
        const outcome = await proposeOperation(env, did, body.operation, body.proof);
        return json(outcome, outcome.status === "finalized" ? 201 : 202);
      }

      if (suffix === "/email" && request.method === "POST") {
        if (name === null) return error("email forwarding is not available for the bare-domain identity", 400);
        if (!(await authenticatedAs(request, env, did))) {
          return error("must be signed in as this identity (or a trusted client acting on its behalf) to set up its mail forwarding", 403);
        }
        const body = (await request.json()) as { forward_to?: string };
        if (!body.forward_to) return error("forward_to is required", 400);
        const result = await requestEmailForwarding(env, name, body.forward_to);
        return result.ok ? json({ ok: true, message: "verification email sent" }) : error(result.reason, 400);
      }

      if (suffix === "/login-secret" && request.method === "POST") {
        if (!(await authenticatedAs(request, env, did))) {
          return error("must be signed in as this identity (or a trusted client acting on its behalf) to reissue its login secret", 403);
        }
        const body = (await request.json().catch(() => ({}))) as { password?: string };
        const loginSecret = await reissueLoginSecret(env, did, body.password);
        return json({ ok: true, login_secret: loginSecret });
      }

      if (suffix === "/rotate" && request.method === "POST") {
        if (!(await authenticatedAs(request, env, did))) {
          return error("must be signed in as this identity (or a trusted client acting on its behalf) to rotate its key", 403);
        }
        await rotateHeldKey(env, did);
        return json({ ok: true, did });
      }

      if (suffix === "/take-custody" && request.method === "POST") {
        // Irreversible from this registrar's side: once it succeeds,
        // every endpoint above that signs on this identity's own behalf
        // (rotate, login-secret, tombstone, remove-self) starts
        // refusing (this registrar no longer holds a key for it).
        if (!(await authenticatedAs(request, env, did))) {
          return error("must be signed in as this identity (or a trusted client acting on its behalf) to take custody of its key", 403);
        }
        const body = (await request.json()) as { operation?: Omit<UpdateOp, "proof">; proof?: DataIntegrityProof };
        if (!body.operation || !body.proof) return error("operation (an update naming the new keys) and proof are required", 400);
        await takeCustody(env, did, body.operation, body.proof);
        return json({ ok: true, did });
      }

      if (suffix === "/remove-self" && request.method === "POST") {
        // The "target identity" for auth purposes is the CALLER (the
        // departing guardian), never `name` (the ward being left).
        const body = (await request.json().catch(() => ({}))) as { guardian_did?: string };
        const callerDid = await callerIdentity(request, env, body);
        if (!callerDid) return error("must be signed in, or a trusted client naming guardian_did, to remove yourself as a guardian", 403);
        await removeGuardianSelf(env, did, callerDid);
        return json({ ok: true, did });
      }

      if (suffix === "/remove" && request.method === "POST") {
        // The ward's own current key, naming evidence (REQ-7-6/REQ-10-7)
        // that the guardian being removed already lost standing. A
        // forced removal by vote of the OTHER guardians, with no
        // evidence, goes through /propose instead -- it needs more than
        // one signature.
        if (!(await authenticatedAs(request, env, did))) {
          return error("must be signed in as this identity (or a trusted client acting on its behalf) to remove a guardian with evidence", 403);
        }
        const body = (await request.json().catch(() => ({}))) as { guardian_did?: string; evidence?: string };
        if (!body.guardian_did || !body.evidence) return error("guardian_did and evidence (an operation hash in that guardian's own log) are required", 400);
        await removeGuardianWithEvidence(env, did, body.guardian_did as Did, body.evidence);
        return json({ ok: true, did });
      }

      if (suffix === "/adopt" && request.method === "POST") {
        // Step 1 of adopt: authenticated as the GUARDIAN, naming `name`
        // as the ward it's accepting. `name` here is the ward -- the
        // guardian's own identity comes from the session/trusted client
        // itself, never a free-text field, so this can't be used to
        // claim consent on the ward's behalf.
        const sessionId = readCookie(request, "gw_session");
        const guardianDid = sessionId ? ((await resolveSession(env, sessionId)) as Did | null) : null;
        if (!guardianDid) return error("must be signed in as the guardian accepting this ward", 401);
        const { pendingId } = await proposeAdopt(env, guardianDid, did);
        return json({ ok: true, pendingId, message: "accepted on the guardian's own log; waiting on the ward's own approval to finish adding it (adopt/confirm)" }, 202);
      }

      if (suffix === "/adopt/confirm" && request.method === "POST") {
        // Step 2 of adopt: authenticated as the WARD.
        if (!(await authenticatedAs(request, env, did))) {
          return error("must be signed in as this identity (or a trusted client acting on its behalf) to confirm a guardian", 403);
        }
        const body = (await request.json()) as { pending_id?: string };
        if (!body.pending_id) return error("pending_id is required", 400);
        const result = await confirmAdopt(env, did, body.pending_id);
        return result.accepted ? json({ ok: true, did }) : error(result.reason ?? "not accepted yet", 400);
      }
    } catch (e) {
      return errorFrom(e, "well-known guardian route error");
    }
    return error("not found", 404);
  }

  // A2A interop: the fixed path is A2A's own convention for a
  // single-agent origin -- satisfied here for this domain's own
  // bare-domain root identity, the same "_" convention did:guardian uses
  // everywhere else.
  if (path === "/.well-known/agent-card.json" && request.method === "GET") {
    return handleAgentCard(env, null);
  }
  if (path === "/.well-known/webfinger" && request.method === "GET") {
    return handleWebfinger(env, url);
  }

  // Multi-signer proposals are identified by their own id, not nested
  // under any one identity's path segment -- a proposal's own `did`
  // member says which log it targets.
  const pendingMatch = path.match(/^\/\.well-known\/guardian\/pending\/([^/]+)(\/sign|\/sign-as-self|\/withdraw)?$/);
  if (pendingMatch) {
    const [, id, pendingSuffix] = pendingMatch;
    try {
      if (!pendingSuffix && request.method === "GET") {
        // Content-negotiated: a browser gets the real voting page; an
        // API caller gets the same JSON this has always returned.
        const accept = request.headers.get("accept") ?? "";
        const status = await getPendingOperationStatus(env, id);
        const name = (() => {
          const m = /^did:guardian:[^:]+:(.+)$/.exec(status.did);
          return m ? m[1] : "_";
        })();
        if (accept.includes("text/html")) {
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? ((await resolveSession(env, sessionId)) as Did | null) : null;
          return await renderPendingOpPage(env, name, id, sessionWardDid);
        }
        return json(status);
      }
      if (pendingSuffix === "/sign" && request.method === "POST") {
        // No session gate, deliberately -- same trust model as
        // /propose: the proof itself is the authorization.
        const body = (await request.json()) as { proof?: DataIntegrityProof };
        if (!body.proof) return error("proof is required", 400);
        const outcome = await contributeProof(env, id, body.proof);
        return json(outcome, outcome.status === "finalized" ? 200 : 202);
      }
      if (pendingSuffix === "/sign-as-self" && request.method === "POST") {
        const status = await getPendingOperationStatus(env, id);
        const name = (() => {
          const m = /^did:guardian:[^:]+:(.+)$/.exec(status.did);
          return m ? m[1] : "_";
        })();
        return await signAsSelf(request, env, name, id);
      }
      if (pendingSuffix === "/withdraw" && request.method === "POST") {
        const status = await getPendingOperationStatus(env, id);
        const sessionId = readCookie(request, "gw_session");
        const sessionDid = sessionId ? await resolveSession(env, sessionId) : null;
        if (sessionDid !== status.did) return error("only the identity this proposal targets may withdraw it", 403);
        const contentType = request.headers.get("content-type") ?? "";
        const isForm = contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data");
        await withdrawAsSelf(env, id);
        if (isForm) return new Response(null, { status: 302, headers: { location: "/account" } });
        return json({ ok: true });
      }
    } catch (e) {
      return errorFrom(e, "pending operation error");
    }
    return error("not found", 404);
  }

  if (path === "/api/me/pending-signatures" && request.method === "GET") {
    const sessionId = readCookie(request, "gw_session");
    const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
    let did = sessionWardDid;
    if (!did) {
      const trustedClient = await authenticateOidcClient(request, env);
      if (!trustedClient) return error("must be signed in, or a trusted client naming ?did=, to list pending signatures", 403);
      did = url.searchParams.get("did");
      if (!did) return error("did query parameter is required for a trusted client", 400);
    }
    const rows = await listPendingForDid(env, did as Did);
    return json({ pending: rows });
  }

  if (path === "/guardian-login" && (request.method === "GET" || request.method === "POST")) {
    return handleDirectLogin(request, env, url);
  }
  if (path === "/guardian-logout" && request.method === "POST") {
    return handleLogout(request, env, url);
  }
  if (path === "/relay-sign" && request.method === "GET") {
    return handleRelaySignPage(request, env, url);
  }
  if (path === "/relay-sign" && request.method === "POST") {
    return handleRelaySignSubmit(request, env);
  }

  if (path === "/account" && request.method === "GET") {
    return handleAccountPage(request, env);
  }
  if (path === "/account/rotate" && request.method === "POST") {
    return handleAccountRotate(request, env);
  }
  if (path === "/account/login-secret/reissue" && request.method === "POST") {
    return handleAccountReissueLoginSecret(request, env);
  }
  if (path === "/account/email" && request.method === "POST") {
    return handleAccountEmail(request, env);
  }
  if (path === "/account/tombstone" && request.method === "GET") {
    return handleAccountTombstoneConfirm(request, env);
  }
  if (path === "/account/tombstone" && request.method === "POST") {
    return handleAccountTombstone(request, env);
  }
  if (path === "/account/consents/revoke" && request.method === "POST") {
    return handleAccountRevokeConsent(request, env);
  }

  // Admin console (adminPage.ts) -- root-identity-only, available
  // regardless of REGISTRATION_MODE (see that gating below).
  if (path === "/admin" && request.method === "GET") {
    return handleAdminPage(request, env);
  }
  if (path === "/admin/create-account" && request.method === "GET") {
    return handleAdminCreateAccountPage(request, env);
  }
  if (path === "/admin/create-account" && request.method === "POST") {
    return handleAdminCreateAccountForm(request, env);
  }
  if (path === "/admin/apps" && request.method === "GET") {
    return handleAdminAppsPage(request, env);
  }
  if (path === "/admin/apps/new" && request.method === "GET") {
    return handleAdminAppsNewPage(request, env);
  }
  if (path === "/admin/apps/new" && request.method === "POST") {
    return handleAdminAppsNewForm(request, env);
  }
  const adminAppDeleteMatch = path.match(/^\/admin\/apps\/([^/]+)\/delete$/);
  if (adminAppDeleteMatch && request.method === "POST") {
    return handleAdminAppsDelete(request, env, decodeURIComponent(adminAppDeleteMatch[1]));
  }

  if (path === "/verify-email" && request.method === "GET") {
    const token = url.searchParams.get("token");
    if (!token) return error("token is required", 400);
    const result = await confirmEmailForwarding(env, token);
    return result.ok
      ? new Response(`Mail forwarding confirmed for ${result.did}.`, { headers: { "content-type": "text/plain" } })
      : error(result.reason, 400);
  }

  // REGISTRATION_MODE (env.ts): "closed" blocks only anonymous
  // self-service -- a bare name, no prior authorization. A Managed
  // Identity API bearer token still works either way; a closed
  // deployment's own root identity creates accounts instead through the
  // admin console (adminPage.ts).
  const registrationClosed = env.REGISTRATION_MODE === "closed";

  if (path === "/register" && request.method === "GET") {
    if (registrationClosed) {
      return html(`<h1>Registration is closed</h1><p class="error">This registrar doesn't accept public registration. If you were given an account, <a href="/guardian-login">sign in</a> instead.</p>`, 403);
    }
    return handleRegisterPage(url);
  }

  if (path === "/register" && request.method === "POST") {
    if (!(await checkRateLimit(env, "register", clientIp(request), 5, 600))) {
      return error("too many registration attempts from this address -- try again in a few minutes", 429);
    }
    const contentType = request.headers.get("content-type") ?? "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      if (registrationClosed) {
        return html(`<h1>Registration is closed</h1><p class="error">This registrar doesn't accept public registration. If you were given an account, <a href="/guardian-login">sign in</a> instead.</p>`, 403);
      }
      return handleRegisterForm(request, env);
    }
    try {
      const body = (await request.json()) as { name?: string; password?: string };
      if (!body.name) return error("name is required", 400);
      // The Managed Identity API (§9): a new identity's guardian is
      // never a free-text field -- it's derived from a real, scope-
      // checked access token's own sub, the authenticated end user who
      // consented (create:managed-identity) to becoming a guardian. A
      // caller with no bearer token gets plain self-service
      // registration, no guardian, unless registration is closed.
      const auth = request.headers.get("authorization") ?? "";
      const bearerToken = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      let guardianDid: Did | null = null;
      if (bearerToken) {
        const verified = await verifyAccessToken(env, bearerToken);
        if (!verified) return error("invalid, expired, or revoked access token", 401);
        if (!verified.scope.includes("create:managed-identity")) {
          return error('this access token was not granted the "create:managed-identity" scope', 403);
        }
        guardianDid = verified.sub as Did;
      } else if (registrationClosed) {
        return error("this registrar doesn't accept public registration -- a Managed Identity API access token is required", 403);
      }

      const result = await registerIdentity(env, body.name, { password: body.password });

      // REQ-10-14: apart from the attestation, one request must not
      // cause this registrar to create proofs for more than one
      // identity. Completing the adopt flow here too (the guardian's
      // own proof, then the new identity's own proof, both within this
      // same POST /register) would do exactly that -- even when this
      // registrar holds both keys. The consenting guardian (named by
      // the Managed Identity API's access token, if any) is added
      // afterward instead, through the ordinary two-step adopt flow, as
      // its own separate requests -- echoed back here only as a DID to
      // act on, never as a proof produced for it.
      return json({ did: result.did, login_secret: result.loginSecret, guardian_pending: guardianDid }, 201);
    } catch (e) {
      return errorFrom(e, "register error");
    }
  }

  if (
    path.startsWith("/.well-known/openid-configuration") ||
    path.startsWith("/.well-known/jwks.json") ||
    path.startsWith("/.well-known/oauth-protected-resource") ||
    path.startsWith("/authorize") ||
    path.startsWith("/token") ||
    path.startsWith("/userinfo") ||
    path.startsWith("/revoke") ||
    path.startsWith("/oauth/")
  ) {
    return handleOidcRequest(request, env);
  }

  return error("not found", 404);
}
