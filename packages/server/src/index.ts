import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { registerWard, reissueLoginSecret, resolveDocument, resolveLog, rotateWard, relinquishWard, tombstoneWard, removeSelfAsGuardian, forceRemoveGuardian, adoptWard, submitOperation, RegistrarError } from "./registrar.js";
import { proposeOperation, contributeToOperation, declineOperation, withdrawFromOperation, getPendingOperationStatus, listPendingForSigner, sendDailyReminders } from "./pendingOps.js";
import { handleOidcRequest } from "./oidc.js";
import { handleEmail, requestEmailForwarding, confirmEmailForwarding } from "./email.js";
import { readCookie, resolveSession } from "./login.js";
import { authenticateOidcClient } from "./clientAuth.js";
import { renderPendingOpPage, signAsSelf, handleDirectLogin } from "./votingPage.js";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function error(message: string, status: number): Response {
  return json({ error: message }, status);
}

function html(body: string, status = 200): Response {
  return new Response(`<!doctype html><meta charset="utf-8"><title>did:guardian</title>${body}`, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    const wellKnownMatch = path.match(/^\/\.well-known\/guardian\/([^/]+)(\/log|\/operations|\/propose|\/email|\/login-secret|\/rotate|\/relinquish|\/tombstone|\/remove-self|\/remove|\/adopt)?$/);
    if (wellKnownMatch) {
      // "_" is the bare-domain root identity's own reserved path segment
      // (spec §2.1/§5) -- never a real registration (assertValidName's own
      // regex already rejects "_", so /register can never produce one).
      const [, rawName, suffix] = wellKnownMatch;
      const name = rawName === "_" ? null : rawName;
      try {
        if (!suffix && request.method === "GET") {
          const doc = await resolveDocument(env, name);
          return doc ? json(doc) : error("not found", 404);
        }
        if (suffix === "/log" && request.method === "GET") {
          const log = await resolveLog(env, name);
          return log ? json(log) : error("not found", 404);
        }
        if (suffix === "/operations" && request.method === "POST") {
          const op = await request.json();
          const result = await submitOperation(env, name, op as any);
          return result.accepted ? json({ accepted: true }) : error(result.reason, 400);
        }
        if (suffix === "/propose" && request.method === "POST") {
          // No session/trusted-client gate, deliberately -- same trust model
          // as plain /operations: the operation's own attached signature is
          // the authorization, not a cookie, since a required signer (an
          // external guardian with no account here at all) must be able to
          // propose or contribute without ever logging in to this registrar.
          const op = await request.json();
          const result = await proposeOperation(env, name, op as any);
          return json(result, 201);
        }
        if (suffix === "/email" && request.method === "POST") {
          // Out of scope for the bare-domain root identity in this pass --
          // not attempted here rather than half-wired (email forwarding's
          // own name-keyed lookups assume a real registered name).
          if (name === null) return error("email forwarding is not available for the bare-domain identity", 400);
          // Either the ward itself (an active gw_session for its own DID)
          // or a trusted OIDC client (clientAuth.ts) may set up forwarding
          // for this address -- the latter is what lets zz's own name-
          // picker wire a contact email in the same request that creates
          // the ward, before any interactive session with this registrar
          // exists. A trusted client still only ever acts on the ward
          // named in the URL path itself, never an arbitrary other one.
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          const trustedClient = sessionWardDid ? null : await authenticateOidcClient(request, env);
          if (sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN) && !trustedClient) {
            return error("must be signed in as this identity (or a trusted client acting on its behalf) to set up its mail forwarding", 403);
          }
          const body = (await request.json()) as { forward_to?: string };
          if (!body.forward_to) return error("forward_to is required", 400);
          const result = await requestEmailForwarding(env, name, body.forward_to);
          return result.ok ? json({ ok: true, message: "verification email sent" }) : error(result.reason, 400);
        }
        if (suffix === "/login-secret" && request.method === "POST") {
          // Same two-way trust as /email, same reason: either the ward
          // itself (an active gw_session for its own DID) or a trusted
          // OIDC client acting on an already-authenticated session of its
          // own may reissue this -- never an arbitrary caller for a DID
          // that isn't theirs.
          if (name === null) return error("the bare-domain identity has no login secret to reissue", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          const trustedClient = sessionWardDid ? null : await authenticateOidcClient(request, env);
          if (sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN) && !trustedClient) {
            return error("must be signed in as this identity (or a trusted client acting on its behalf) to reissue its login secret", 403);
          }
          const loginSecret = await reissueLoginSecret(env, name);
          return json({ ok: true, login_secret: loginSecret });
        }
        if (suffix === "/rotate" && request.method === "POST") {
          // Same two-way trust as /email and /login-secret, same
          // reason: either the ward itself (self-rotation, an active
          // gw_session for its own DID) or a trusted OIDC client acting
          // on an already-authenticated decision of its own (zz
          // rotating a managed agent's key on behalf of whoever created
          // it, say) -- never an arbitrary caller for a DID that isn't
          // theirs. Rotating the custodied operational key, not the
          // guardian relationship itself (full relinquishment has its
          // own convenience endpoint, /relinquish, below -- swapping
          // in a NEW guardian, guardian_transfer, is reached only
          // through /operations, pre-signed, since that hands new
          // authority to a party who never consented here).
          if (name === null) return error("the bare-domain identity's own key isn't rotatable through this path", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          const trustedClient = sessionWardDid ? null : await authenticateOidcClient(request, env);
          if (sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN) && !trustedClient) {
            return error("must be signed in as this identity (or a trusted client acting on its behalf) to rotate its key", 403);
          }
          const result = await rotateWard(env, name);
          return json({ ok: true, did: result.did, document: result.document });
        }
        if (suffix === "/relinquish" && request.method === "POST") {
          // Same two-way trust as /rotate, same reasoning: self-
          // contained (every signer this needs is already a current
          // guardian voluntarily giving up its own standing, not a
          // new party being handed authority), so the same trusted-
          // client-or-self-session gate is enough -- see relinquishWard's
          // own comment for why this is NOT extended to the general
          // guardian_transfer case.
          if (name === null) return error("the bare-domain identity's own guardians aren't relinquishable through this path", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          const trustedClient = sessionWardDid ? null : await authenticateOidcClient(request, env);
          if (sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN) && !trustedClient) {
            return error("must be signed in as this identity (or a trusted client acting on its behalf) to relinquish its guardians", 403);
          }
          const result = await relinquishWard(env, name);
          return json({ ok: true, did: result.did, document: result.document });
        }
        if (suffix === "/tombstone" && request.method === "POST") {
          // Same two-way trust as /rotate -- self-destruct needs only
          // the ward's own operational key (tombstone_threshold's
          // default is "any", the lowest bar), so this is exactly as
          // self-contained as rotation.
          if (name === null) return error("the bare-domain identity isn't tombstonable through this path", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          const trustedClient = sessionWardDid ? null : await authenticateOidcClient(request, env);
          if (sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN) && !trustedClient) {
            return error("must be signed in as this identity (or a trusted client acting on its behalf) to tombstone it", 403);
          }
          const result = await tombstoneWard(env, name);
          return json({ ok: true, did: result.did, document: result.document });
        }
        if (suffix === "/remove-self" && request.method === "POST") {
          // Unlike every endpoint above, the "target identity" for auth
          // purposes is the CALLER (the departing guardian), never `name`
          // (the ward being left) -- the ward's own session has no say in
          // whether one of its guardians steps down. A session identifies
          // the caller directly; a trusted client must name one explicitly
          // via guardian_did in the body, same split /api/me/pending-
          // signatures uses for the same underlying reason.
          if (name === null) return error("remove-self does not apply to the bare-domain identity", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionDid = sessionId ? await resolveSession(env, sessionId) : null;
          let callerDid = sessionDid;
          if (!callerDid) {
            const trustedClient = await authenticateOidcClient(request, env);
            if (!trustedClient) return error("must be signed in, or a trusted client naming guardian_did, to remove yourself as a guardian", 403);
            const body = (await request.json().catch(() => ({}))) as { guardian_did?: string };
            if (!body.guardian_did) return error("guardian_did is required for a trusted client", 400);
            callerDid = body.guardian_did;
          }
          const result = await removeSelfAsGuardian(env, name, callerDid);
          return json({ ok: true, did: result.did, document: result.document });
        }
        if (suffix === "/remove" && request.method === "POST") {
          // Forced removal -- same two-way trust as /relinquish: the ward's
          // own session or a trusted client may trigger the attempt, but
          // the real authority comes from whichever OTHER guardians this
          // registrar can sign for actually meeting removal_threshold.
          if (name === null) return error("the bare-domain identity's own guardians aren't forcibly removable through this path", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          const trustedClient = sessionWardDid ? null : await authenticateOidcClient(request, env);
          if (sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN) && !trustedClient) {
            return error("must be signed in as this identity (or a trusted client acting on its behalf) to force-remove one of its guardians", 403);
          }
          const body = (await request.json()) as { outgoing_did?: string };
          if (!body.outgoing_did) return error("outgoing_did is required", 400);
          const result = await forceRemoveGuardian(env, name, body.outgoing_did);
          return json({ ok: true, did: result.did, document: result.document });
        }
        if (suffix === "/adopt" && request.method === "POST") {
          // Same auth split as /remove-self: the caller adopting the ward
          // is a different identity than `name` (the ward being adopted),
          // so a session identifies the caller directly, and a trusted
          // client must name one explicitly via guardian_did.
          if (name === null) return error("adopt does not apply to the bare-domain identity", 400);
          const sessionId = readCookie(request, "gw_session");
          const sessionDid = sessionId ? await resolveSession(env, sessionId) : null;
          let incomingDid = sessionDid;
          if (!incomingDid) {
            const trustedClient = await authenticateOidcClient(request, env);
            if (!trustedClient) return error("must be signed in, or a trusted client naming guardian_did, to adopt a ward", 403);
            const body = (await request.json().catch(() => ({}))) as { guardian_did?: string };
            if (!body.guardian_did) return error("guardian_did is required for a trusted client", 400);
            incomingDid = body.guardian_did;
          }
          const result = await adoptWard(env, name, incomingDid);
          return json({ ok: true, did: result.did, document: result.document });
        }
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        console.error("well-known guardian route error:", e);
        return error("internal error", 500);
      }
      return error("not found", 404);
    }

    // Ward-scoped, per the registrar API spec's own §3 table -- the ward's
    // name is just a routing namespace here (consistent with every other
    // .well-known path), not a claim about who's involved; the pending
    // operation's own id is what actually identifies it. No session/
    // trusted-client gate on /sign or /decline, same reasoning as /propose:
    // the attached signature is the authorization, and a required signer
    // may be an external guardian with no account on this registrar at all.
    const pendingMatch = path.match(/^\/\.well-known\/guardian\/([^/]+)\/pending\/([^/]+)(\/sign|\/sign-as-self|\/decline|\/withdraw)?$/);
    if (pendingMatch) {
      const [, rawName, id, pendingSuffix] = pendingMatch;
      const name = rawName === "_" ? null : rawName;
      try {
        if (!pendingSuffix && request.method === "GET") {
          // Content-negotiated: a browser (clicking an email link, or
          // navigating here directly) gets the real voting page; an API
          // caller gets the same JSON this has always returned. Never
          // GET-triggers-an-action here, deliberately -- see votingPage.ts's
          // own header comment for why (email link prefetching/scanning).
          const accept = request.headers.get("accept") ?? "";
          if (accept.includes("text/html")) {
            const token = url.searchParams.get("token");
            const sessionId = readCookie(request, "gw_session");
            const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
            return await renderPendingOpPage(env, rawName, id, token, sessionWardDid);
          }
          const wardDid = didFor(name, env.REGISTRAR_DOMAIN);
          const status = await getPendingOperationStatus(env, wardDid, id);
          return json(status);
        }
        if (pendingSuffix === "/sign" && request.method === "POST") {
          const body = (await request.json()) as { signer_did?: string; sig?: string };
          if (!body.signer_did || !body.sig) return error("signer_did and sig are required", 400);
          const result = await contributeToOperation(env, id, body.signer_did, body.sig);
          return json(result);
        }
        if (pendingSuffix === "/sign-as-self" && request.method === "POST") {
          // gw_session-gated, server signs with the key it already custodies -- see votingPage.ts.
          return await signAsSelf(request, env, id);
        }
        // /decline and /withdraw each accept either a signed body
        // (signer_did + sig -- works for anyone who can produce a
        // signature) or a token (?token=... in a JSON body, or a form
        // field from the voting page's own buttons) -- proof by verified-
        // email possession rather than a signature; see email.ts's own
        // header comment on why that's an equally valid proof for this
        // specific action. A form submission (the voting page's own
        // buttons) redirects back to the status page; a JSON request gets
        // JSON back.
        if ((pendingSuffix === "/decline" || pendingSuffix === "/withdraw") && request.method === "POST") {
          const contentType = request.headers.get("content-type") ?? "";
          const isForm = contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data");
          const auth = isForm
            ? { token: String((await request.formData()).get("token") ?? "") }
            : await (async () => {
                const body = (await request.json()) as { signer_did?: string; sig?: string; token?: string };
                return body.token ? { token: body.token } : { signerDid: body.signer_did ?? "", sig: body.sig ?? "" };
              })();
          const act = pendingSuffix === "/decline" ? declineOperation : withdrawFromOperation;
          try {
            const result = await act(env, id, auth as any);
            if (isForm) return new Response(null, { status: 302, headers: { location: `/.well-known/guardian/${rawName}/pending/${id}` } });
            return json(result);
          } catch (e) {
            if (e instanceof RegistrarError) {
              if (isForm) return html(`<p>${e.message}</p>`, e.status);
              return error(e.message, e.status);
            }
            throw e;
          }
        }
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        console.error("pending operation error:", e);
        return error("internal error", 500);
      }
      return error("not found", 404);
    }

    if (path === "/api/me/pending-signatures" && request.method === "GET") {
      // "me" resolves from an active gw_session; a trusted OIDC client has
      // no single identity of its own, so it must name one explicitly via
      // ?did=, asserting it's authorized to act for that DID -- same split
      // as every ward-name-scoped endpoint above, just without a name in
      // the URL to carry that role here.
      const sessionId = readCookie(request, "gw_session");
      const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
      let did = sessionWardDid;
      if (!did) {
        const trustedClient = await authenticateOidcClient(request, env);
        if (!trustedClient) return error("must be signed in, or a trusted client naming ?did=, to list pending signatures", 403);
        did = url.searchParams.get("did");
        if (!did) return error("did query parameter is required for a trusted client", 400);
      }
      const rows = await listPendingForSigner(env, did);
      return json({ pending: rows.map((r) => ({ id: r.id, ward_did: r.ward_did, op_type: r.op_type, state: r.state, created_at: r.created_at, expires_at: r.expires_at })) });
    }

    if (path === "/login" && (request.method === "GET" || request.method === "POST")) {
      // This registrar's own first-party login (votingPage.ts) -- distinct
      // from the OIDC relying-party flow (/authorize, oidc.ts): no
      // client_id/redirect_uri registration, just "sign in, then take me
      // back to whatever first-party page sent me here" (the voting page,
      // today; any future first-party HTML page this registrar grows).
      return handleDirectLogin(request, env, url);
    }

    if (path === "/verify-email" && request.method === "GET") {
      const token = url.searchParams.get("token");
      if (!token) return error("token is required", 400);
      const result = await confirmEmailForwarding(env, token);
      return result.ok
        ? new Response(`Mail forwarding confirmed for ${result.did}.`, { headers: { "content-type": "text/plain" } })
        : error(result.reason, 400);
    }

    if (path === "/register" && request.method === "POST") {
      try {
        const body = (await request.json()) as { name?: string; guardian_did?: string };
        if (!body.name) return error("name is required", 400);
        // guardian_did is only ever honored for a trusted OIDC client (the
        // same credential already used at /token) -- an unauthenticated
        // caller's guardian_did is silently ignored, not an error, since
        // plain self-service registration (no guardian) is still a normal,
        // valid request shape.
        const client = await authenticateOidcClient(request, env);
        const result = await registerWard(env, body.name, client ? body.guardian_did : null);
        return json(result, 201);
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        console.error("register error:", e);
        return error("internal error", 500);
      }
    }

    if (path.startsWith("/.well-known/openid-configuration") || path.startsWith("/.well-known/jwks.json") || path.startsWith("/authorize") || path.startsWith("/token") || path.startsWith("/userinfo")) {
      return handleOidcRequest(request, env);
    }

    return error("not found", 404);
  },

  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    await handleEmail(message, env);
  },

  /** Daily reminder sweep for still-collecting proposals -- see pendingOps.ts's own sendDailyReminders. Cron schedule set in each deployment's own wrangler config (triggers.crons). */
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    await sendDailyReminders(env);
  },
};
