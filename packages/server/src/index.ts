import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { registerWard, reissueLoginSecret, resolveDocument, resolveLog, rotateWard, relinquishWard, tombstoneWard, submitOperation, RegistrarError } from "./registrar.js";
import { proposeOperation, contributeToOperation, declineOperation, listPendingForSigner } from "./pendingOps.js";
import { handleOidcRequest } from "./oidc.js";
import { handleEmail, requestEmailForwarding, confirmEmailForwarding } from "./email.js";
import { readCookie, resolveSession } from "./login.js";
import { authenticateOidcClient } from "./clientAuth.js";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function error(message: string, status: number): Response {
  return json({ error: message }, status);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    const wellKnownMatch = path.match(/^\/\.well-known\/guardian\/([^/]+)(\/log|\/operations|\/operations\/propose|\/email|\/login-secret|\/rotate|\/relinquish|\/tombstone)?$/);
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
        if (suffix === "/operations/propose" && request.method === "POST") {
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
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        return error("internal error", 500);
      }
      return error("not found", 404);
    }

    const pendingContributeMatch = path.match(/^\/pending\/([^/]+)\/contribute$/);
    if (pendingContributeMatch && request.method === "POST") {
      try {
        const [, id] = pendingContributeMatch;
        const body = (await request.json()) as { signer_did?: string; sig?: string };
        if (!body.signer_did || !body.sig) return error("signer_did and sig are required", 400);
        const result = await contributeToOperation(env, id, body.signer_did, body.sig);
        return json(result);
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        console.error("contribute error:", e);
        return error("internal error", 500);
      }
    }

    const pendingDeclineMatch = path.match(/^\/pending\/([^/]+)\/decline$/);
    if (pendingDeclineMatch && request.method === "POST") {
      try {
        const [, id] = pendingDeclineMatch;
        const result = await declineOperation(env, id);
        return json(result);
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        return error("internal error", 500);
      }
    }

    if (path === "/pending" && request.method === "GET") {
      const signer = url.searchParams.get("signer");
      if (!signer) return error("signer query parameter is required", 400);
      const rows = await listPendingForSigner(env, signer);
      return json({ pending: rows.map((r) => ({ id: r.id, ward_did: r.ward_did, op_type: r.op_type, state: r.state, created_at: r.created_at, expires_at: r.expires_at })) });
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
};
