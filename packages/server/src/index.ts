import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { registerWard, resolveDocument, resolveLog, submitOperation, RegistrarError } from "./registrar.js";
import { handleOidcRequest } from "./oidc.js";
import { handleEmail, requestEmailForwarding, confirmEmailForwarding } from "./email.js";
import { readCookie, resolveSession } from "./login.js";

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

    const wellKnownMatch = path.match(/^\/\.well-known\/guardian\/([^/]+)(\/log|\/operations|\/email)?$/);
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
        if (suffix === "/email" && request.method === "POST") {
          // Out of scope for the bare-domain root identity in this pass --
          // not attempted here rather than half-wired (email forwarding's
          // own name-keyed lookups assume a real registered name).
          if (name === null) return error("email forwarding is not available for the bare-domain identity", 400);
          // Only the ward itself (an active gw_session for its own DID) may
          // set up forwarding for its own address -- otherwise anyone could
          // redirect someone else's mail just by naming their identity.
          const sessionId = readCookie(request, "gw_session");
          const sessionWardDid = sessionId ? await resolveSession(env, sessionId) : null;
          if (!sessionWardDid || sessionWardDid !== didFor(name, env.REGISTRAR_DOMAIN)) {
            return error("must be signed in as this identity to set up its mail forwarding", 403);
          }
          const body = (await request.json()) as { forward_to?: string };
          if (!body.forward_to) return error("forward_to is required", 400);
          const result = await requestEmailForwarding(env, name, body.forward_to);
          return result.ok ? json({ ok: true, message: "verification email sent" }) : error(result.reason, 400);
        }
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        return error("internal error", 500);
      }
      return error("not found", 404);
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
        const body = (await request.json()) as { name?: string };
        if (!body.name) return error("name is required", 400);
        const result = await registerWard(env, body.name);
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
