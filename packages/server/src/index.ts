import type { Env } from "./env.js";
import { registerWard, resolveDocument, resolveLog, submitOperation, RegistrarError } from "./registrar.js";
import { handleOidcRequest } from "./oidc.js";
import { handleEmail } from "./email.js";

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

    const wellKnownMatch = path.match(/^\/\.well-known\/guardian\/([^/]+)(\/log|\/operations)?$/);
    if (wellKnownMatch) {
      const [, name, suffix] = wellKnownMatch;
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
      } catch (e) {
        if (e instanceof RegistrarError) return error(e.message, e.status);
        return error("internal error", 500);
      }
      return error("not found", 404);
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
