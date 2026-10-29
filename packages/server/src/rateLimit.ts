import type { Env } from "./env.js";

/** Client IP from Cloudflare's own edge header. Never forwarded/spoofable by the caller -- Cloudflare sets this itself on every request reaching a Worker. */
export function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

/**
 * Fixed-window per-key rate limit backed by KV. Returns true if the caller
 * is still under `limit` within the current `windowSeconds` window, false
 * if they've hit it.
 *
 * KV reads/writes aren't strongly consistent, so a true concurrent burst
 * from the same IP can let a few extra requests slip past the exact limit
 * -- acceptable here, since this exists to blunt scripted abuse and cap
 * CPU-bound cost (PBKDF2 on /register and /guardian-login), not to serve
 * as a precise or adversarially-tight boundary.
 */
export async function checkRateLimit(env: Env, bucket: string, key: string, limit: number, windowSeconds: number): Promise<boolean> {
  if (!env.RATE_LIMIT_KV) return true; // no KV bound (e.g. a deployment that hasn't configured it yet) -- fail open, never block legitimate traffic over a missing binding.
  const window = Math.floor(Date.now() / 1000 / windowSeconds);
  const kvKey = `rl:${bucket}:${key}:${window}`;
  const current = parseInt((await env.RATE_LIMIT_KV.get(kvKey)) ?? "0", 10);
  if (current >= limit) return false;
  await env.RATE_LIMIT_KV.put(kvKey, String(current + 1), { expirationTtl: windowSeconds * 2 });
  return true;
}
