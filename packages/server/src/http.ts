/**
 * `Request.prototype.formData()` throws when the request has no body at
 * all (not just a malformed one) -- a bare POST with no Content-Type and
 * no body, which every handler here previously called directly,
 * uncaught. Found live: POST /account/tombstone 500'd on an empty POST
 * instead of returning the clean 400 its own "confirm" field validation
 * was already set up to produce. Returns an empty FormData on failure
 * instead of throwing, so every caller's own existing "missing/invalid
 * field" check runs exactly as if an empty form had been submitted,
 * rather than needing its own try/catch.
 */
export async function safeFormData(request: Request): Promise<FormData> {
  try {
    return await request.formData();
  } catch {
    return new FormData();
  }
}
