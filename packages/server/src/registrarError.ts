/** REQ-10-4: a rejected operation gets HTTP 400 with {error: <this message>} by default; a route raises a different `status` for e.g. 404 (not found) or 409 (conflict). */
export class RegistrarError extends Error {
  constructor(message: string, public status: number = 400) {
    super(message);
  }
}
