/**
 * Turning an HTTP failure into something worth showing an operator.
 *
 * It lives in one file rather than in each page because the useful part is the wording, and three
 * pages each phrasing a 401 differently would teach an operator that the message depends on where they
 * happened to be standing rather than on what went wrong.
 */

/** The one field of Angular's HttpErrorResponse this module needs, without importing the class. */
interface StatusCarrier {
  /** The HTTP status, or 0 when the request never reached the server. */
  status?: number;

  /** The problem document the control plane returns, when it got far enough to write one. */
  error?: ProblemDocument;
}

/** The body the control plane returns with a non-2xx status. */
interface ProblemDocument {
  /** A stable machine-readable code, such as `self_approval`. */
  error?: string;

  /** Human-readable text, written for somebody reading a curl output during an incident. */
  message?: string;
}

/**
 * Describes an HTTP failure.
 *
 * A 401 is by far the most likely one and has a specific cause — a credential that has expired, been
 * revoked or was wrong to begin with — so it is named rather than rendered as a status code somebody
 * has to look up. It deliberately does not say which of the two credentials failed: a session and a
 * bearer token expire for different reasons, and an operator who is told the wrong one has been sent
 * to look in the wrong place. Everything else prefers the control plane's own message: the API writes
 * those for a human reading a curl output during an incident, and repeating them here means the
 * browser and the terminal say the same thing.
 */
export function describeError(err: unknown): string {
  const carrier = err as StatusCarrier | null;
  const status = carrier?.status;
  if (status === 401) {
    return 'The control plane refused this credential. Sign in again.';
  }
  if (status === 0 || status === undefined) {
    return 'The control plane could not be reached.';
  }
  const message = carrier?.error?.message;
  return message ? message : `The control plane returned ${status}.`;
}

/**
 * Describes a credential that authenticated and reaches nothing this interface renders.
 *
 * The control plane answers 403 `not_an_operator` when a platform credential — which administers
 * fleets and deliberately reaches no fleet's hosts or jobs — is used on a fleet route, and its message
 * says exactly that. It is worth showing verbatim and worth telling apart from a wrong password: one
 * sends somebody to check what they typed, and the other sends them to find their other token.
 *
 * Everything else is not this function's business, so it returns an empty string and the caller falls
 * back to describeError.
 */
export function describeRefusedCredential(err: unknown): string {
  const carrier = err as StatusCarrier | null;
  if (carrier?.status !== 403) {
    return '';
  }
  return carrier.error?.message ?? '';
}
