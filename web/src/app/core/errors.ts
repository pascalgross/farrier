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
 * A 401 is by far the most likely one and has a specific cause — a wrong or expired token — so it is
 * named rather than rendered as a status code somebody has to look up. Everything else prefers the
 * control plane's own message: the API writes those for a human reading a curl output during an
 * incident, and repeating them here means the browser and the terminal say the same thing.
 */
export function describeError(err: unknown): string {
  const carrier = err as StatusCarrier | null;
  const status = carrier?.status;
  if (status === 401) {
    return 'The control plane rejected this token. Sign out and enter the one it printed at startup.';
  }
  if (status === 0 || status === undefined) {
    return 'The control plane could not be reached.';
  }
  const message = carrier?.error?.message;
  return message ? message : `The control plane returned ${status}.`;
}
