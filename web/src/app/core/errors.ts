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
 * Reads the machine-readable code out of a refusal, empty when there is none.
 *
 * The message is for a person and the code is for a branch, and until now nothing in the browser
 * needed the second — every failure rendered as a sentence. The wallboard does: a 401 saying
 * `passphrase_required` is a screen that has not been unlocked yet and must show a form, while every
 * other 401 is a credential that has stopped working and must stop polling for ever. Matching on the
 * wording of the sentence would be the alternative, and it would break the first time somebody
 * improved the sentence.
 *
 * It lives here rather than in the page for the reason the rest of this module exists: the shape of a
 * problem document is the control plane's, and one file should know it.
 */
export function errorCode(err: unknown): string {
  return (err as StatusCarrier | null)?.error?.error ?? '';
}

/**
 * Reads the HTTP status out of a failure, zero when the request never reached the control plane.
 *
 * Its caller is the wallboard, which is the first thing in this application that has to *act* on a
 * status rather than describe one: a refusal is terminal and stops the board polling for good, while
 * a control plane that could not answer is retried until it can. Getting that the wrong way round is
 * either a screen that goes dark over one restart or a dead share retried every fifteen seconds for
 * a year.
 *
 * Zero for an unreachable control plane, matching what Angular reports and what `describeError`
 * already treats as "could not be reached", so the two agree about the same failure.
 */
export function errorStatus(err: unknown): number {
  return (err as StatusCarrier | null)?.status ?? 0;
}

/**
 * Describes a control plane that could not answer, as distinct from one that refused.
 *
 * It exists for one caller and one moment: the identity probe the shell makes on start. That request
 * has two failure modes and they mean opposite things. A 401 is the ordinary answer for a browser that
 * has not signed in, and belongs on no screen at all. Anything else — a 500 because the database is
 * unreachable, or no response because the control plane is not running — is not about the credential,
 * and presenting it as one puts a sign-in form in front of somebody whose session is fine and whose
 * password will not help.
 *
 * That distinction is the browser half of `auth.ErrUnavailable`, which is what makes the control plane
 * answer 500 rather than 401 during an outage. Without this, the server's care would end at the wire:
 * the interface would render every failure as "sign in again" regardless.
 *
 * It returns an empty string for a 401, so the caller can treat "no message" as "signed out".
 */
export function describeUnavailable(err: unknown): string {
  const carrier = err as StatusCarrier | null;
  if (carrier?.status === 401) {
    return '';
  }
  const message = carrier?.error?.message;
  return message
    ? `${message} This is not a refusal — your session may be fine.`
    : 'The control plane could not say who you are. This is not a refusal: it could not answer at all.';
}
