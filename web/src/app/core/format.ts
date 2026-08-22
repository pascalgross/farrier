/**
 * Small formatting helpers shared by the fleet list and the host detail page.
 *
 * They live in one module so that a duration renders identically everywhere. A dashboard where the same
 * value is written two ways in two places is one whose reader stops trusting either.
 */

/**
 * Renders a duration in seconds as a short human-readable string.
 *
 * The precision deliberately drops as the value grows: "3 days" is what somebody wants to know about an
 * uptime, and "3 days, 4 hours, 12 minutes" is noise they have to read past.
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return '—';
  }
  if (seconds < 60) {
    return `${Math.floor(seconds)}s`;
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m`;
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h`;
  }
  return `${Math.floor(seconds / 86400)}d`;
}

/**
 * Renders how long ago an instant was, relative to the control plane's clock.
 *
 * The server's time is used rather than the browser's on purpose: an operator whose laptop clock is
 * wrong should still see accurate ages, and a fleet tool that showed "last seen in 3 hours" because of
 * a local clock would undermine the one number people check first.
 */
export function formatAge(instant: string | null, now: string): string {
  if (!instant) {
    return 'never';
    }
  const then = Date.parse(instant);
  const reference = Date.parse(now);
  if (Number.isNaN(then) || Number.isNaN(reference)) {
    return '—';
  }
  const seconds = Math.max(0, (reference - then) / 1000);
  return `${formatDuration(seconds)} ago`;
}

/**
 * Renders a clock offset with its sign, so "ahead" and "behind" are distinguishable.
 *
 * The sign matters more than the magnitude: a host running ahead of the control plane and one running
 * behind it fail in different ways, and both are worth telling apart at a glance.
 *
 * The agent computes the offset as its own clock minus the control plane's, so a **positive** value is
 * a host running **ahead**. Getting this backwards is the sort of mistake that survives review — the
 * page still renders, the number is still right, and only the word is wrong — so it is stated here and
 * pinned by a test.
 */
export function formatOffset(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds === 0) {
    return 'in sync';
  }
  const magnitude = formatDuration(Math.abs(seconds));
  return seconds > 0 ? `${magnitude} ahead` : `${magnitude} behind`;
}
