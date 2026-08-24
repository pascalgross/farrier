/**
 * How the closed event vocabulary is rendered.
 *
 * One table, in one file, because the vocabulary is closed on the server for exactly this reason: a
 * kind is a word operators build filters and dashboards on, and a page that invented its own label
 * for `job.expired` would be a page whose reader learns two names for one thing. Adding a member on
 * the server means adding a row here, and an unknown kind falls back to its wire name rather than
 * being hidden — an event nobody has taught the UI about is still an event.
 */

import { Tone } from './tone';

/** How one event kind is presented: a label, an icon, and how much it should alarm somebody. */
export interface EventKindStyle {
  /** The human-readable name. */
  label: string;

  /** A Material icon ligature. */
  icon: string;

  /** The severity band, which picks the colour. The bands are shared; see `core/tone.ts`. */
  tone: Tone;
}

/** The complete vocabulary, matching `internal/notify/kinds.go`. */
export const EVENT_KINDS: Record<string, EventKindStyle> = {
  'host.enrolled': { label: 'Host enrolled', icon: 'add_circle_outline', tone: 'info' },
  'host.silent': { label: 'Host silent', icon: 'cloud_off', tone: 'bad' },
  'host.recovered': { label: 'Host recovered', icon: 'cloud_done', tone: 'info' },
  'job.created': { label: 'Job queued', icon: 'playlist_add', tone: 'info' },
  'job.approved': { label: 'Job released', icon: 'how_to_reg', tone: 'info' },
  'job.failed': { label: 'Job failed', icon: 'error_outline', tone: 'bad' },
  'job.expired': { label: 'Job expired', icon: 'timer_off', tone: 'warn' },
  'service.failed': { label: 'Unit failed', icon: 'report_problem', tone: 'bad' },
  'service.recovered': { label: 'Unit recovered', icon: 'check_circle_outline', tone: 'info' },
  'updates.pending': { label: 'Security updates', icon: 'security', tone: 'warn' },
  'updates.resolved': { label: 'Updates cleared', icon: 'verified_user', tone: 'info' },
  'reboot.overdue': { label: 'Reboot overdue', icon: 'restart_alt', tone: 'warn' },
  'reboot.done': { label: 'Reboot done', icon: 'restart_alt', tone: 'info' },
};

/** Describes one kind, falling back to its wire name so an unknown event is still legible. */
export function describeKind(kind: string): EventKindStyle {
  return EVENT_KINDS[kind] ?? { label: kind, icon: 'notifications', tone: 'info' };
}

