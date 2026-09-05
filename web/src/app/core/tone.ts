/**
 * The severity bands the console paints with, and the colour each one maps to.
 *
 * They live apart from any one vocabulary because more than one thing is graded now: an event kind
 * has a tone, and so does a systemd unit's condition. Two tables that each invented their own bands
 * would drift, and a dashboard where amber means "needs attention" on one page and "unknown" on the
 * next is one whose reader stops distinguishing them at all.
 */

/**
 * How much something should alarm somebody.
 *
 * Three bands and not five: `bad` is something is broken, `warn` is something needs attention, and
 * `info` is something happened. A palette with more gradations than a reader can tell apart at a
 * glance is a palette they stop reading.
 */
export type Tone = 'bad' | 'warn' | 'info';

/**
 * The Tailwind text colour for a tone.
 *
 * A function rather than a class built in the template, because Tailwind's scanner needs to see each
 * class literally somewhere in the source — which the strings below satisfy — and a template
 * expression that concatenated `text-hostseal-` with a variable would not.
 */
export function toneClass(tone: Tone): string {
  switch (tone) {
    case 'bad':
      return 'text-hostseal-bad';
    case 'warn':
      return 'text-hostseal-warn';
    default:
      return 'text-hostseal-quiet';
  }
}
