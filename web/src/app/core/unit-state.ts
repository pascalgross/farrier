/**
 * Reading a systemd unit's two states together, so that different problems look different.
 *
 * A host reports `loadState` and `activeState` for every unit and both have always survived to the
 * browser, but the pages rendered only "failed or not" — which is the failure issue #5 names: a
 * masked unit and a crashed unit are different problems, and a dashboard that paints both red
 * teaches operators to ignore it, the same way a permanently amber Ubuntu Pro badge on Debian does.
 *
 * One table, in one file, for the same reason `event-kinds.ts` is one table: the services page and
 * the host page must not each invent their own word for a masked unit.
 */

import { UnitState } from './api.models';
import { Tone } from './tone';

/**
 * What is wrong with a unit, in one word, as far as this console distinguishes.
 *
 * Six members and not systemd's full cross product of load and active states, because the question
 * this answers is "what kind of problem is this", and the answers an operator acts on differently
 * are: it crashed, somebody turned it off, it is not there, its unit file is unreadable, it is
 * loaded and idle, or it is fine.
 */
export type UnitCondition =
  | 'failed'
  | 'masked'
  | 'not-found'
  | 'unreadable'
  | 'inactive'
  | 'running';

/** How one unit's condition is presented: what to call it, what to draw, and how loudly. */
export interface UnitConditionStyle {
  /** The condition, for a caller that groups units rather than renders them. */
  condition: UnitCondition;

  /** The short word shown beside the unit name. */
  label: string;

  /** A Material icon ligature. */
  icon: string;

  /** The severity band, which picks the colour. */
  tone: Tone;

  /** One sentence naming what makes this state different from a crash, for a tooltip or a caption. */
  explanation: string;
}

/**
 * Describes one unit's condition from the pair of states the host reported.
 *
 * The load state is read first and that order is the whole point. A unit systemd could not load has
 * not crashed — it is pinned off, or its unit file is gone — and whatever active state accompanies
 * that says nothing about the service the operator cares about. Reading `activeState` first would
 * collapse "somebody masked nginx" into "nginx failed", which is exactly the conflation this module
 * exists to undo.
 *
 * An unrecognised load state falls through to the active state rather than being reported as a
 * problem: systemd has spellings this console has not been taught (`stub`, `merged`), and inventing
 * an alarm for one would be worse than rendering what the host actually said.
 */
export function describeUnit(unit: UnitState): UnitConditionStyle {
  switch (unit.loadState) {
    case 'masked':
      return {
        condition: 'masked',
        label: 'masked',
        icon: 'block',
        tone: 'warn',
        explanation:
          'Masked: the unit is pinned off, so it is not running because somebody decided it should ' +
          'not be, rather than because it crashed.',
      };
    case 'not-found':
      return {
        condition: 'not-found',
        label: 'no unit file',
        icon: 'search_off',
        tone: 'warn',
        explanation:
          'No unit file: systemd has nothing by this name, so this is a missing, renamed or ' +
          'uninstalled unit rather than a crash.',
      };
    case 'error':
    case 'bad-setting':
      return {
        condition: 'unreadable',
        label: 'unreadable unit file',
        icon: 'help_outline',
        tone: 'warn',
        explanation:
          'The unit file could not be read, so what this unit would do is unknown rather than ' +
          'known to be fine.',
      };
    default:
      break;
  }

  switch (unit.activeState) {
    case 'failed':
      return {
        condition: 'failed',
        label: 'failed',
        icon: 'report_problem',
        tone: 'bad',
        explanation: 'Failed: the unit is loaded and systemd ran it, and it stopped with an error.',
      };
    case 'inactive':
      return {
        condition: 'inactive',
        label: 'inactive',
        icon: 'radio_button_unchecked',
        tone: 'info',
        explanation:
          'Inactive: loaded and not running, which for a timer, a socket or a one-shot unit may be ' +
          'exactly right.',
      };
    default:
      return {
        condition: 'running',
        label: unit.activeState,
        icon: 'check_circle_outline',
        tone: 'info',
        explanation: `Reported as ${unit.activeState}.`,
      };
  }
}

/**
 * Whether a unit is one systemd could not load at all.
 *
 * A predicate rather than three comparisons at each call site, because the set is what the pages
 * group on and a page that forgot `unreadable` would silently drop the units nobody can explain.
 */
export function isUnloadable(unit: UnitState): boolean {
  const condition = describeUnit(unit).condition;
  return condition === 'masked' || condition === 'not-found' || condition === 'unreadable';
}

/**
 * Describes a unit's condition and then repeats the raw states verbatim.
 *
 * Both halves are needed and neither replaces the other: the sentence is what an operator acts on,
 * and the three words after it are what they quote into a `systemctl` command or a bug report. The
 * console interpreting a state is never a reason to stop showing what the host actually said.
 */
export function explainUnit(unit: UnitState): string {
  const described = describeUnit(unit);
  return `${described.explanation} Reported as ${unit.loadState} / ${unit.activeState} / ${unit.subState}.`;
}
