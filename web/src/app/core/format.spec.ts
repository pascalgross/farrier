import { formatAge, formatDuration, formatOffset } from './format';

describe('formatOffset', () => {
  /**
   * The sign was inverted once and the page still rendered: the number was right and only the word was
   * wrong. The agent computes the offset as its own clock minus the control plane's, so a positive
   * value is a host running ahead — and a fleet tool that says "behind" when a host is ahead sends
   * somebody looking in the wrong direction during the incident where it matters.
   */
  it('renders a positive offset as ahead, because the agent reports local minus server', () => {
    expect(formatOffset(600)).toBe('10m ahead');
    expect(formatOffset(-600)).toBe('10m behind');
  });

  /** Zero and non-finite values must not render as "0s ahead". */
  it('renders no offset as in sync', () => {
    expect(formatOffset(0)).toBe('in sync');
    expect(formatOffset(Number.NaN)).toBe('in sync');
  });
});

describe('formatDuration', () => {
  /** Precision drops as the value grows: "3d" is what somebody wants from an uptime. */
  it('renders each magnitude with a single unit', () => {
    expect(formatDuration(45)).toBe('45s');
    expect(formatDuration(90)).toBe('1m');
    expect(formatDuration(7200)).toBe('2h');
    expect(formatDuration(3 * 86400)).toBe('3d');
  });

  /** A negative or non-finite duration is missing data, not a duration. */
  it('renders nonsense as an em dash rather than a number', () => {
    expect(formatDuration(-1)).toBe('—');
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe('—');
  });
});

describe('formatAge', () => {
  /**
   * Ages are computed against the control plane's clock rather than the browser's, so an operator whose
   * laptop clock is wrong still sees accurate ages — and a fleet tool never shows "last seen in 3
   * hours", which would undermine the one number people check first.
   */
  it('measures against the server clock, not the browser', () => {
    expect(formatAge('2026-08-22T12:00:00Z', '2026-08-22T12:05:00Z')).toBe('5m ago');
    expect(formatAge(null, '2026-08-22T12:05:00Z')).toBe('never');
  });

  /** A host seen fractionally in the future — clock skew — must not render as a negative age. */
  it('clamps a future timestamp to zero rather than showing a negative age', () => {
    expect(formatAge('2026-08-22T12:05:00Z', '2026-08-22T12:00:00Z')).toBe('0s ago');
  });
});
