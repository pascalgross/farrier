import { UnitState } from './api.models';
import { describeUnit, explainUnit, isUnloadable } from './unit-state';

/** Builds one reported unit, so each spec below names only the states it is actually about. */
function unit(loadState: string, activeState: string, subState = 'dead'): UnitState {
  return { name: 'nginx.service', loadState, activeState, subState };
}

describe('describeUnit', () => {
  /**
   * The distinction the whole module exists for. A masked unit and a crashed unit are different
   * problems, and a dashboard that paints both red teaches operators to ignore it — which is the
   * failure mode issue #5 names, and the one the permanently amber Ubuntu Pro badge on Debian had.
   */
  it('tells a crash, a mask and a missing unit file apart', () => {
    expect(describeUnit(unit('loaded', 'failed', 'exited')).condition).toBe('failed');
    expect(describeUnit(unit('masked', 'inactive')).condition).toBe('masked');
    expect(describeUnit(unit('not-found', 'inactive')).condition).toBe('not-found');
    expect(describeUnit(unit('error', 'inactive')).condition).toBe('unreadable');
  });

  /**
   * The load state is read first, and this is the case that proves why. systemd will report a masked
   * unit as `failed` when something tried to start it, and reading the active state first would turn
   * "somebody pinned nginx off" into "nginx crashed" — sending an operator to look for a fault in a
   * service nobody is running.
   */
  it('reads the load state first, so a masked unit reporting failed is still masked', () => {
    const described = describeUnit(unit('masked', 'failed', 'failed'));
    expect(described.condition).toBe('masked');
    expect(described.tone).toBe('warn');
  });

  /** The colours have to differ too, or the words are the only difference and nobody reads them. */
  it('gives a crash a different tone from a unit systemd never loaded', () => {
    expect(describeUnit(unit('loaded', 'failed', 'exited')).tone).toBe('bad');
    expect(describeUnit(unit('not-found', 'inactive')).tone).toBe('warn');
    expect(describeUnit(unit('loaded', 'active', 'running')).tone).toBe('info');
  });

  /** A spelling this console has not been taught is rendered, not alarmed about. */
  it('falls back to the reported active state for a load state it does not know', () => {
    expect(describeUnit(unit('stub', 'activating', 'start')).condition).toBe('running');
    expect(describeUnit(unit('stub', 'activating', 'start')).label).toBe('activating');
  });
});

describe('isUnloadable', () => {
  /** The set the pages group on: everything systemd could not load, and nothing else. */
  it('holds masked, missing and unreadable units, and no failure that actually ran', () => {
    expect(isUnloadable(unit('masked', 'inactive'))).toBeTrue();
    expect(isUnloadable(unit('not-found', 'inactive'))).toBeTrue();
    expect(isUnloadable(unit('bad-setting', 'inactive'))).toBeTrue();
    expect(isUnloadable(unit('loaded', 'failed', 'exited'))).toBeFalse();
    expect(isUnloadable(unit('loaded', 'active', 'running'))).toBeFalse();
  });
});

describe('explainUnit', () => {
  /**
   * The console interpreting a state is never a reason to stop showing what the host said: the
   * sentence is what an operator acts on, and the three raw words are what they quote into a
   * `systemctl` command.
   */
  it('repeats the raw states verbatim after the explanation', () => {
    expect(explainUnit(unit('masked', 'failed', 'dead'))).toContain('masked / failed / dead');
  });
});
