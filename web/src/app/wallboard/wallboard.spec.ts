import { ComponentFixture, TestBed } from '@angular/core/testing';
import { WritableSignal, provideZonelessChangeDetection } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Observable, of, throwError } from 'rxjs';

import { ApiService } from '../core/api.service';
import { WallboardAttention, WallboardView } from '../core/api.models';
import { Wallboard } from './wallboard';

/** Builds one answer from the control plane, so each spec names only the part it is about. */
function view(partial: Partial<WallboardView> = {}): WallboardView {
  return {
    serverTime: '2026-08-28T09:14:02Z',
    pollSeconds: 15,
    title: 'Production — Frankfurt',
    hosts: { total: 4, ok: 4, bad: 0, unknown: 0 },
    security: { hosts: 0, packages: 0, unknown: 0 },
    reboots: { hosts: 0, unknown: 0 },
    units: { hosts: 0, unknown: 0 },
    attention: [],
    attentionOmitted: 0,
    ...partial,
  };
}

/** Builds one tile, so a spec about the grid does not have to spell out a whole host. */
function tile(partial: Partial<WallboardAttention> = {}): WallboardAttention {
  return {
    hostname: 'web-07',
    status: 'bad',
    reason: 'offline',
    detail: 'no heartbeat for 14 minutes',
    ...partial,
  };
}

/**
 * A refusal from the control plane, in the shape this application's error helpers read.
 *
 * A plain object rather than an `HttpErrorResponse`: what the board branches on is the status and the
 * problem document's code, which `core/errors.ts` reads by duck typing precisely so that neither it
 * nor a spec has to hold the framework's class. Building one here would be testing Angular.
 */
interface Refusal {
  /** The HTTP status, zero for a request that never reached the control plane at all. */
  status: number;

  /** The problem document, absent when the failure never got as far as one being written. */
  error?: {
    /** The stable machine-readable code, such as `passphrase_required`. */
    error?: string;

    /** The sentence the control plane wrote for whoever is reading. */
    message?: string;
  };
}

/**
 * The control plane, under a spec's control.
 *
 * A mutable object rather than a fixed observable because the behaviour worth pinning is what
 * happens when a board that *was* answering stops: the failures here are the interesting half, and
 * they only mean something after a success.
 */
interface Fake {
  /** What the next poll answers with. */
  answer: WallboardView;

  /** What the next poll fails with, null when it succeeds. */
  failure: Refusal | null;

  /** How many polls have been made, which is how "it stopped polling" is asserted. */
  polls: number;
}

/**
 * The two signals a spec reaches into, named so the cast below stays readable.
 *
 * Protected on the component because they are the template's, and a spec that ages a board the way
 * the ticker does has to say so out loud rather than widen the component's surface. Reaching for
 * them is what lets the staleness thresholds be tested without a fake clock: the arithmetic under
 * test is "browser now, minus browser then", and both halves are here.
 */
interface BoardInternals {
  /** The browser's clock as the board sees it, advanced once a second by the ticker. */
  now: WritableSignal<number>;

  /** When the last poll succeeded, by the same clock. */
  lastSuccessAt: WritableSignal<number>;
}

/** Renders the board against a controllable control plane. */
function render(fake: Fake, isPublic = false): ComponentFixture<Wallboard> {
  const poll = (): Observable<WallboardView> => {
    fake.polls += 1;
    return fake.failure ? throwError(() => fake.failure) : of(fake.answer);
  };

  // Reset first, so one spec can render twice — the pair of assertions about the share panel is one
  // property, and splitting it into two specs would let either half pass alone.
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ActivatedRoute,
        useValue: {
          snapshot: { data: isPublic ? { public: true } : {} },
        } as unknown as ActivatedRoute,
      },
      {
        provide: ApiService,
        useValue: {
          wallboard: poll,
          publicWallboard: poll,
          wallboardShares: () => of({ shares: [], serverTime: '2026-08-28T09:14:02Z' }),
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(Wallboard);
  fixture.detectChanges();
  return fixture;
}

/** Builds a control plane that answers, so a spec only says how it differs. */
function answering(partial: Partial<WallboardView> = {}): Fake {
  return { answer: view(partial), failure: null, polls: 0 };
}

/** Collapses whitespace, so an assertion can be written the way the screen actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

/** Moves the board's own clock forward by this many seconds, as the one-second ticker would. */
function age(fixture: ComponentFixture<Wallboard>, seconds: number): void {
  const board = fixture.componentInstance as unknown as BoardInternals;
  board.now.set(board.now() + seconds * 1000);
  fixture.detectChanges();
}

describe('Wallboard freshness', () => {
  /**
   * The failure this whole screen exists to avoid. A board that could not read the fleet must not
   * render numbers about it, because a room reads a counter as a statement about now — and the one
   * that is easiest to get wrong is the first poll of the day, where there is nothing to show but
   * the page still has to render something.
   */
  it('renders no fleet health at all when the first poll has failed', () => {
    const fake = answering();
    fake.failure = { status: 500, error: { message: 'the database is unreachable' } };
    const fixture = render(fake);

    expect(fixture.nativeElement.querySelector('.wb')).toBeNull();
    expect(fixture.nativeElement.querySelectorAll('.wb__counter').length).toBe(0);
    expect(text(fixture.nativeElement)).toContain('Waiting for the first read');
  });

  /**
   * Between two and six poll intervals the numbers stay and the claim that they are current is
   * withdrawn. Both halves matter: dropping the numbers this early would blind a room over one
   * restart of the control plane, and keeping the greens would let it walk past a frozen screen.
   */
  it('names the age and the last good read once the data is stale, keeping the numbers', () => {
    const fake = answering({ hosts: { total: 9, ok: 8, bad: 1, unknown: 0 }, attention: [tile()] });
    const fixture = render(fake);
    fake.failure = { status: 503, error: { message: 'the control plane is restarting' } };

    age(fixture, 45);

    const board = fixture.nativeElement.querySelector('.wb');
    expect(board).not.toBeNull();
    expect(board.classList.contains('wb--stale')).toBeTrue();
    expect(fixture.nativeElement.querySelectorAll('.wb__counter').length).toBe(3);
    expect(text(fixture.nativeElement.querySelector('.wb__stale'))).toContain('Not updated for 45s');
    expect(text(fixture.nativeElement.querySelector('.wb__stale'))).toContain('last good read was at');
  });

  /**
   * Past six intervals the numbers go. What replaces them says both the age and the absolute time,
   * because "four minutes ago" does not distinguish a control plane that is restarting from a
   * browser that was asleep all night.
   */
  it('withdraws the numbers entirely once the data is older than six poll intervals', () => {
    const fake = answering({ hosts: { total: 9, ok: 9, bad: 0, unknown: 0 } });
    const fixture = render(fake);
    fake.failure = { status: 0 };

    age(fixture, 15 * 7);

    expect(fixture.nativeElement.querySelector('.wb')).toBeNull();
    expect(fixture.nativeElement.querySelectorAll('.wb__counter').length).toBe(0);
    expect(text(fixture.nativeElement)).toContain('since this board could read the fleet');
    expect(text(fixture.nativeElement)).toContain('Last good read at');
  });
});

describe('Wallboard states', () => {
  /**
   * An empty grid reads as a page that failed to render, which is the worst possible rendering of
   * "everything is fine" — the state a room is most often walking past.
   */
  it('renders an all-clear panel when there are hosts and nothing needs attention', () => {
    const fixture = render(answering({ hosts: { total: 12, ok: 12, bad: 0, unknown: 0 } }));

    expect(fixture.nativeElement.querySelector('.wb__grid')).toBeNull();
    expect(fixture.nativeElement.querySelector('.wb__panel--clear')).not.toBeNull();
    expect(text(fixture.nativeElement)).toContain('Nothing needs anybody');
    expect(text(fixture.nativeElement)).toContain('All 12 of 12 hosts');
  });

  /**
   * Zero hosts well out of zero hosts is arithmetically an all-clear and means nothing is being
   * watched. It is also what a deleted fleet's scoped read answers with, so a board that painted it
   * green would go on reassuring a room about a fleet that no longer exists.
   */
  it('never renders an all-clear for a fleet with no hosts', () => {
    const fixture = render(answering({ hosts: { total: 0, ok: 0, bad: 0, unknown: 0 } }));

    expect(fixture.nativeElement.querySelector('.wb__panel--clear')).toBeNull();
    expect(fixture.nativeElement.querySelector('.wb').classList.contains('wb--empty')).toBeTrue();
    expect(text(fixture.nativeElement)).toContain('No hosts are enrolled in this fleet');
  });

  /**
   * The tiles are examples and the counters are the truth. A grid that silently stopped at twelve
   * would hide the thirteenth failing host using the mechanism meant to make the screen readable.
   */
  it('says how many hosts the grid is not showing', () => {
    const fixture = render(
      answering({
        hosts: { total: 400, ok: 263, bad: 137, unknown: 0 },
        attention: [
          tile({ hostname: 'web-07' }),
          tile({ hostname: 'db-02', reason: 'unit_failed' }),
        ],
        attentionOmitted: 125,
      }),
    );

    expect(fixture.nativeElement.querySelectorAll('.wb__tile').length).toBe(2);
    expect(text(fixture.nativeElement.querySelector('.wb__more'))).toContain('and 125 more hosts');
  });

  /**
   * Colour is never the only carrier: this screen is read at three metres, including by people who
   * will not separate the red from the amber. Every tile says its reason in words as well.
   */
  it('writes the reason for each tile in words as well as in colour', () => {
    const fixture = render(
      answering({
        hosts: { total: 3, ok: 1, bad: 1, unknown: 1 },
        attention: [
          tile({ hostname: 'db-02', reason: 'unit_failed', detail: '2 units failed' }),
          tile({
            hostname: 'edge-11',
            status: 'unknown',
            reason: 'never_seen',
            detail: 'enrolled, never reported',
          }),
        ],
      }),
    );

    const tiles = Array.from(fixture.nativeElement.querySelectorAll('.wb__tile')) as Element[];
    expect(text(tiles[0])).toContain('unit failed');
    expect(text(tiles[1])).toContain('never seen');
    expect(tiles[0].classList.contains('wb__tile--bad')).toBeTrue();
    expect(tiles[1].classList.contains('wb__tile--bad')).toBeFalse();
  });
});

describe('Wallboard credentials', () => {
  // A published board takes its key from the fragment, so a spec about one has to put it there. The
  // address is restored afterwards: the spec below about a link with no key depends on there being
  // none, and a fragment left behind would make it pass for the wrong reason.
  afterEach(() => {
    location.hash = '';
  });
  /**
   * A refusal is terminal. Retrying a withdrawn share every fifteen seconds until somebody unplugs
   * the television is a bucket kept warm for nothing, and a board that kept its numbers behind the
   * message would be showing a fleet it is no longer entitled to read.
   */
  it('clears the board and stops polling when the credential is refused', () => {
    const fake = answering();
    fake.failure = { status: 401, error: { error: 'unauthorized', message: 'no' } };
    const fixture = render(fake);

    expect(fixture.nativeElement.querySelector('.wb')).toBeNull();
    expect(text(fixture.nativeElement)).toContain('will not come back on its own');
    expect(fake.polls).toBe(1);
  });

  /**
   * The one 401 that is not a refusal: a screen that has not been unlocked yet. It gets a form
   * rather than an epitaph, and no numbers in the meantime.
   */
  it('asks for the passphrase when the share carries one', () => {
    const fake = answering();
    fake.failure = { status: 401, error: { error: 'passphrase_required', message: 'locked' } };
    location.hash = 'frb_01JTENANT.abcdefghijklmnopqrstuvwxyz';
    const fixture = render(fake, true);

    expect(fixture.nativeElement.querySelector('.wb')).toBeNull();
    expect(text(fixture.nativeElement)).toContain('This board is locked');
    expect(fixture.nativeElement.querySelector('input[type="password"]')).not.toBeNull();
  });

  /**
   * A link whose fragment was eaten in transit — by a chat client, or by somebody retyping it from a
   * photograph — is refused here rather than sent. An empty bearer token would come back as an
   * ordinary refusal, and the screen would blame the share for a mistake made in the address bar.
   */
  it('never polls a published board whose address carries no key', () => {
    const fake = answering();
    const fixture = render(fake, true);

    expect(fake.polls).toBe(0);
    expect(text(fixture.nativeElement)).toContain('This address carries no key');
  });

  /**
   * The share panel belongs to whoever can publish one, and a published board renders alone: no
   * toolbar, no navigation, and nothing offering a corridor screen a route it has no credential for.
   */
  it('offers the share panel to an operator and never on a published board', () => {
    const framed = render(answering()).nativeElement;
    const published = render(answering(), true).nativeElement;

    expect(framed.querySelector('farrier-share-panel')).not.toBeNull();
    expect(published.querySelector('farrier-share-panel')).toBeNull();

    // The class the shell's copy of the board is sized by. Without it the operator's board is a full
    // viewport tall and the share panel underneath it starts below the fold — which for a panel
    // nobody knows exists is the same as it not being there.
    expect(framed.classList.contains('farrier-wallboard--framed')).toBeTrue();
    expect(published.classList.contains('farrier-wallboard--framed')).toBeFalse();
  });
});
