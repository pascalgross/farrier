import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { ActivatedRoute } from '@angular/router';

import { ApiService } from '../core/api.service';
import { SharePanel } from './share-panel';
import { WallboardAttention, WallboardView } from '../core/api.models';
import { describeError, errorCode, errorStatus } from '../core/errors';
import { formatDuration } from '../core/format';

/**
 * How often the board's own sense of time advances, in milliseconds.
 *
 * One second, which is finer than anything it prints, and deliberately so: this ticker is the only
 * thing that ages a board nobody is touching. Every other page in this console recomputes when an
 * operator does something; a television does nothing for months, so if the age did not tick by
 * itself, a control plane that stopped answering at midnight would still be reporting "updated 2s
 * ago" at noon.
 */
const AGE_TICK_MILLISECONDS = 1000;

/**
 * The poll interval assumed before the first answer arrives, in seconds.
 *
 * The server sets the real one — see `WallboardView.pollSeconds` — and this exists only so that the
 * staleness thresholds mean something during the first request, when no answer has yet said what the
 * pacing is. Fifteen seconds matches the control plane's own default, so the two agree in the one
 * case where the browser has to guess.
 */
const DEFAULT_POLL_SECONDS = 15;

/**
 * The shortest pacing this board will accept from the server, in seconds.
 *
 * A floor rather than a validation: a control plane that answered `pollSeconds: 0` would otherwise
 * turn a wall-mounted browser into a request loop, and the staleness arithmetic below divides by this
 * number. Clamping is the version of that failure that stays on screen.
 */
const MINIMUM_POLL_SECONDS = 5;

/**
 * How many poll intervals may pass before the board stops claiming its numbers are current.
 *
 * Two, because one missed poll is ordinary — a request that lands a moment late, a control plane
 * being restarted — and a board that shouted about every one of those would be a board whose warning
 * nobody reads by the second week.
 */
const STALE_MULTIPLE = 2;

/**
 * How many poll intervals may pass before the numbers are withdrawn entirely.
 *
 * Six. Past this the board is not a fleet summary with a caveat on it, it is a photograph, and the
 * honest thing to show a room is that nothing is known rather than a set of numbers with an
 * explanation somebody has to walk up to the screen to read.
 */
const LOST_MULTIPLE = 6;

/**
 * Which of the two boards this is.
 *
 * The mode comes from the route rather than from inspecting the address or the session, because the
 * two differ in what they may do — one polls with a session, the other with a key out of the
 * fragment and shows no navigation at all — and a page that guessed would eventually guess wrong in
 * the direction that renders operator navigation on a screen in a public corridor.
 */
type WallboardMode = 'operator' | 'public';

/** How much the board still trusts what it is showing, from the age of the last successful poll. */
type Freshness = 'fresh' | 'stale' | 'lost';

/**
 * What the whole screen is currently showing.
 *
 * Five values rather than a pair of booleans, because four of them replace the board entirely and
 * only one of them renders fleet health. Making that a single closed value is what stops a future
 * template writing a condition that shows counters beside a message saying the data is gone.
 */
type BoardState = 'board' | 'waiting' | 'lost' | 'locked' | 'refused';

/**
 * How one reason is rendered, in words and as a glyph.
 *
 * Both, always, because colour is never the only carrier on this screen: it is read at three metres
 * by whoever is walking past, including the eight percent of them who will not distinguish the amber
 * from the green.
 */
interface ReasonStyle {
  /** The reason in English, which is what the tile says under the hostname. */
  word: string;

  /** A Material icon, so a tile is identifiable before any of its text is legible. */
  icon: string;
}

/**
 * The closed vocabulary of reasons, as `WallboardAttention.reason` spells them.
 *
 * A table rather than a switch so that an unrecognised member falls back instead of failing: a
 * control plane one version ahead may know a reason this bundle does not, and a blank tile for the
 * host somebody needs to walk to is the worst possible way to learn that.
 */
const REASONS: Record<string, ReasonStyle> = {
  offline: { word: 'offline', icon: 'cloud_off' },
  unit_failed: { word: 'unit failed', icon: 'error_outline' },
  clock_skewed: { word: 'clock skewed', icon: 'schedule' },
  never_seen: { word: 'never seen', icon: 'help_outline' },
  paused: { word: 'paused', icon: 'pause_circle_outline' },
  facts_unknown: { word: 'nothing reported', icon: 'help_outline' },
};

/** What an unrecognised reason renders as: still a tile, still a hostname, still worth walking to. */
const UNRECOGNISED: ReasonStyle = { word: 'needs attention', icon: 'help_outline' };

/**
 * One screen that answers "does anything in this fleet need somebody", for a room rather than a desk.
 *
 * It is not a smaller fleet list and cannot be made out of one. A fleet list is read by somebody who
 * came to read it and who will notice an error banner; this is read by somebody walking past who was
 * not looking for it, which imposes two rules the console's other pages do not carry. It must fit one
 * screen — a property of the payload being bounded at twelve tiles, never of anything in the
 * stylesheet clipping, because what would disappear behind that fold is the thirteenth failing host.
 * And it must never show a confident green screen about data it no longer holds.
 *
 * That second rule is the whole of the timing code below. The age of the data is measured on the
 * browser's own clock, taken at the moment a poll succeeded, and never from `serverTime` — which
 * arrives inside the response and freezes with it, so a board that aged itself with it would report
 * "updated a second ago" for as long as the television was powered. Past twice the poll interval the
 * greens are withdrawn and the age is named; past six times the numbers are withdrawn altogether.
 * Green is removed rather than turned red, because red says the fleet is bad and this says we do not
 * know, which is a third thing.
 *
 * The two modes differ in their credential and in nothing else. An operator's board polls with the
 * session; a published one polls with a key it reads from the address's fragment, which is never
 * transmitted, and shows a passphrase form if the control plane says the share carries one. The
 * tiles are links in neither mode: the property that the public payload is the only payload is worth
 * more than a hyperlink, and an operator who wants the host page is one click away in the toolbar.
 */
@Component({
  selector: 'hostseal-wallboard',
  imports: [
    FormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    SharePanel,
  ],
  host: {
    // Inside the shell the board shares a page with a toolbar and with the share panel below it, so
    // it takes a screen-shaped block rather than the screen. See the stylesheet.
    '[class.hostseal-wallboard--framed]': "mode === 'operator'",
  },
  templateUrl: './wallboard.html',
  styleUrl: './wallboard.scss',
})
export class Wallboard {
  /** Talks to the control plane, with whichever of the two credentials this mode carries. */
  private readonly api = inject(ApiService);

  /** Where the mode comes from: `data.public` on the route, rather than a guess about the address. */
  private readonly route = inject(ActivatedRoute);

  /** Stops both timers when the board is left, so a closed tab costs the control plane nothing. */
  private readonly destroyRef = inject(DestroyRef);

  /** Which board this is. Read once: a component instance does not change route. */
  protected readonly mode: WallboardMode;

  /** The last successful answer, null until one arrives and again once one is withdrawn. */
  protected readonly view = signal<WallboardView | null>(null);

  /**
   * When the last poll succeeded, by `Date.now()`, zero for never.
   *
   * The browser's clock and not the control plane's, which is the single decision this component
   * exists to get right. It is a wall clock rather than a monotonic one, so a machine whose time is
   * corrected by NTP while the board is up will misreport one age; that is a bounded, one-off error,
   * and the alternative — `performance.now()`, which cannot be turned into the absolute time the
   * amber band has to print — trades it for a board that cannot say *when* the last good read was.
   */
  protected readonly lastSuccessAt = signal(0);

  /** The browser's clock, advanced by the ticker so that the age moves on an untouched screen. */
  protected readonly now = signal(Date.now());

  /** Why the last poll failed, empty when it did not. Shown in the footer; it clears nothing. */
  protected readonly failure = signal('');

  /** Why this board has stopped for good, empty while it has not. A 401 or a 404 sets it. */
  protected readonly refusal = signal('');

  /** Whether the share carries a passphrase this screen has not yet proved. */
  protected readonly locked = signal(false);

  /** The passphrase being typed, held only until it is sent. */
  protected readonly passphrase = signal('');

  /** Whether an unlock is in flight, so the button can be disabled. */
  protected readonly unlocking = signal(false);

  /** Why the last unlock failed, empty when it did not. */
  protected readonly unlockError = signal('');

  /** The key this board polls with, empty in operator mode. */
  private readonly key: string;

  /** The pending poll, so it can be cancelled rather than left to fire at a dead component. */
  private timer: ReturnType<typeof setTimeout> | null = null;

  /**
   * The pacing the server asked for, floored, in seconds.
   *
   * Server-set for the reason the protocol sets the heartbeat interval: a number baked into a client
   * is a number that is wrong the day somebody changes it, and the screens carrying it are the ones
   * nobody will reload.
   */
  protected readonly pollSeconds = computed(() =>
    Math.max(MINIMUM_POLL_SECONDS, this.view()?.pollSeconds ?? DEFAULT_POLL_SECONDS),
  );

  /** How old the data on screen is, in seconds; infinite before the first successful poll. */
  protected readonly ageSeconds = computed(() => {
    const last = this.lastSuccessAt();
    if (last === 0) {
      return Number.POSITIVE_INFINITY;
    }
    return Math.max(0, (this.now() - last) / 1000);
  });

  /** How much the board still trusts what it is showing. */
  protected readonly freshness = computed<Freshness>(() => {
    const poll = this.pollSeconds();
    const age = this.ageSeconds();
    if (age < STALE_MULTIPLE * poll) {
      return 'fresh';
    }
    return age <= LOST_MULTIPLE * poll ? 'stale' : 'lost';
  });

  /**
   * What the whole screen shows.
   *
   * The order is the point. A refusal outranks everything, because a board whose credential has been
   * withdrawn holds nothing worth ranking; a locked board has no data either; and having no answer
   * yet is distinct from having had one that went stale, because the first has nothing to age.
   */
  protected readonly state = computed<BoardState>(() => {
    if (this.refusal()) {
      return 'refused';
    }
    if (this.locked()) {
      return 'locked';
    }
    if (this.view() === null) {
      return 'waiting';
    }
    return this.freshness() === 'lost' ? 'lost' : 'board';
  });

  /** The fleet's name, empty until the first answer. */
  protected readonly title = computed(() => this.view()?.title ?? '');

  /** The host counts, zeroed before the first answer — which no state renders. */
  protected readonly counts = computed(
    () => this.view()?.hosts ?? { total: 0, ok: 0, bad: 0, unknown: 0 },
  );

  /** The hosts the board names, at most twelve of them. */
  protected readonly entries = computed<WallboardAttention[]>(() => this.view()?.attention ?? []);

  /** How many bad-or-unknown hosts did not fit, which the grid says out loud rather than hiding. */
  protected readonly omitted = computed(() => this.view()?.attentionOmitted ?? 0);

  /**
   * Whether the fleet holds no hosts at all.
   *
   * Its own state, because zero of zero hosts being well is arithmetically an all-clear and is not
   * one: an empty fleet renders green on any board that only counts, and the room then trusts a
   * screen that is watching nothing. It also stands in for a deleted tenant, whose scoped read
   * answers with an empty fleet rather than an error.
   */
  protected readonly emptyFleet = computed(() => this.counts().total === 0);

  /** The age in words, for the amber band and the withdrawn-numbers screen. */
  protected readonly ageWords = computed(() => formatDuration(this.ageSeconds()));

  /**
   * The wall-clock time of the last good read, or a dash before there has been one.
   *
   * Printed beside the age, never instead of it: somebody walking past at nine in the morning needs
   * to know whether "three minutes ago" was three minutes ago or three minutes before the machine
   * was suspended overnight, and only the pair of them answers that.
   */
  protected readonly lastGoodClock = computed(() => {
    const last = this.lastSuccessAt();
    return last === 0 ? '—' : new Date(last).toLocaleTimeString();
  });

  /**
   * Starts the board, unless there is nothing to poll with.
   *
   * A public address with no fragment is a link somebody truncated — pasted through a chat client
   * that ate the `#`, or retyped from a photograph — and it is refused here rather than sent, because
   * an empty bearer token would come back as an ordinary refusal and the screen would blame the
   * share for a mistake made in the address bar.
   */
  constructor() {
    this.mode = this.route.snapshot.data['public'] === true ? 'public' : 'operator';
    this.key = this.mode === 'public' ? this.keyFromAddress() : '';

    if (this.mode === 'public' && !this.key) {
      this.refusal.set(
        'This address carries no key. A board link ends in "#hsb_…" — the part after the "#" is the ' +
          'credential, and some ways of sharing a link drop it.',
      );
    } else {
      this.poll();
    }

    const ticker = setInterval(() => this.now.set(Date.now()), AGE_TICK_MILLISECONDS);
    this.destroyRef.onDestroy(() => {
      clearInterval(ticker);
      this.stop();
    });
  }

  /**
   * The key, taken from the address's fragment.
   *
   * A fragment rather than a path segment, which is why the route takes no parameter: a fragment is
   * never transmitted, so the key is absent from the control plane's access log, from every proxy's,
   * from `Referer`, and from a link-preview crawler's fetch. What it does not escape is browser
   * history and a photograph of the address bar, and that is the residual cost of publishing a
   * screen this way.
   *
   * A method rather than an inline read, so the one browser global this component touches is named
   * once and a spec can drive it by putting a key in the address the way a published link does.
   */
  protected keyFromAddress(): string {
    return location.hash.replace(/^#/, '').trim();
  }

  /** The reason word for a tile. */
  protected reasonWord(entry: WallboardAttention): string {
    return (REASONS[entry.reason] ?? UNRECOGNISED).word;
  }

  /** The icon for a tile, so the tile is identifiable before its text is legible. */
  protected reasonIcon(entry: WallboardAttention): string {
    return (REASONS[entry.reason] ?? UNRECOGNISED).icon;
  }

  /**
   * Proves the share's passphrase, once, and resumes polling.
   *
   * Once is the whole design: the control plane exchanges the passphrase for a cookie the poll
   * carries cheaply, because re-deriving Argon2id every fifteen seconds on every screen would be the
   * sign-in path's entire memory budget spent on televisions.
   */
  protected unlock(): void {
    const secret = this.passphrase();
    if (this.unlocking() || !secret) {
      return;
    }
    this.unlocking.set(true);
    this.unlockError.set('');
    this.api
      .unlockWallboard(this.key, secret)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
      next: () => {
        this.unlocking.set(false);
        this.passphrase.set('');
        this.locked.set(false);
        this.poll();
      },
      error: (err: unknown) => {
        this.unlocking.set(false);
        // Deliberately the control plane's own sentence. A wrong passphrase, an expired share and an
        // unknown key are one refusal there, taking one amount of time, and a browser that split
        // them into three messages would put the distinction back.
        this.unlockError.set(describeError(err));
      },
    });
  }

  /**
   * Reads the board once, and schedules the next read unless something has ended the sequence.
   *
   * The next poll is scheduled when this one finishes rather than on a fixed interval, so a slow
   * control plane is met with fewer requests instead of a queue of overlapping ones — which is the
   * behaviour that turns a struggling control plane into an unreachable one.
   */
  private poll(): void {
    const request =
      this.mode === 'public' ? this.api.publicWallboard(this.key) : this.api.wallboard();
    // Cancelled with the component, which is the half that matters rather than tidiness: a poll still
    // in flight when the board is left would otherwise land on a dead component and book the next
    // one, leaving a timer nothing can reach polling the control plane for the life of the tab.
    request.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (view) => {
        this.view.set(view);
        this.failure.set('');
        this.now.set(Date.now());
        this.lastSuccessAt.set(Date.now());
        this.schedule();
      },
      error: (err: unknown) => this.absorb(err),
    });
  }

  /**
   * Decides what one failed poll means, which is two different things.
   *
   * A 401 or a 404 is the control plane saying this credential is not one it accepts — revoked,
   * expired, or for a fleet that no longer exists — and no amount of retrying changes that. The data
   * goes, the screen says so, and the polling stops: a decommissioned television retrying a dead
   * share every fifteen seconds for a year is a bucket kept warm for nothing.
   *
   * Anything else — a 500, a proxy in the way, a network that has gone — is the control plane failing
   * to answer rather than refusing, so the numbers stay and age visibly and the board keeps trying.
   * The one exception is the passphrase, which arrives as a 401 and is not a refusal at all: it is a
   * screen that has not been unlocked yet, and it gets a form rather than an epitaph.
   */
  private absorb(err: unknown): void {
    const status = errorStatus(err);
    if (status === 401 && errorCode(err) === 'passphrase_required') {
      this.forgetData();
      this.locked.set(true);
      this.stop();
      return;
    }
    if (status === 401 || status === 404) {
      this.forgetData();
      this.refusal.set(
        this.mode === 'public'
          ? 'This board is no longer published. The link has been withdrawn or has expired — ask ' +
              'whoever put this screen up for a new one.'
          : 'The control plane no longer accepts this session. Sign in again.',
      );
      this.stop();
      return;
    }
    this.failure.set(describeError(err));
    this.schedule();
  }

  /**
   * Drops everything the board was showing.
   *
   * Both halves, and the second is the one that matters: clearing the view without clearing the
   * timestamp would leave a board that says nothing is known while a stale-age computation quietly
   * carries on describing data that is gone.
   */
  private forgetData(): void {
    this.view.set(null);
    this.lastSuccessAt.set(0);
    this.failure.set('');
  }

  /** Books the next read, replacing any already booked so two sequences cannot run at once. */
  private schedule(): void {
    this.stop();
    this.timer = setTimeout(() => this.poll(), this.pollSeconds() * 1000);
  }

  /** Cancels the pending read, which is how "stop polling" is actually spelled. */
  private stop(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
