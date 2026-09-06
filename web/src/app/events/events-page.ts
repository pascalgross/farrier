import { Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { ApiService } from '../core/api.service';
import { EVENT_KINDS, describeKind } from '../core/event-kinds';
import { EventStream, mergeEvents } from '../core/event-stream';
import { FleetEvent } from '../core/api.models';
import { describeError } from '../core/errors';
import { formatAge } from '../core/format';
import { toneClass } from '../core/tone';

/**
 * How often the ages on this page are recomputed, in milliseconds.
 *
 * They have to tick. The feed stays open for hours and new rows arrive on it, so a `now` captured
 * once at construction leaves every row saying "2m ago" for the rest of the afternoon — and an age
 * that is confidently wrong is worse than no age at all on a page whose whole purpose is telling
 * somebody when something happened. Ten seconds is finer than the smallest unit `formatAge` prints
 * once a row is a minute old, and coarse enough to be invisible next to the stream itself.
 */
const AGE_TICK_MILLISECONDS = 10_000;

/**
 * How many events a filtered read asks the control plane for.
 *
 * The largest it accepts, `store.MaxEventLimit`, asked for rather than defaulted: the default is a
 * tenth of the inbox and is right for "what is new", while narrowing to one kind is the request that
 * wants depth. An operator filtering `job.expired` is asking what has expired, not what expired most
 * recently — and the inbox keeps a thousand events per fleet, so there is history here to reach.
 */
const FILTERED_EVENT_LIMIT = 500;

/**
 * The event inbox: what the control plane noticed, whether or not anybody's tab was open.
 *
 * The page exists because best-effort delivery has to *look* best-effort. The live stream reaches an
 * open tab and the webhook reaches a chat channel, and both can miss; this is the durable copy, so an
 * event that reached nobody live is still here when somebody looks. That is also why the page reads
 * the shared feed rather than fetching for itself — the feed is the merge of this inbox and the live
 * stream, de-duplicated on the event id, so an operator watching it during an incident sees new
 * entries appear without reloading and without double-counting.
 *
 * The kind filter is the one thing this page does not do in memory, and the reason is arithmetic: the
 * feed holds the newest two hundred events and the inbox holds a thousand, so filtering the feed for
 * `job.expired` could not reach a single expiry that happened before the newest two hundred events —
 * it would answer "nothing of this kind has happened" about a fleet where plenty had. Choosing a kind
 * asks the server, which filters over the whole inbox; the live stream's matching events are merged
 * on top so the filtered view stays live too.
 *
 * Nothing here is actionable, deliberately. There is no approve button and no retry button on an
 * event: anything that changes state goes through its own page with its own authentication, and a
 * destructive job still needs an offline signature and a second person. What this page does is make
 * somebody open the right tab.
 */
@Component({
  selector: 'hostseal-events-page',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatSelectModule,
    MatSlideToggleModule,
    MatTooltipModule,
    RouterLink,
  ],
  templateUrl: './events-page.html',
  styleUrl: './events-page.scss',
})
export class EventsPage {
  /** The merged live-and-durable feed. */
  protected readonly stream = inject(EventStream);

  /** Talks to the control plane, for the filtered read the shared feed cannot answer. */
  private readonly api = inject(ApiService);

  /** Stops the age ticker when the operator leaves the page, so a closed page costs nothing. */
  private readonly destroyRef = inject(DestroyRef);

  /** The kind filter, empty for everything. */
  protected readonly kind = signal('');

  /**
   * The server's answer for the chosen kind, over the whole inbox rather than over the feed.
   *
   * Null while a fetch is in flight and whenever no kind is chosen. Null rather than an empty array
   * on purpose: "the server has not answered yet" and "the server says there are none" are different
   * states, and rendering the first as the second would flash "nothing of this kind has happened"
   * over a fleet where it had.
   */
  private readonly matching = signal<FleetEvent[] | null>(null);

  /** Why the filtered read failed, empty when it did not. Shown beside the filter, not as the page. */
  protected readonly filterError = signal('');

  /** Every kind, for the filter, with its label. */
  protected readonly kinds = Object.entries(EVENT_KINDS).map(([value, style]) => ({
    value,
    label: style.label,
  }));

  /**
   * The browser's clock, used for ages on this page and nowhere else.
   *
   * The rule everywhere else is the server's clock, because an age is a decision input. Here it is
   * not: the feed is a merge of a live stream and a fetch, so there is no single response whose
   * `serverTime` covers every row, and an event that arrived over the stream a second ago has no
   * server timestamp newer than its own. A skewed laptop mis-renders these ages, which for a "what
   * happened" list is a smaller cost than a clock that jumps backwards between rows.
   *
   * It advances on a timer; see AGE_TICK_MILLISECONDS for why a page with a live stream on it cannot
   * hold one instant for the whole session.
   */
  protected readonly now = signal(new Date().toISOString());

  /**
   * The events the filter admits, newest first.
   *
   * Unfiltered, this is the shared feed unchanged. Filtered, it is the server's answer with the live
   * stream's matching events merged over it — de-duplicated on the event id, because during an
   * incident the same event arrives from both and an operator counting them must not count it twice.
   * While the server's answer is outstanding the live half stands alone, which is a partial view
   * rather than a wrong one and fills in as the fetch lands.
   */
  protected readonly shown = computed(() => {
    const wanted = this.kind();
    const feed = this.stream.events();
    if (!wanted) {
      return feed;
    }
    return mergeEvents(
      this.matching() ?? [],
      feed.filter((event) => event.kind === wanted),
    );
  });

  /** Whether the browser can show desktop notifications at all. */
  protected readonly desktopAvailable = this.stream.desktopAvailable();

  /** Whether the operator has already denied the browser prompt, which cannot be re-asked from here. */
  protected readonly desktopDenied = this.stream.desktopPermission() === 'denied';

  /**
   * Loads the inbox and keeps it marked read for as long as this page is open.
   *
   * The effect rather than a single call after the fetch, and that is a fix rather than a flourish:
   * the inbox arrives asynchronously and the live stream keeps adding to it, so marking once at
   * construction would leave the bell counting events the operator is looking at. While this page is
   * mounted, anything that arrives has been seen by definition.
   */
  constructor() {
    this.stream.start();
    this.stream.refresh();
    effect(() => {
      // Read for the dependency, act on the side effect: every change to the feed re-marks it.
      this.stream.events();
      this.stream.markSeen();
    });

    const ticker = setInterval(
      () => this.now.set(new Date().toISOString()),
      AGE_TICK_MILLISECONDS,
    );
    this.destroyRef.onDestroy(() => clearInterval(ticker));
  }

  /** Re-reads the inbox. The effect above clears the unread count as the answer arrives. */
  protected reload(): void {
    this.now.set(new Date().toISOString());
    this.stream.refresh();
    this.fetchKind();
  }

  /** Chooses the kind filter, and asks the control plane for it rather than sieving the feed. */
  protected chooseKind(kind: string): void {
    this.kind.set(kind);
    this.fetchKind();
  }

  /**
   * Reads the chosen kind from the control plane.
   *
   * Every answer is checked against the filter that is current when it lands. Two fetches for two
   * kinds can be in flight at once — an operator changing their mind is the ordinary case, not the
   * pathological one — and without the check the slower answer would paint the wrong kind's events
   * under the right kind's label.
   */
  private fetchKind(): void {
    const wanted = this.kind();
    this.matching.set(null);
    this.filterError.set('');
    if (!wanted) {
      return;
    }
    this.api.events(wanted, FILTERED_EVENT_LIMIT).subscribe({
      next: (response) => {
        if (this.kind() === wanted) {
          this.matching.set(response.events);
        }
      },
      error: (err: unknown) => {
        if (this.kind() === wanted) {
          this.filterError.set(describeError(err));
        }
      },
    });
  }

  /** Turns desktop notifications on or off, asking the browser the first time. */
  protected toggleDesktop(wanted: boolean): void {
    if (wanted) {
      void this.stream.enableDesktop();
    } else {
      this.stream.disableDesktop();
    }
  }

  /** How long ago an event was, by the browser's clock. */
  protected age(event: FleetEvent): string {
    return formatAge(event.at, this.now());
  }

  /** The label for an event's kind. */
  protected label(event: FleetEvent): string {
    return describeKind(event.kind).label;
  }

  /** The icon for an event's kind. */
  protected icon(event: FleetEvent): string {
    return describeKind(event.kind).icon;
  }

  /** The colour class for an event's kind. */
  protected tone(event: FleetEvent): string {
    return toneClass(describeKind(event.kind).tone);
  }
}
