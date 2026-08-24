import { Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { EVENT_KINDS, describeKind, toneClass } from '../core/event-kinds';
import { EventStream } from '../core/event-stream';
import { FleetEvent } from '../core/api.models';
import { formatAge } from '../core/format';

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
 * Nothing here is actionable, deliberately. There is no approve button and no retry button on an
 * event: anything that changes state goes through its own page with its own authentication, and a
 * destructive job still needs an offline signature and a second person. What this page does is make
 * somebody open the right tab.
 */
@Component({
  selector: 'farrier-events-page',
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

  /** The kind filter, empty for everything. */
  protected readonly kind = signal('');

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
   */
  protected readonly now = signal(new Date().toISOString());

  /** The events the filter admits. */
  protected readonly shown = computed(() => {
    const wanted = this.kind();
    const events = this.stream.events();
    return wanted ? events.filter((event) => event.kind === wanted) : events;
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
  }

  /** Re-reads the inbox. The effect above clears the unread count as the answer arrives. */
  protected reload(): void {
    this.now.set(new Date().toISOString());
    this.stream.refresh();
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
