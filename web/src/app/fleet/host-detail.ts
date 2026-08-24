import { Component, computed, inject, input, signal } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { MatCardModule } from '@angular/material/card';
import { MatDividerModule } from '@angular/material/divider';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { RouterLink } from '@angular/router';
import { catchError, of, startWith, switchMap } from 'rxjs';

import { Host, UnitState, UnitTransition } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeUnit, isUnloadable } from '../core/unit-state';
import { formatAge, formatDuration, formatOffset } from '../core/format';

/**
 * One host in full: its identity, what it reported, and — the part that matters — what it will accept.
 *
 * The local policy and the trusted signers are given as much space as the inventory, which is unusual
 * for a fleet tool and is the point. Those two are what bound the control plane, so an operator looking
 * at a host should be able to see what this control plane could and could not make it do, without
 * logging in to it.
 */
@Component({
  selector: 'farrier-host-detail',
  imports: [
    MatCardModule,
    MatDividerModule,
    MatIconModule,
    MatListModule,
    MatProgressBarModule,
    RouterLink,
  ],
  templateUrl: './host-detail.html',
  styleUrl: './host-detail.scss',
})
export class HostDetail {
  /** The host identifier, bound from the route. */
  readonly id = input.required<string>();

  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The last error message, empty when the host loaded. */
  protected readonly error = signal('');

  /** The host, or null while loading. */
  protected readonly host = toSignal(
    toObservable(this.id).pipe(
      switchMap((id) =>
        this.api.host(id).pipe(
          startWith(null),
          catchError(() => {
            this.error.set('This host could not be loaded.');
            return of(null);
          }),
        ),
      ),
    ),
    { initialValue: null },
  );

  /** Whether the host is still loading. */
  protected readonly loading = computed(() => this.host() === null && !this.error());

  /**
   * Why the unit history could not be read, empty while it is loading or once it has.
   *
   * Its own signal rather than reading a null `transitions` as failure, which is the same fix the
   * `host` signal already carries: null means "no answer yet", and the in-flight window is most of a
   * page load — so conflating the two renders "could not be read" every single time, on a card that
   * is about to fill in.
   */
  protected readonly historyError = signal('');

  /**
   * This host's recorded unit-state changes, newest first.
   *
   * Its own request rather than a field on the host, because it is the one part of this page that is
   * a time series: everything else answers "now" from the last heartbeat, and this answers "since
   * when" — which is what turns "nginx is failed" into "nginx has been flapping since Tuesday".
   */
  protected readonly transitions = toSignal(
    toObservable(this.id).pipe(
      switchMap((id) => {
        // Cleared as the request goes out, so switching hosts does not carry the previous host's
        // failure onto the next one's page.
        this.historyError.set('');
        return this.api.serviceHistory(id).pipe(
          startWith(null),
          catchError(() => {
            this.historyError.set('The unit history could not be read.');
            return of(null);
          }),
        );
      }),
    ),
    { initialValue: null },
  );

  /**
   * The units this host reports as failed, meaning systemd loaded them and running them went wrong.
   *
   * A masked or missing unit is deliberately not in here even when it also reports `failed`. It has
   * not crashed — somebody pinned it off, or its unit file is gone — and putting it in this list
   * would send an operator looking for a fault in a service nobody is running.
   */
  protected readonly failedUnits = computed<UnitState[]>(() =>
    (this.host()?.facts?.services ?? []).filter(
      (unit) => describeUnit(unit).condition === 'failed',
    ),
  );

  /**
   * The units systemd could not load: masked, missing, or with an unreadable unit file.
   *
   * Shown beside the failed ones rather than hidden, because "nothing is failed here" is not the
   * same answer as "the unit you are looking for is masked" — and the second one is what the
   * operator hunting a service that will not start needs to be told. It is the same distinction
   * issue #5 makes: a masked unit and a crashed unit are different problems.
   */
  protected readonly unloadableUnits = computed<UnitState[]>(() =>
    (this.host()?.facts?.services ?? []).filter((unit) => isUnloadable(unit)),
  );

  /** Renders the host's uptime. */
  protected uptime(host: Host): string {
    return formatDuration(host.uptimeSeconds);
  }

  /** Renders the host's clock offset with its sign. */
  protected offset(host: Host): string {
    return formatOffset(host.clockOffsetSeconds);
  }

  /**
   * Explains what an empty trusted-signers file means, in words rather than as a count of zero.
   *
   * "0 keys" reads as missing data. "This host will execute nothing destructive" is the same fact and
   * is the one an operator can act on — including by deciding that it is exactly what they wanted.
   */
  protected signersSummary(host: Host): string {
    const count = host.signers?.length ?? 0;
    if (count === 0) {
      return 'None. This host will execute no destructive operation, from anyone.';
    }
    return `${count} key${count === 1 ? '' : 's'} may authorise destructive operations on this host.`;
  }

  /**
   * Describes the host's release, falling back through what it did report.
   *
   * PRETTY_NAME is absent from some minimal images, and rendering an em dash for a host that reported
   * its id, version and codename perfectly well would say "not reported" about a fact that was.
   */
  protected release(host: Host): string {
    const dist = host.facts?.distribution;
    if (!dist) {
      return 'not reported yet';
    }
    return dist.prettyName || `${dist.id} ${dist.version} (${dist.codename})`;
  }

  /**
   * Describes what this host's `[services] watched` list means, in words rather than as a list length.
   *
   * The empty default is the opposite of `restartable`'s and reads wrong as "none": permitting an
   * action and reporting a fact are different questions, so an empty watch list watches everything.
   */
  protected watchedSummary(host: Host): string {
    const watched = host.policy?.services.watched ?? [];
    if (watched.length === 0) {
      return 'every unit — the host has named none, and reporting is the default';
    }
    return watched.join(', ');
  }

  /** The word for why a unit could not be loaded: masked, no unit file, or unreadable. */
  protected unitLabel(unit: UnitState): string {
    return describeUnit(unit).label;
  }

  /** Renders how long ago a transition was, against the control plane's clock. */
  protected transitionAge(transition: UnitTransition): string {
    const now = this.transitions()?.serverTime;
    return now ? formatAge(transition.at, now) : '—';
  }

  /** Renders Ubuntu Pro state, distinguishing "not applicable" from "not attached". */
  protected subscriptionSummary(host: Host): string {
    const sub = host.facts?.subscription;
    if (!sub) {
      return 'not reported yet';
    }
    if (!sub.applicable) {
      return 'not applicable on this distribution';
    }
    if (sub.attached) {
      return 'attached';
    }
    return sub.note ? `not attached — ${sub.note}` : 'not attached';
  }
}
