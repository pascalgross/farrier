import { Component, computed, inject, input, signal } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatDividerModule } from '@angular/material/divider';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';
import { catchError, of, startWith, switchMap } from 'rxjs';

import { Host } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { formatDuration, formatOffset } from '../core/format';

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
    MatChipsModule,
    MatDividerModule,
    MatIconModule,
    MatListModule,
    MatProgressBarModule,
    MatTooltipModule,
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
