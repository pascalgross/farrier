import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { ApiService } from '../core/api.service';
import { FailedServiceHost } from '../core/api.models';
import { describeError } from '../core/errors';

/**
 * The fleet-wide service view: where is something failed, without opening hosts one at a time.
 *
 * The page answers one question and refuses to answer it approximately. Two things follow from that.
 *
 * A host whose unit list was cut at the protocol's cap is listed even when nothing it reported has
 * failed, because "no failed units here" and "the failed unit sorts after the five hundredth" must
 * not render identically — the same rule the needrestart scan already follows, and for the same
 * reason: a dashboard that quietly turns an unknown into a clean bill of health is worse than no
 * dashboard.
 *
 * A masked or absent unit is shown as such rather than painted the same red as a crashed one. They
 * are different problems, and a view that paints both red teaches its readers to ignore it — the
 * failure mode of the permanently amber Ubuntu Pro badge on Debian.
 */
@Component({
  selector: 'farrier-services-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatProgressBarModule,
    MatTooltipModule,
    RouterLink,
  ],
  templateUrl: './services-page.html',
  styleUrl: './services-page.scss',
})
export class ServicesPage {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The hosts with something failed, or with a truncated list. Null while the first load runs. */
  protected readonly hosts = signal<FailedServiceHost[] | null>(null);

  /** How many hosts were examined, so the count reads as "3 of 300". */
  protected readonly total = signal(0);

  /** Why the page could not load, empty when it did. */
  protected readonly error = signal('');

  /** How many units are failed across the fleet. */
  protected readonly failedUnits = computed(() =>
    (this.hosts() ?? []).reduce((sum, host) => sum + host.failed.length, 0),
  );

  /** How many hosts reported a truncated unit list, which is an unknown rather than a clean answer. */
  protected readonly truncatedHosts = computed(
    () => (this.hosts() ?? []).filter((host) => host.servicesTruncated).length,
  );

  /** Loads the view. */
  constructor() {
    this.reload();
  }

  /** Re-reads the fleet's failed units. */
  protected reload(): void {
    this.api.failedServices().subscribe({
      next: (response) => {
        this.hosts.set(response.hosts);
        this.total.set(response.total);
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }
}
