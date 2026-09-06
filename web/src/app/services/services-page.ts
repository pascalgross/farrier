import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { ApiService } from '../core/api.service';
import { FailedServiceHost, UnitState } from '../core/api.models';
import { describeUnit, explainUnit } from '../core/unit-state';
import { describeError } from '../core/errors';
import { toneClass } from '../core/tone';

/**
 * The fleet-wide service view: where is something failed, without opening hosts one at a time.
 *
 * The page answers one question and refuses to answer it approximately. Three things follow from
 * that.
 *
 * A host whose unit list was cut at the protocol's cap is listed even when nothing it reported has
 * failed, because "no failed units here" and "the failed unit sorts after the five hundredth" must
 * not render identically — the same rule the needrestart scan already follows, and for the same
 * reason: a dashboard that quietly turns an unknown into a clean bill of health is worse than no
 * dashboard. A host whose facts cannot be read at all is listed for the same reason, one level up.
 *
 * A masked or absent unit is shown as such rather than painted the same red as a crashed one. They
 * are different problems, and a view that paints both red teaches its readers to ignore it — the
 * failure mode of the permanently amber Ubuntu Pro badge on Debian.
 *
 * And every number in the header counts one thing. The three reasons a host appears below — it has
 * a failed unit, its list was truncated, nothing is known about it — are counted separately,
 * because a single "on N of M hosts" over the whole list read "1 failed on 6 of 300 hosts" for a
 * fleet with one failure and five unknowns. A count that overstates the fleet's trouble is read once
 * and then discounted for ever.
 */
@Component({
  selector: 'hostseal-services-page',
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

  /** The hosts with something failed, a truncated list or no readable facts. Null on first load. */
  protected readonly hosts = signal<FailedServiceHost[] | null>(null);

  /** How many hosts the control plane examined, revoked ones excluded, for the "of 300". */
  protected readonly total = signal(0);

  /** Why the page could not load, empty when it did. */
  protected readonly error = signal('');

  /** How many units are failed across the fleet. */
  protected readonly failedUnits = computed(() =>
    (this.hosts() ?? []).reduce((sum, host) => sum + host.failed.length, 0),
  );

  /**
   * How many hosts have at least one failed unit.
   *
   * Not the length of the list, which is the defect this replaces: the list also holds hosts that
   * are there only because their unit list was truncated or their facts could not be read, so
   * "failed on {{ list.length }} hosts" claimed failures on hosts that had reported none.
   */
  protected readonly failingHosts = computed(
    () => (this.hosts() ?? []).filter((host) => host.failed.length > 0).length,
  );

  /** How many hosts reported a truncated unit list, which is an unknown rather than a clean answer. */
  protected readonly truncatedHosts = computed(
    () => (this.hosts() ?? []).filter((host) => host.servicesTruncated).length,
  );

  /**
   * How many hosts nothing is known about: never reported, or facts that will not parse.
   *
   * Its own count and never folded into the failing ones. A host that has not spoken is a different
   * problem from a host with a broken unit, and the fleet page is where the first one is chased.
   */
  protected readonly unknownHosts = computed(
    () => (this.hosts() ?? []).filter((host) => host.factsUnknown).length,
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

  /**
   * The word beside a unit's name.
   *
   * A unit that crashed keeps its sub state — `exited`, `auto-restart` — because that is the detail
   * an operator reads next. A unit systemd could not load shows what stopped it loading instead, so
   * that `nginx.service (masked)` cannot be mistaken for a crash.
   */
  protected label(unit: UnitState): string {
    const described = describeUnit(unit);
    return described.condition === 'failed' ? unit.subState : described.label;
  }

  /** The icon for a unit's condition. */
  protected icon(unit: UnitState): string {
    return describeUnit(unit).icon;
  }

  /** The colour class for a unit's condition, so a mask is not painted the same red as a crash. */
  protected tone(unit: UnitState): string {
    return toneClass(describeUnit(unit).tone);
  }

  /** The tooltip: what kind of problem this is, and then the three states the host reported. */
  protected explain(unit: UnitState): string {
    return explainUnit(unit);
  }
}
