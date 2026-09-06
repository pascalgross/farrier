import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';
import { catchError, of, startWith } from 'rxjs';

import { Host } from '../core/api.models';
import { EnrolPanel } from './enrol-panel';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import { formatAge, formatDuration, formatOffset } from '../core/format';

/** What the fleet request can be doing, so the template can render each state distinctly. */
type LoadState = 'loading' | 'loaded' | 'failed';

/**
 * The fleet list: every enrolled host and the four things an operator checks first.
 *
 * Those four are chosen deliberately. Whether the host is reachable, how many security updates it is
 * behind, whether it needs a reboot, and whether anything is wrong with its clock or its policy — that
 * last group being the one most dashboards omit, because it is the one that only matters when something
 * has already gone wrong.
 *
 * Everything a cell can say is derived from what the host reported. Nothing here infers state the agent
 * did not send: a column that guessed would eventually guess wrong about the host somebody was looking
 * at during an incident.
 */
@Component({
  selector: 'hostseal-fleet-list',
  imports: [
    EnrolPanel,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatProgressBarModule,
    MatTableModule,
    MatTooltipModule,
    RouterLink,
  ],
  templateUrl: './fleet-list.html',
  styleUrl: './fleet-list.scss',
})
export class FleetList {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The columns rendered, in order. */
  protected readonly columns = [
    'hostname',
    'status',
    'distribution',
    'updates',
    'reboot',
    'policy',
    'lastSeen',
  ];

  /** The last error message, empty when the fleet loaded. */
  protected readonly error = signal('');

  /**
   * The fleet, or null while it is loading.
   *
   * The request is converted to a signal rather than subscribed to in a lifecycle hook, so the template
   * can render the loading, loaded and failed states without the component holding a subscription it
   * would then have to remember to release.
   */
  protected readonly fleet = toSignal(
    this.api.fleet().pipe(
      startWith(null),
      catchError((err: unknown) => {
        this.error.set(describeError(err));
        return of(null);
      }),
    ),
    { initialValue: null },
  );

  /** Which of the three states the page is in. */
  protected readonly state = computed<LoadState>(() => {
    if (this.error()) {
      return 'failed';
    }
    return this.fleet() === null ? 'loading' : 'loaded';
  });

  /** The hosts, or an empty list while loading. */
  protected readonly hosts = computed<Host[]>(() => this.fleet()?.hosts ?? []);

  /** The control plane's clock, used so ages do not depend on the browser's. */
  protected readonly serverTime = computed(() => this.fleet()?.serverTime ?? new Date().toISOString());

  /** How many hosts are currently reachable, for the summary line. */
  protected readonly onlineCount = computed(() => this.hosts().filter((h) => h.online).length);

  /** How many security updates are outstanding across the fleet. */
  protected readonly securityBacklog = computed(() =>
    this.hosts().reduce((total, h) => total + (h.facts?.packages?.upgradableSecurity ?? 0), 0),
  );

  /** How many hosts are waiting on a reboot. */
  protected readonly rebootCount = computed(
    () => this.hosts().filter((h) => h.facts?.reboot?.required).length,
  );

  /** Renders how long ago a host was last heard from, against the control plane's clock. */
  protected age(host: Host): string {
    return formatAge(host.lastSeen, this.serverTime());
  }

  /** Renders a host's uptime. */
  protected uptime(host: Host): string {
    return formatDuration(host.uptimeSeconds);
  }

  /** Renders a host's clock offset with its sign. */
  protected offset(host: Host): string {
    return formatOffset(host.clockOffsetSeconds);
  }

  /**
   * Describes a host's release, or says the facts have not arrived yet.
   *
   * "Not reported yet" is shown rather than a blank cell, because a blank cell in a fleet list reads as
   * "nothing to say" and this means "the host has not told us".
   */
  protected release(host: Host): string {
    const dist = host.facts?.distribution;
    if (!dist) {
      return 'not reported yet';
    }
    return dist.prettyName || `${dist.id} ${dist.version} (${dist.codename})`;
  }

  /**
   * Reports whether a host is on a release HostSeal supports.
   *
   * An unsupported release is flagged rather than hidden. A host nobody is patching is exactly the one
   * an operator needs to see.
   */
  protected unsupportedRelease(host: Host): boolean {
    return host.facts?.distribution?.supported === false;
  }

  /**
   * Summarises a host's policy in one phrase.
   *
   * The policy is the thing the control plane cannot change, so what it says is worth a column of its
   * own rather than being buried on the detail page. A host that will accept nothing looks different
   * here from one that will accept everything, at a glance.
   */
  protected policySummary(host: Host): string {
    const policy = host.policy;
    if (!policy) {
      return 'not reported yet';
    }
    const reboot = policy.updates.reboot === 'never' ? 'no reboots' : `reboots in ${policy.updates.window}`;
    return `${policy.updates.allow} updates, ${reboot}`;
  }

  /** Reports whether anything about a host warrants an operator's attention. */
  protected needsAttention(host: Host): boolean {
    return (
      !host.online ||
      host.paused ||
      host.revoked ||
      host.clockSkewed ||
      (host.facts?.packages?.upgradableSecurity ?? 0) > 0 ||
      (host.facts?.reboot?.required ?? false)
    );
  }
}
