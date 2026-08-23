import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { CatalogueEntry, Host, Job } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import { formatAge } from '../core/format';

/**
 * The jobs page: what has been asked of the fleet, and what came back.
 *
 * Only read-only work can be started from here, and that is not a limitation of the page. A destructive
 * job carries a signature made offline by a key the control plane does not hold, and a browser is the
 * last place that key should ever be — so the form offers what a browser can legitimately authorise and
 * says plainly why the rest is not there, rather than presenting a control that cannot work.
 *
 * What the page *can* do for a destructive job is approve one, which is the half that belongs in a
 * control plane. On an installation with a single operator account that always fails, and the failure
 * is shown as the control plane wrote it: a second person is the requirement, and there is only one.
 */
@Component({
  selector: 'farrier-jobs-list',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatProgressBarModule,
    MatSelectModule,
    MatTableModule,
    MatTooltipModule,
    RouterLink,
  ],
  templateUrl: './jobs-list.html',
  styleUrl: './jobs-list.scss',
})
export class JobsList {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The columns rendered, in order. */
  protected readonly columns = ['intent', 'host', 'state', 'authorisation', 'created', 'actions'];

  /** The jobs, newest first. Null while the first load is in flight. */
  protected readonly jobs = signal<Job[] | null>(null);

  /**
   * Every job waiting for a second operator, whether or not it is on the page below.
   *
   * Fetched separately for the reason the separate endpoint exists: the list is bounded, and a
   * destructive job on a busy fleet leaves the newest page within a working day. A second operator who
   * can only approve what happens to still be on screen is not the second operator
   * docs/SECURITY.md §3 describes.
   */
  protected readonly awaiting = signal<Job[]>([]);

  /** Whether the list below was cut short, so there are older jobs it does not show. */
  protected readonly truncated = signal(false);

  /** Every enrolled host, for the form's host picker. */
  protected readonly hosts = signal<Host[]>([]);

  /** The catalogue, for the form's operation picker. */
  protected readonly intents = signal<CatalogueEntry[]>([]);

  /** The last error from loading the page, empty when it loaded. */
  protected readonly error = signal('');

  /** The last error from creating or approving, shown beside the form rather than replacing the page. */
  protected readonly actionError = signal('');

  /** The host selected in the form. */
  protected readonly chosenHost = signal('');

  /** The operation selected in the form. */
  protected readonly chosenIntent = signal('');

  /** Whether a create or approve request is in flight, so the buttons can be disabled. */
  protected readonly busy = signal(false);

  /** The browser's clock, refreshed on each load, for rendering ages. */
  protected readonly now = signal(new Date().toISOString());

  /**
   * The operations this page will offer to start.
   *
   * Read-only and implemented, and nothing else. A routine intent has no online key to sign it and a
   * destructive one needs a signature this browser must never be able to make; offering either would be
   * a control whose only outcome is an error message.
   */
  protected readonly startableIntents = computed(() =>
    this.intents().filter((entry) => entry.class === 'read' && entry.implemented),
  );

  /** Whether the form has enough to submit. */
  protected readonly canCreateJob = computed(
    () => this.chosenHost().length > 0 && this.chosenIntent().length > 0 && !this.busy(),
  );

  /** Loads everything the page shows. */
  constructor() {
    this.reload();
    this.api.fleet().subscribe({
      next: (fleet) => this.hosts.set(fleet.hosts),
      error: (err: unknown) => this.error.set(describeError(err)),
    });
    this.api.catalogue().subscribe({
      next: (catalogue) => this.intents.set(catalogue.intents),
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }

  /**
   * Re-reads the job list.
   *
   * It is called after every create and approve rather than the response being spliced into the list,
   * because what the control plane holds is the answer and a locally patched row would eventually
   * disagree with it — most likely about a job somebody was watching.
   */
  protected reload(): void {
    this.api.jobs().subscribe({
      next: (response) => {
        this.jobs.set(response.jobs);
        this.truncated.set(response.truncated);
        this.now.set(new Date().toISOString());
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
    });
    this.api.jobsAwaitingApproval().subscribe({
      next: (response) => this.awaiting.set(response.jobs),
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }

  /** Queues the read-only job the form describes. */
  protected createJob(): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .createReadJob({ hostId: this.chosenHost(), intent: this.chosenIntent(), params: {} })
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.reload();
        },
        error: (err: unknown) => {
          this.busy.set(false);
          this.actionError.set(describeError(err));
        },
      });
  }

  /** Records this operator's approval of a destructive job. */
  protected approve(job: Job): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api.approveJob(job.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.reload();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.actionError.set(describeError(err));
      },
    });
  }

  /** Renders how long ago a job was created. */
  protected age(job: Job): string {
    return formatAge(job.createdAt, this.now());
  }

  /** Renders the hostname for a job, falling back to the identifier the host has not named itself with. */
  protected hostname(job: Job): string {
    return this.hosts().find((host) => host.id === job.hostId)?.hostname ?? job.hostId;
  }

  /**
   * Describes how a job was authorised, in the words that matter.
   *
   * "mTLS only" is not a euphemism for unauthorised: a read intent changes nothing and reads nothing an
   * unprivileged local user could not, so the certificate is the whole of what it needs. Saying so
   * beside a signed job is what makes the difference between the tiers visible.
   */
  protected authorisation(job: Job): string {
    if (!job.signed) {
      return 'mTLS only';
    }
    return `signed by ${job.signerKeyId ?? 'an unnamed key'}`;
  }

  /** Reports whether this job is waiting for a second operator. */
  protected awaitingApproval(job: Job): boolean {
    return job.state === 'awaiting_approval';
  }

  /**
   * Reports whether a job's outcome is one an operator should look at.
   *
   * A refusal is not a failure, and the two are coloured differently on purpose: an operator who is
   * shown red for every job local policy declined learns to ignore red, which is the wrong lesson to
   * take from the mechanism working exactly as designed.
   */
  protected failed(job: Job): boolean {
    return job.state === 'failed';
  }

  /** Reports whether a job was refused rather than attempted. */
  protected refused(job: Job): boolean {
    return job.state.startsWith('refused_') || job.state === 'unsupported_intent' || job.state === 'expired';
  }
}
