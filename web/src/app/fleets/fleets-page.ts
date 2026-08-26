import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatTooltipModule } from '@angular/material/tooltip';

import { ApiService } from '../core/api.service';
import { Tenant } from '../core/api.models';
import { describeError } from '../core/errors';

/**
 * One approval mode, with the sentence that explains when to choose it.
 *
 * A table here rather than three options and a link, because this is the moment somebody decides it —
 * and "who has to agree before a host may act on a destructive job" is not a question anybody answers
 * correctly from a value called `second_person`.
 */
interface ApprovalOption {
  /** The value the API takes. */
  value: string;

  /** What it is called on the form. */
  label: string;

  /** Why an installation would choose it. */
  rationale: string;
}

/** The three modes, in increasing order of how many people have to agree. */
const APPROVAL_MODES: ApprovalOption[] = [
  {
    value: 'none',
    label: 'No approval',
    rationale:
      'The offline signature is the whole of the control plane’s authorisation. Right for a fleet ' +
      'with one operator, and the default.',
  },
  {
    value: 'self',
    label: 'Somebody must release it',
    rationale: 'A destructive job waits until somebody presses approve, and it may be its own author.',
  },
  {
    value: 'second_person',
    label: 'A second person must release it',
    rationale:
      'Somebody other than the job’s author. It needs every operator to be a distinct principal, ' +
      'which means accounts rather than a shared token.',
  },
];

/**
 * The fleets on this installation, for the platform credential and nobody else.
 *
 * It exists because the tenant API had no interface at all. Everything it does was already reachable
 * with `curl` and documented in `INSTALL.md`, and that is a different thing from being findable: an
 * installation's administrator who pasted their token into the sign-in form landed on an empty console
 * that said "identity unknown", because every route the interface rendered refuses their credential by
 * design.
 *
 * What it deliberately does **not** do is hand out a way into a fleet. Creating one does not create a
 * credential for it, and there is no control here that could — `docs/SECURITY.md` §5.3 turns on the
 * platform administrator being unable to authenticate as a customer, so the route that would allow it
 * does not exist. What the page does instead is say, at the moment somebody has just created a fleet
 * and is wondering what happens next, exactly which command to run on the control plane.
 *
 * There is also nothing here that reaches a fleet's hosts, jobs, results or tokens, and that is not a
 * shortage of screen space: this credential is refused by every one of those routes. Running Farrier
 * for other people should not require being able to read what they run.
 */
@Component({
  selector: 'farrier-fleets-page',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatSelectModule,
    MatTooltipModule,
  ],
  templateUrl: './fleets-page.html',
  styleUrl: './fleets-page.scss',
})
export class FleetsPage {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The approval modes offered, for both forms. */
  protected readonly approvalModes = APPROVAL_MODES;

  /** The fleets, null while the first load is in flight. */
  protected readonly fleets = signal<Tenant[] | null>(null);

  /** Why the page could not load, empty when it did. */
  protected readonly error = signal('');

  /** Why the last create or edit failed, shown beside the form that failed. */
  protected readonly actionError = signal('');

  /** Whether a write is in flight, so the buttons can be disabled. */
  protected readonly busy = signal(false);

  /** The slug being typed for a new fleet. */
  protected readonly newSlug = signal('');

  /** The display name being typed for a new fleet, empty for the slug. */
  protected readonly newName = signal('');

  /** The approval mode chosen for a new fleet. */
  protected readonly newApproval = signal('none');

  /** The fleet whose settings are open, empty for none. */
  protected readonly open = signal('');

  /** The slug of the fleet created most recently, so the page can name its next step. */
  protected readonly created = signal('');

  /**
   * The sentence explaining the mode currently chosen on the new-fleet form.
   *
   * A computed rather than an `@if` inside the `<mat-form-field>`: Material projects `mat-hint` with a
   * content selector, and a hint inside a template block is not projected at all — it renders inside
   * the field's own outline instead, which looks exactly like a broken component.
   */
  protected readonly chosenRationale = computed(
    () => APPROVAL_MODES.find((mode) => mode.value === this.newApproval())?.rationale ?? '',
  );

  /** Whether the new-fleet form has enough to submit. */
  protected readonly canCreate = computed(
    () => !this.busy() && SLUG_PATTERN.test(this.newSlug().trim()),
  );

  /** Loads the fleets. */
  constructor() {
    this.reload();
  }

  /** Re-reads the fleets from the control plane, which is the answer rather than a local patch. */
  protected reload(): void {
    this.api.tenants().subscribe({
      next: (response) => {
        this.fleets.set(response.tenants);
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }

  /** Creates a fleet, and remembers which one so the page can say what to do next. */
  protected create(): void {
    if (!this.canCreate()) {
      return;
    }
    const slug = this.newSlug().trim();
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .createTenant({
        slug,
        displayName: this.newName().trim() || slug,
        approvalMode: this.newApproval(),
      })
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.created.set(slug);
          this.newSlug.set('');
          this.newName.set('');
          this.reload();
        },
        error: (err: unknown) => {
          this.busy.set(false);
          this.actionError.set(describeError(err));
        },
      });
  }

  /** Changes one fleet's approval mode. */
  protected setApproval(fleet: Tenant, mode: string): void {
    this.patch(fleet, { approvalMode: mode });
  }

  /** Changes one fleet's event webhook. */
  protected setWebhook(fleet: Tenant, url: string): void {
    this.patch(fleet, { webhookUrl: url.trim() });
  }

  /** Changes one fleet's display name. */
  protected setName(fleet: Tenant, name: string): void {
    const trimmed = name.trim();
    if (trimmed.length === 0 || trimmed === fleet.displayName) {
      return;
    }
    this.patch(fleet, { displayName: trimmed });
  }

  /**
   * Applies one change to one fleet.
   *
   * A patch of exactly the field that changed, never the whole record: the API distinguishes "not
   * sent" from "sent empty", so writing back a whole tenant would clear a webhook somebody set from a
   * form that never showed it.
   */
  private patch(fleet: Tenant, change: Record<string, string>): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api.updateTenant(fleet.id, change).subscribe({
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

  /** Opens or closes one fleet's settings. */
  protected toggle(fleet: Tenant): void {
    this.open.update((held) => (held === fleet.id ? '' : fleet.id));
  }

  /** Names the approval mode a fleet is on, for the summary line. */
  protected approvalLabel(fleet: Tenant): string {
    return APPROVAL_MODES.find((mode) => mode.value === fleet.approvalMode)?.label ?? fleet.approvalMode;
  }

  /** The command that gives a fleet its first operator, which is the step this page cannot take. */
  protected accountCommand(slug: string): string {
    return `farrier-server accounts add --tenant ${slug} --email ops@example.org`;
  }
}

/**
 * The shape a slug may take, matching the server's own pattern.
 *
 * Checked here as well so that the button is disabled rather than the request refused — the constraint
 * is not a rule anybody has to discover twice. The server checks it too, because a client-side check
 * is a convenience and never a boundary.
 */
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
