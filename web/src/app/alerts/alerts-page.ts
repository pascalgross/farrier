import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';

import { AlertRule } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import { formatDuration } from '../core/format';

/** One condition, with the words that make its threshold mean something. */
interface ConditionSpec {
  /** The wire value the API takes. */
  value: string;

  /** What the picker calls it. */
  label: string;

  /** Why an operator would want it, in one line. */
  rationale: string;

  /** What the threshold counts, empty for a condition that ignores it. */
  unit: string;
}

/**
 * The conditions this control plane evaluates, with their units spelled out.
 *
 * The unit is the whole reason this table exists rather than a plain string list: `threshold` is one
 * integer column on the server, and a form that asked for "threshold" without saying whether it meant
 * minutes, packages or days would produce a rule that fires a fortnight late and an operator who
 * blames the alerting.
 */
const CONDITIONS: ConditionSpec[] = [
  {
    value: 'host_silent',
    label: 'Host silent',
    rationale: 'The only signal that separates a quiet fleet from a dead agent.',
    unit: 'minutes without a heartbeat',
  },
  {
    value: 'security_updates',
    label: 'Security updates pending',
    rationale: 'The one number this product exists to show, crossing a line.',
    unit: 'pending security updates',
  },
  {
    value: 'reboot_required',
    label: 'Reboot overdue',
    rationale: 'The thing that never gets done until it is an incident.',
    unit: 'days a reboot has been outstanding',
  },
  {
    value: 'unit_failed',
    label: 'Unit failed',
    rationale: 'Fires on the event itself, bounded by each host’s own watch list.',
    unit: '',
  },
  {
    value: 'job_failed',
    label: 'Job failed or expired',
    rationale: 'A job dropped for age is exactly where silence is the wrong answer.',
    unit: '',
  },
];

/**
 * The alerting page: which events are worth waking somebody for, and who.
 *
 * Two things about it are load-bearing rather than cosmetic.
 *
 * **A rule produces a notification and never a job.** There is no "apply the updates when more than
 * five are pending" control here, and its absence is deliberate: auto-remediation does not break the
 * guarantee — a host's own policy still bounds it and anything destructive still needs an offline
 * signature — but it converts the control plane from something that asks into something that acts on
 * a schedule of its own, which is a different feature with a different argument.
 *
 * **Mail is the only delivery an operator opts into per rule.** The inbox, the live stream and the
 * tenant webhook receive every event regardless; recipients here are the one delivery that interrupts
 * somebody. So the page says loudly when a rule names recipients on an installation with no relay,
 * and shows what happened to the last attempt — an alert that never went out and an alert that never
 * fired are indistinguishable from an inbox.
 */
@Component({
  selector: 'farrier-alerts-page',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatSelectModule,
    MatSlideToggleModule,
    MatTooltipModule,
  ],
  templateUrl: './alerts-page.html',
  styleUrl: './alerts-page.scss',
})
export class AlertsPage {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The conditions offered, for the form. */
  protected readonly conditions = CONDITIONS;

  /** The rules, null while the first load is in flight. */
  protected readonly rules = signal<AlertRule[] | null>(null);

  /** What a zero cooldown means on this control plane. */
  protected readonly defaultCooldown = signal(0);

  /** Whether this installation has a mail relay configured at all. */
  protected readonly mailConfigured = signal(true);

  /** Why the page could not load, empty when it did. */
  protected readonly error = signal('');

  /** Why the last create, edit or delete failed, shown beside the form. */
  protected readonly actionError = signal('');

  /** Whether a write is in flight, so the buttons can be disabled. */
  protected readonly busy = signal(false);

  /** The condition chosen in the form. */
  protected readonly newCondition = signal(CONDITIONS[0].value);

  /** The threshold typed in the form. */
  protected readonly newThreshold = signal(15);

  /** The cooldown typed in the form, in minutes, zero for the server's default. */
  protected readonly newCooldownMinutes = signal(0);

  /** The recipients typed in the form, comma or whitespace separated. */
  protected readonly newRecipients = signal('');

  /** The spec for the condition currently chosen, so the form can name its unit. */
  protected readonly chosenSpec = computed(
    () => CONDITIONS.find((c) => c.value === this.newCondition()) ?? CONDITIONS[0],
  );

  /** Whether the chosen condition takes a threshold at all. */
  protected readonly needsThreshold = computed(() => this.chosenSpec().unit.length > 0);

  /** Whether the form has enough to submit. */
  protected readonly canCreate = computed(
    () => !this.busy() && (!this.needsThreshold() || this.newThreshold() >= 1),
  );

  /** Loads the rules. */
  constructor() {
    this.reload();
  }

  /** Re-reads the rules from the control plane, which is the answer rather than a local patch. */
  protected reload(): void {
    this.api.alertRules().subscribe({
      next: (response) => {
        this.rules.set(response.rules);
        this.defaultCooldown.set(response.defaultCooldownSeconds);
        this.mailConfigured.set(response.mailConfigured);
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }

  /** Creates the rule the form describes. */
  protected create(): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .createAlertRule({
        condition: this.newCondition(),
        threshold: this.needsThreshold() ? this.newThreshold() : 0,
        cooldownSeconds: Math.max(0, Math.floor(this.newCooldownMinutes() * 60)),
        emailTo: splitRecipients(this.newRecipients()),
      })
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.newRecipients.set('');
          this.reload();
        },
        error: (err: unknown) => {
          this.busy.set(false);
          this.actionError.set(describeError(err));
        },
      });
  }

  /**
   * Turns one rule on or off.
   *
   * Disabling rather than deleting is the usual answer during an incident — a rule that is firing
   * about the thing everybody is already looking at is noise, and its history is worth keeping.
   */
  protected setEnabled(rule: AlertRule, enabled: boolean): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .updateAlertRule(rule.id, {
        threshold: rule.threshold,
        cooldownSeconds: rule.cooldownSeconds,
        emailTo: rule.emailTo,
        enabled,
      })
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

  /** Deletes a rule and the firing state it accumulated. */
  protected remove(rule: AlertRule): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api.deleteAlertRule(rule.id).subscribe({
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

  /** Describes one rule's condition in a sentence, threshold and unit included. */
  protected describe(rule: AlertRule): string {
    const spec = CONDITIONS.find((c) => c.value === rule.condition);
    if (!spec) {
      return rule.condition;
    }
    return spec.unit ? `${spec.label} — over ${rule.threshold} ${spec.unit}` : spec.label;
  }

  /** Renders a rule's cooldown, naming the server's default when the rule sets none. */
  protected cooldown(rule: AlertRule): string {
    const seconds = rule.cooldownSeconds > 0 ? rule.cooldownSeconds : this.defaultCooldown();
    const suffix = rule.cooldownSeconds > 0 ? '' : ' (default)';
    return `${formatDuration(seconds)}${suffix}`;
  }
}

/**
 * Splits a typed recipient list into addresses.
 *
 * Commas, semicolons and whitespace all separate, because an operator pasting from an address book
 * gets whichever of those that book used, and a form that accepted only one of them would silently
 * create a rule with a single nonsense recipient.
 */
function splitRecipients(raw: string): string[] {
  return raw
    .split(/[,;\s]+/)
    .map((address) => address.trim())
    .filter((address) => address.length > 0);
}
