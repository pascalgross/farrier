import { DatePipe } from '@angular/common';
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
import { CreateWallboardShareResponse, WallboardShare } from '../core/api.models';
import { describeError } from '../core/errors';
import { formatAge } from '../core/format';

/**
 * One choice of how long a link lives, with the case it is for.
 *
 * Named cases rather than a number field, for the reason the account page gives about token
 * lifetimes: "how many days" is a question nobody has an opinion about until it is asked in the
 * abstract, and then everybody types the maximum. There is no "never" here at all, and its absence
 * is the point — a share that does not expire is the shared, permanent credential §4.5 removed
 * wearing a different name.
 */
interface ShareLifetime {
  /** Days the link lives. Never zero: the control plane refuses a share without a deadline. */
  days: number;

  /** What it is called on the form. */
  label: string;
}

/** The lifetimes offered, shortest first. The longest is the server's own ceiling. */
const LIFETIMES: ShareLifetime[] = [
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 365, label: 'A year — the longest allowed' },
];

/**
 * Publishing this board to a screen, and withdrawing it again.
 *
 * A share is a bearer credential in a URL, which is the thing this project removed from operators on
 * principle, so the panel is written to keep the four differences visible rather than to make
 * publishing feel routine. It reaches one fixed-shape read of one fleet and can change nothing; it
 * carries a deadline chosen here, with no "never" on the form; it is withdrawn by deleting a row and
 * every screen holding it goes dark at its next poll; and it records who published it. What it does
 * not and cannot record is who reads it, which is why the list shows `createdBy` and offers no
 * access history: there is none to offer, and a column of dashes would imply there might be.
 *
 * The list keeps expired shares. A share that stopped working is the first thing somebody looks for
 * when the screen in the corridor has gone dark, and a list that hid it would answer "there is no
 * such link" to the person holding one.
 *
 * The link itself is shown exactly once, in the same shape as an enrolment token and an API token:
 * only its digest is stored, so a database dump is not a set of live wallboards, and there is
 * nothing to show again afterwards.
 */
@Component({
  selector: 'hostseal-share-panel',
  imports: [
    DatePipe,
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
  templateUrl: './share-panel.html',
})
export class SharePanel {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** The shares this fleet has published, newest first. */
  protected readonly shares = signal<WallboardShare[]>([]);

  /** Whether the list has been asked for yet, so opening twice does not fetch twice. */
  private readonly asked = signal(false);

  /**
   * Whether a read of the list is in flight.
   *
   * True before anybody has opened the panel, which is not a lie so much as the honest starting
   * answer: nothing has been read, so "nothing is published" is not something this panel knows yet.
   * Starting at false put that sentence in the markup of a closed panel, one frame from being shown
   * to whoever opened it.
   */
  protected readonly loading = signal(true);

  /** Why the list could not be read, empty when it could. */
  protected readonly loadError = signal('');

  /** The clock the ages in the list are measured against, refreshed with each read. */
  protected readonly now = signal(new Date().toISOString());

  /** What the new share will be called. */
  protected readonly label = signal('');

  /** How long the new share will live, in days. Ninety, matching the server's own default. */
  protected readonly days = signal(90);

  /** The optional passphrase, held only until it is sent. */
  protected readonly passphrase = signal('');

  /**
   * The share just published, with its link, or null when none has been this visit.
   *
   * Null again as soon as it is dismissed. Holding it any longer would leave a live credential on an
   * operator's screen behind whatever they do next, which on a board that reloads itself every
   * fifteen seconds is a long time for a secret to sit in a room.
   */
  protected readonly published = signal<CreateWallboardShareResponse | null>(null);

  /** Why publishing failed, empty when it did not. */
  protected readonly publishError = signal('');

  /** Whether a create or a delete is in flight, so the buttons can be disabled. */
  protected readonly working = signal(false);

  /** Whether the link has been copied, so the button can say so. */
  protected readonly copied = signal(false);

  /** The lifetimes the form offers. */
  protected readonly lifetimes = LIFETIMES;

  /** Whether the form has enough to publish: a name, and no request already in flight. */
  protected readonly canPublish = computed(
    () => !this.working() && this.label().trim().length > 0,
  );

  /**
   * Reads the list when the panel is opened, and not before.
   *
   * A native `<details>` and a first read on open, exactly as the enrolment panel does and for the
   * same two reasons: the expansion module costs more of the initial bundle than a disclosure widget
   * is worth, and this panel sits under a board that is already polling — an operator who never opens
   * it should not be adding a second request to every visit.
   *
   * The guard makes the toggle idempotent, because `toggle` fires on closing as well as opening.
   */
  protected open(): void {
    if (this.asked()) {
      return;
    }
    this.asked.set(true);
    this.load();
  }

  /** Re-reads the list, which is also what a create and a delete do afterwards. */
  protected load(): void {
    this.loading.set(true);
    this.api.wallboardShares().subscribe({
      next: (response) => {
        this.loading.set(false);
        this.shares.set(response.shares);
        this.now.set(response.serverTime);
        this.loadError.set('');
      },
      error: (err: unknown) => {
        this.loading.set(false);
        this.loadError.set(describeError(err));
      },
    });
  }

  /**
   * Publishes a link and shows it once.
   *
   * The passphrase is cleared from the form with everything else. It is not stored anywhere by this
   * application, and it cannot be recovered from the control plane either — what is kept there is an
   * Argon2id hash — so an operator who forgets it revokes the share and publishes another.
   */
  protected publish(): void {
    if (!this.canPublish()) {
      return;
    }
    this.working.set(true);
    this.publishError.set('');
    this.copied.set(false);
    const secret = this.passphrase();
    this.api
      .createWallboardShare({
        label: this.label().trim(),
        days: this.days(),
        ...(secret ? { passphrase: secret } : {}),
      })
      .subscribe({
        next: (response) => {
          this.working.set(false);
          this.published.set(response);
          this.label.set('');
          this.passphrase.set('');
          this.load();
        },
        error: (err: unknown) => {
          this.working.set(false);
          this.publishError.set(describeError(err));
        },
      });
  }

  /**
   * Withdraws one share.
   *
   * There is no confirmation, which matches how an API token is revoked here and is the right way
   * round for this particular mistake: revoking a share that was still wanted costs one republish and
   * a walk to a television, and a dialogue in the way costs an operator hesitating over a link they
   * have decided they do not recognise.
   */
  protected revoke(share: WallboardShare): void {
    this.working.set(true);
    this.loadError.set('');
    this.api.deleteWallboardShare(share.id).subscribe({
      next: () => {
        this.working.set(false);
        // The just-published panel goes with it, so that revoking the share somebody is still looking
        // at does not leave its link on screen as though it were live.
        if (this.published()?.share.id === share.id) {
          this.dismiss();
        }
        this.load();
      },
      error: (err: unknown) => {
        this.working.set(false);
        this.loadError.set(describeError(err));
      },
    });
  }

  /** Dismisses the just-published link, once somebody has copied it. */
  protected dismiss(): void {
    this.published.set(null);
    this.copied.set(false);
  }

  /**
   * Copies the link, best effort.
   *
   * Best effort like every other copy button here: several browsers refuse clipboard access without
   * a gesture they recognise, and the link is on screen and selectable — a refusal must not look
   * like the link itself being wrong.
   */
  protected async copy(): Promise<void> {
    const link = this.published()?.link;
    if (!link || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(link);
      this.copied.set(true);
    } catch {
      // Left on screen for a manual copy, which is the fallback that always works.
    }
  }

  /** Renders how long ago an instant was, against the control plane's clock. */
  protected age(instant: string | null): string {
    return formatAge(instant, this.now());
  }
}
