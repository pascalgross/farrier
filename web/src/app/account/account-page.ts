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

import { Account, ApiToken, IssuedApiToken, OperatorSession } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { SessionStore } from '../core/session';
import { describeError } from '../core/errors';
import { formatAge } from '../core/format';

/** The shortest password the control plane will store, matching `server.MinPasswordLength`. */
const MIN_PASSWORD_LENGTH = 12;

/**
 * One choice of how long a token lasts, with the case it is for.
 *
 * A list rather than a number field, because "how many days" is a question nobody has an opinion about
 * until they are asked it in the abstract, and then they type 365. Naming the cases is what turns it
 * into a decision: a token being pasted into a pipeline today is not the same as one a CI runner will
 * hold for as long as the runner exists.
 */
interface Lifetime {
  /** Days, or zero for a token that does not expire. */
  days: number;

  /** What it is called on the form. */
  label: string;
}

/** The lifetimes offered, shortest first. */
const LIFETIMES: Lifetime[] = [
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 365, label: 'A year' },
  { days: 0, label: 'No expiry' },
];

/**
 * The signed-in account: its password, the browsers it is signed in on, and the tokens it has issued.
 *
 * It exists because removing the shared bearer token left three things with nowhere to happen. A
 * password could only be changed by somebody with a shell on the control plane; a session could only
 * be ended by whoever was holding it, so a laptop left on a train was unanswerable; and a script had
 * no credential at all once `FARRIER_ADMIN_TOKEN` was gone. This page is where all three now are.
 *
 * It is reachable by an operator and by a platform administrator alike, which no other page is. That
 * is not a convenience — everybody has an account and everybody has a password to change — and it is
 * why the route is excluded from the shell's platform redirect.
 *
 * An API token cannot reach any of it. A token acts as the account that issued it, which is what keeps
 * second-person approval honest, and the cost of that is that a token presented here would look
 * exactly like the person and could mint a second one, with no expiry, that survives the first being
 * revoked. The control plane refuses it with 403 rather than 401, so the message says the credential is
 * fine and is for something else.
 */
@Component({
  selector: 'farrier-account-page',
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
  templateUrl: './account-page.html',
  styleUrl: './account-page.scss',
})
export class AccountPage {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** Whether this browser is signed in, so signing out everywhere can drop the identity with it. */
  private readonly session = inject(SessionStore);

  /** The account, null until the first load answers. */
  protected readonly account = signal<Account | null>(null);

  /** The browsers this account is signed in on. */
  protected readonly sessions = signal<OperatorSession[]>([]);

  /** The tokens this account holds. */
  protected readonly tokens = signal<ApiToken[]>([]);

  /** Why the page could not be loaded, empty when it could. */
  protected readonly loadError = signal('');

  /** Whether the first load is still in flight. */
  protected readonly loading = signal(true);

  /** The clock the ages on this page are relative to, refreshed with each load. */
  protected readonly now = signal(new Date().toISOString());

  /** The current password being typed, for the change-password form. */
  protected readonly currentPassword = signal('');

  /** The replacement being typed. */
  protected readonly newPassword = signal('');

  /** The replacement typed a second time, because nobody can see what they typed. */
  protected readonly confirmPassword = signal('');

  /** Why the password change failed, empty when it did not. */
  protected readonly passwordError = signal('');

  /** What to say after a password change succeeded, empty when nothing has. */
  protected readonly passwordDone = signal('');

  /** Whether a password change is in flight. */
  protected readonly changing = signal(false);

  /** What the new token is to be called. */
  protected readonly tokenLabel = signal('');

  /** How long the new token lasts, in days, zero for no expiry. */
  protected readonly tokenDays = signal(LIFETIMES[1].days);

  /** The lifetimes offered. */
  protected readonly lifetimes = LIFETIMES;

  /**
   * The token just issued, null when none has been this visit.
   *
   * It is held in a signal rather than shown in a dialog because the value has to stay on screen
   * while somebody pastes it somewhere else, and a dialog is the thing people dismiss with the mouse
   * on the way to their terminal.
   */
  protected readonly issued = signal<IssuedApiToken | null>(null);

  /** Why minting or revoking a token failed, empty when neither did. */
  protected readonly tokenError = signal('');

  /** Whether a token operation is in flight. */
  protected readonly working = signal(false);

  /** Whether the change-password form has enough to submit, and agrees with itself. */
  protected readonly canChangePassword = computed(
    () =>
      !this.changing() &&
      this.currentPassword().length > 0 &&
      this.newPassword().length >= MIN_PASSWORD_LENGTH &&
      this.newPassword() === this.confirmPassword(),
  );

  /**
   * What is wrong with the replacement password as it stands, empty when nothing is.
   *
   * Shown as a hint rather than after a refused request, because both of these are answerable before
   * anything is sent and a round trip to be told "too short" is a round trip nobody needed.
   */
  protected readonly passwordHint = computed(() => {
    const replacement = this.newPassword();
    if (replacement.length > 0 && replacement.length < MIN_PASSWORD_LENGTH) {
      return `At least ${MIN_PASSWORD_LENGTH} characters. There is no rule about digits or symbols.`;
    }
    if (this.confirmPassword().length > 0 && replacement !== this.confirmPassword()) {
      return 'The two do not match.';
    }
    return '';
  });

  /** Whether the token form has enough to submit. */
  protected readonly canMintToken = computed(
    () => !this.working() && this.tokenLabel().trim().length > 0,
  );

  /**
   * Loads everything the page shows.
   *
   * In the constructor rather than in an effect or a resolver, because there is nothing to react to:
   * the page has one subject, it is whoever is signed in, and it does not change while the page is
   * open.
   */
  constructor() {
    this.load();
  }

  /**
   * Loads the account, its sessions and its tokens.
   *
   * Three requests rather than one document, because they change on different timescales and two of
   * them are refetched on their own after a write — a merged endpoint would mean re-reading the
   * password fields' surroundings every time somebody revoked a token.
   */
  protected load(): void {
    this.loading.set(true);
    this.now.set(new Date().toISOString());
    this.api.account().subscribe({
      next: (account) => {
        this.account.set(account);
        this.loadError.set('');
        this.loading.set(false);
      },
      error: (err: unknown) => {
        this.loadError.set(describeError(err));
        this.loading.set(false);
      },
    });
    this.loadSessions();
    this.loadTokens();
  }

  /** Re-reads the session list. */
  protected loadSessions(): void {
    this.now.set(new Date().toISOString());
    this.api.sessions().subscribe({
      next: (answer) => this.sessions.set(answer.sessions),
      error: (err: unknown) => this.loadError.set(describeError(err)),
    });
  }

  /** Re-reads the token list. */
  protected loadTokens(): void {
    this.api.apiTokens().subscribe({
      next: (answer) => this.tokens.set(answer.tokens),
      error: (err: unknown) => this.loadError.set(describeError(err)),
    });
  }

  /**
   * Changes the password, and clears the three fields whatever happens.
   *
   * Whatever happens, because the commonest failure is a mistyped current password and leaving it in
   * the box is how somebody submits the same wrong thing three times into a rate limit.
   */
  protected changePassword(): void {
    if (!this.canChangePassword()) {
      return;
    }
    this.changing.set(true);
    this.passwordError.set('');
    this.passwordDone.set('');
    this.api
      .changePassword({ currentPassword: this.currentPassword(), newPassword: this.newPassword() })
      .subscribe({
        next: () => {
          this.changing.set(false);
          this.clearPasswordFields();
          this.passwordDone.set(
            'Changed. Your other sessions are still signed in — sign out everywhere below if that ' +
              'is what you meant.',
          );
        },
        error: (err: unknown) => {
          this.changing.set(false);
          this.clearPasswordFields();
          this.passwordError.set(describeError(err));
        },
      });
  }

  /**
   * Ends every session, including this one.
   *
   * The identity is dropped locally afterwards rather than by calling sign-out, because the credential
   * this browser holds has already stopped working: a second request would have nothing to delete and
   * its failure would look like the sign-out having failed.
   */
  protected signOutEverywhere(): void {
    this.working.set(true);
    this.api.revokeSessions().subscribe({
      next: () => {
        this.working.set(false);
        this.session.forget();
      },
      error: (err: unknown) => {
        this.working.set(false);
        this.loadError.set(describeError(err));
      },
    });
  }

  /** Mints a token and shows it once. */
  protected mintToken(): void {
    if (!this.canMintToken()) {
      return;
    }
    this.working.set(true);
    this.tokenError.set('');
    this.api
      .createApiToken({ label: this.tokenLabel().trim(), expiresInDays: this.tokenDays() })
      .subscribe({
        next: (token) => {
          this.working.set(false);
          this.issued.set(token);
          this.tokenLabel.set('');
          this.loadTokens();
        },
        error: (err: unknown) => {
          this.working.set(false);
          this.tokenError.set(describeError(err));
        },
      });
  }

  /** Revokes one token, which stops it working immediately. */
  protected revokeToken(token: ApiToken): void {
    this.working.set(true);
    this.tokenError.set('');
    this.api.revokeApiToken(token.id).subscribe({
      next: () => {
        this.working.set(false);
        // The panel showing a just-issued value goes with it, so that revoking the token somebody is
        // still looking at does not leave its value on screen as though it were live.
        if (this.issued()?.id === token.id) {
          this.issued.set(null);
        }
        this.loadTokens();
      },
      error: (err: unknown) => {
        this.working.set(false);
        this.tokenError.set(describeError(err));
      },
    });
  }

  /** Dismisses the just-issued token, once somebody has copied it. */
  protected dismissIssued(): void {
    this.issued.set(null);
  }

  /** Renders how long ago an instant was, against the clock this page loaded with. */
  protected age(instant: string | null): string {
    return formatAge(instant, this.now());
  }

  /**
   * Describes a session in one line: what the browser said it was, and where from.
   *
   * Both halves are advisory and the template says so once, beside the list, rather than on every row.
   */
  protected describeSession(held: OperatorSession): string {
    const agent = held.userAgent.trim() || 'an unnamed client';
    return held.source ? `${agent} — ${held.source}` : agent;
  }

  /** Empties the three password fields. */
  private clearPasswordFields(): void {
    this.currentPassword.set('');
    this.newPassword.set('');
    this.confirmPassword.set('');
  }
}
