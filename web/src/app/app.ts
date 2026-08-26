import { Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatBadgeModule } from '@angular/material/badge';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatDividerModule } from '@angular/material/divider';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { EventStream } from './core/event-stream';
import { SessionStore } from './core/session';
import { ToastStack } from './toasts/toast-stack';

/**
 * The application shell: a toolbar, the router outlet, and the sign-in form.
 *
 * The form lives here rather than on a separate route because there is nowhere else to be: every page
 * needs a credential, so a `/login` route would be a redirect target and a second place for the shell
 * to be half-rendered. It offers an address and a password and nothing else. The bearer-token box that
 * used to sit under a divider is gone with the credential it took: a script now carries an API token
 * belonging to an account, minted from the account page, and never types anything into this form.
 *
 * Whether somebody is signed in is asked of the control plane rather than read locally, and that is
 * forced rather than chosen: the credential is an HttpOnly cookie no script can see. So the shell has
 * three states, not two — checking, signed in, signed out — and the first one renders a progress bar,
 * because flashing a sign-in form at somebody who is already signed in is worse than a moment of
 * nothing.
 *
 * The toolbar names the fleet this credential reaches. It is not a switcher and there is nothing to
 * switch to: one credential reaches one fleet, so the name is there for the operator with two tabs
 * open, not to be clicked.
 *
 * The live feed is connected here and the toast stack is rendered here for the same reason: this is
 * the only component that is always mounted, so it is the only place a notification can reach an
 * operator who is on the fleet list rather than on the events page.
 */
@Component({
  selector: 'farrier-root',
  imports: [
    FormsModule,
    MatBadgeModule,
    MatButtonModule,
    MatCardModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatMenuModule,
    MatProgressBarModule,
    MatToolbarModule,
    MatTooltipModule,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
    ToastStack,
  ],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  /** Whether this browser is signed in, and as whom. */
  protected readonly session = inject(SessionStore);

  /**
   * Asks the router to re-check where we are when the identity settles.
   *
   * The routes decide who may be where; this only re-poses the question. See the effect in the
   * constructor for why that transition needs re-posing at all.
   */
  private readonly router = inject(Router);

  /**
   * The live event feed, connected here rather than on the events page.
   *
   * The shell is the only component that is always mounted, and the bell has to keep counting while
   * an operator is on the fleet list — which is the whole point of a bell. The page reads the same
   * feed rather than opening a second stream.
   */
  protected readonly events = inject(EventStream);

  /** The address being typed. */
  protected readonly email = signal('');

  /** The password being typed, held only until it is sent. */
  protected readonly password = signal('');

  /** Whether the password is being shown, so somebody can check what they typed. */
  protected readonly passwordShown = signal(false);

  /** Whether the form has enough to submit. */
  protected readonly canSignIn = computed(
    () => !this.session.working() && this.email().trim().length > 0 && this.password().length > 0,
  );

  /**
   * Asks who this browser is, and keeps the live feed matched to the answer.
   *
   * The effect is what replaces the four places that used to start and stop the stream by hand — the
   * constructor, the two sign-in paths and sign-out. There is exactly one rule, written once: the feed
   * runs when somebody is signed in. It also drops the feed on sign-out rather than leaving it
   * running, because it holds this fleet's events and a signed-out console showing the last hour of
   * somebody else's incidents is the sort of leak nobody notices until it matters.
   */
  constructor() {
    this.session.probe();
    effect(() => {
      // The feed is a fleet's events, so it belongs to an operator and to nobody else: a platform
      // credential is refused by the stream exactly as it is by every other fleet route, and starting
      // it would be a reconnect loop against a 403.
      if (this.session.signedIn() && !this.session.isPlatform()) {
        this.events.start();
      } else {
        this.events.stop();
      }
    });
    effect(() => {
      // Which routes a credential may reach is declared on the routes themselves, in `canMatch` — see
      // app.routes.ts and core/platform-guard.ts. This effect does not repeat that decision and must
      // not: it says only that the answer may have changed, and asks the router to put the question
      // again for wherever we already are.
      //
      // That transition is the one case a guard cannot cover on its own. The first navigation happens
      // before `whoami` has answered, so the guards see "not signed in" and let everything match; when
      // the identity arrives a moment later, nothing navigates and nothing would ask again. Reading
      // `router.url` here is honest for exactly that purpose — it is a snapshot of where we are, not a
      // subscription to where we go.
      const known = this.session.ready() && this.session.signedIn();
      // Read unconditionally, so the effect tracks it rather than only tracking it on some paths.
      this.session.isPlatform();
      if (!known) {
        return;
      }
      void this.router.navigateByUrl(this.router.url, { onSameUrlNavigation: 'reload' });
    });
  }

  /** Signs in with the address and password on the form. */
  protected signIn(): void {
    if (!this.canSignIn()) {
      return;
    }
    this.session.signIn(this.email().trim(), this.password());
    this.password.set('');
  }

  /** Ends the session. */
  protected signOut(): void {
    this.session.signOut();
    this.email.set('');
    this.password.set('');
    this.passwordShown.set(false);
  }
}
