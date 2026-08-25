import { Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatBadgeModule } from '@angular/material/badge';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatDividerModule } from '@angular/material/divider';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
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
 * to be half-rendered. It offers an address and a password, which is what an operator has, and keeps a
 * bearer token beside it, which is what a fresh control plane prints before anybody has an account and
 * what the platform credential still is.
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
   * Moves a platform credential to the one page it can use.
   *
   * The default route is the fleet list, which a platform credential is refused by design. Landing
   * there and rendering the refusal would be technically honest and practically the same empty console
   * this change exists to remove.
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

  /** The bearer token being typed, for the credential that is one. */
  protected readonly token = signal('');

  /** Whether the token field is showing, so the account form is what an operator sees first. */
  protected readonly tokenShown = signal(false);

  /** Whether the account form has enough to submit. */
  protected readonly canSignIn = computed(
    () => !this.session.working() && this.email().trim().length > 0 && this.password().length > 0,
  );

  /** Whether the token form has enough to submit. */
  protected readonly canUseToken = computed(
    () => !this.session.working() && this.token().trim().length > 0,
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
      if (this.session.isPlatform() && !this.router.url.startsWith('/fleets')) {
        void this.router.navigate(['/fleets']);
      }
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

  /** Signs in with the bearer token on the form. */
  protected useToken(): void {
    if (!this.canUseToken()) {
      return;
    }
    this.session.useToken(this.token());
    this.token.set('');
  }

  /** Ends the session and forgets the token. */
  protected signOut(): void {
    this.session.signOut();
    this.email.set('');
    this.password.set('');
    this.token.set('');
  }
}
