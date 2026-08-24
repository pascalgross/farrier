import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatBadgeModule } from '@angular/material/badge';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { ApiService } from './core/api.service';
import { EventStream } from './core/event-stream';
import { ToastStack } from './toasts/toast-stack';
import { Whoami } from './core/api.models';
import { describeError } from './core/errors';
import { TokenStore } from './core/token-store';

/**
 * The application shell: a toolbar, the router outlet, and the operator token prompt.
 *
 * The token prompt lives here rather than on a separate login route because there is no session to
 * establish — the control plane accepts a bearer token and nothing else. A full login page would imply
 * a flow that does not exist, and implying a mechanism you do not have is how a security claim becomes
 * untrue by accident.
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
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
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
  /** Holds the operator's bearer token. */
  protected readonly tokens = inject(TokenStore);

  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /**
   * The live event feed, connected here rather than on the events page.
   *
   * The shell is the only component that is always mounted, and the bell has to keep counting while
   * an operator is on the fleet list — which is the whole point of a bell. The page reads the same
   * feed rather than opening a second stream.
   */
  protected readonly events = inject(EventStream);

  /** The token being typed, before it is stored. */
  protected readonly draft = signal('');

  /** Who the control plane says this credential is, null until it has answered. */
  protected readonly me = signal<Whoami | null>(null);

  /** Why the identity could not be read, empty when it could. */
  protected readonly identityError = signal('');

  /** Asks who this credential is, as soon as there is one to ask about. */
  constructor() {
    if (this.tokens.hasToken()) {
      this.loadIdentity();
      this.events.start();
    }
  }

  /**
   * Reads the current identity.
   *
   * A failure is shown rather than swallowed: the most likely cause is a platform credential, which
   * administers tenants and deliberately reaches no fleet, and somebody who pasted the wrong one of
   * their two tokens needs to be told that rather than shown an empty fleet list.
   */
  private loadIdentity(): void {
    this.api.whoami().subscribe({
      next: (me) => {
        this.me.set(me);
        this.identityError.set('');
      },
      error: (err: unknown) => this.identityError.set(describeError(err)),
    });
  }

  /** Stores the typed token, which makes every subsequent request authenticated. */
  protected save(): void {
    this.tokens.set(this.draft());
    this.draft.set('');
    this.loadIdentity();
    this.events.start();
  }

  /** Forgets the token, returning the application to the prompt. */
  protected signOut(): void {
    this.tokens.clear();
    this.me.set(null);
    this.identityError.set('');
    // The feed is dropped rather than left running: it holds this fleet's events, and a signed-out
    // console showing the last hour of somebody else's incidents is the sort of leak nobody notices
    // until it matters.
    this.events.stop();
  }
}
