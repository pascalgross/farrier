import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatToolbarModule } from '@angular/material/toolbar';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { TokenStore } from './core/token-store';

/**
 * The application shell: a toolbar, the router outlet, and the operator token prompt.
 *
 * The token prompt lives here rather than on a separate login route because there is no session to
 * establish — the control plane accepts a bearer token and nothing else in phase 0. A full login page
 * would imply a flow that does not exist, and implying a mechanism you do not have is how a security
 * claim becomes untrue by accident.
 */
@Component({
  selector: 'farrier-root',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatToolbarModule,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
  ],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  /** Holds the operator's bearer token. */
  protected readonly tokens = inject(TokenStore);

  /** The token being typed, before it is stored. */
  protected readonly draft = signal('');

  /** Stores the typed token, which makes every subsequent request authenticated. */
  protected save(): void {
    this.tokens.set(this.draft());
    this.draft.set('');
  }

  /** Forgets the token, returning the application to the prompt. */
  protected signOut(): void {
    this.tokens.clear();
  }
}
