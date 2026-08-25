import { Injectable, inject, signal } from '@angular/core';

import { ApiService } from './api.service';
import { TokenStore } from './token-store';
import { Whoami } from './api.models';
import { describeError, describeRefusedCredential } from './errors';

/**
 * Whether this browser is signed in, and as whom.
 *
 * It exists because the answer stopped being something the application could look up. A bearer token
 * was in `localStorage`, so "are we signed in" was one synchronous read; a session is an HttpOnly
 * cookie the browser holds and no script can see, so the only way to ask is to ask the control plane.
 * That turns a boolean into a small state machine with a `checking` state, and this is where it lives
 * so that the shell is not the only component that could ever know.
 *
 * The two credentials are deliberately both here. An account is what a person uses; a bearer token is
 * what a fresh control plane prints before anybody has an account, and what the platform credential
 * still is. Signing out clears both, because an operator who pressed it has said what they meant.
 */
@Injectable({ providedIn: 'root' })
export class SessionStore {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** Holds the bearer token, for the credential that is one. */
  private readonly tokens = inject(TokenStore);

  /** Who the control plane says this browser is, null when nobody. */
  private readonly who = signal<Whoami | null>(null);

  /** Whether the first probe has answered, so the shell can wait rather than flash a sign-in form. */
  private readonly checked = signal(false);

  /** Why the last sign-in failed, empty when it did not. */
  private readonly failure = signal('');

  /** Whether a sign-in is in flight, so the form can be disabled. */
  private readonly busy = signal(false);

  /**
   * Why a credential that authenticated cannot be used here, empty when there is no such problem.
   *
   * It is separate from a sign-in failure because it is a different thing to tell somebody: the
   * credential worked and reaches nothing this interface renders, which is what happens when a
   * platform token — which administers fleets and deliberately reaches no fleet's hosts — is pasted
   * into the box. Reporting that as "wrong password" would send them looking for the wrong mistake.
   */
  private readonly mismatch = signal('');

  /** Who this browser is signed in as, null when nobody. */
  identity(): Whoami | null {
    return this.who();
  }

  /** Whether the first probe has answered. */
  ready(): boolean {
    return this.checked();
  }

  /** Whether somebody is signed in. */
  signedIn(): boolean {
    return this.who() !== null;
  }

  /** Why the last sign-in failed, empty when it did not. */
  error(): string {
    return this.failure();
  }

  /** Why a credential that authenticated reaches nothing here, empty when there is no such problem. */
  unusable(): string {
    return this.mismatch();
  }

  /** Whether a sign-in is in flight. */
  working(): boolean {
    return this.busy();
  }

  /**
   * Asks the control plane who this browser is.
   *
   * Called once on start, and after each sign-in. A 401 is not an error to show anybody — it is the
   * ordinary answer for a browser that has not signed in yet — so it clears the identity and settles
   * the state rather than surfacing a message.
   */
  probe(): void {
    this.api.whoami().subscribe({
      next: (me) => {
        this.who.set(me);
        this.mismatch.set('');
        this.checked.set(true);
      },
      error: (err: unknown) => {
        this.who.set(null);
        this.mismatch.set(describeRefusedCredential(err));
        this.checked.set(true);
      },
    });
  }

  /**
   * Signs in with an address and a password.
   *
   * The identity comes from `whoami` rather than from the sign-in response, even though the response
   * says who signed in: `whoami` also names the fleet, and the toolbar needs that before it renders
   * anything. One extra round trip, once, at the moment somebody is already waiting for a page.
   */
  signIn(email: string, password: string): void {
    this.busy.set(true);
    this.failure.set('');
    this.api.signIn({ email, password }).subscribe({
      next: () => {
        this.busy.set(false);
        this.probe();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.failure.set(describeError(err));
      },
    });
  }

  /**
   * Signs in with a bearer token, which is what a fresh control plane prints at startup.
   *
   * Kept beside the account form rather than removed, because the first person to open a new
   * installation has no account and the token is how they get one — and because the platform
   * credential is still a token. It is stored in `localStorage`, with the trade `TokenStore`
   * describes; an account does not, which is the reason to prefer one.
   */
  useToken(token: string): void {
    this.busy.set(true);
    this.failure.set('');
    this.tokens.set(token);
    this.api.whoami().subscribe({
      next: (me) => {
        this.busy.set(false);
        this.who.set(me);
        this.mismatch.set('');
        this.checked.set(true);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        // The token is forgotten again rather than left behind: a stored credential that does not
        // work is one every later request pays for and one the next reload silently retries.
        this.tokens.clear();
        this.who.set(null);
        const unusable = describeRefusedCredential(err);
        this.failure.set(unusable || describeError(err));
        this.checked.set(true);
      },
    });
  }

  /**
   * Ends the session and forgets the token.
   *
   * Both, unconditionally. An operator who pressed sign out has said what they meant, and a browser
   * that kept one of the two credentials would come back signed in for a reason nobody could see.
   * The local state is cleared without waiting for the server, because the one thing worse than a
   * failed sign-out is a sign-out that appears not to have happened.
   */
  signOut(): void {
    this.api.signOut().subscribe({
      next: () => undefined,
      error: () => undefined,
    });
    this.tokens.clear();
    this.who.set(null);
    this.failure.set('');
    this.mismatch.set('');
    this.checked.set(true);
  }
}
