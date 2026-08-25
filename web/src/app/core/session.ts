import { Injectable, inject, signal } from '@angular/core';

import { ApiService } from './api.service';
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
 * There is one credential and it is this. The bearer token that used to sit beside it — pasted into a
 * box, kept in `localStorage`, readable by any script on this origin — is gone: a shared string that
 * named nobody in the audit trail is not something an interface should be teaching people to paste.
 * What a script uses now is an API token belonging to an account, minted from the account page, and it
 * never touches this application.
 */
@Injectable({ providedIn: 'root' })
export class SessionStore {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

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
   * credential worked and reaches nothing this interface renders. Reporting that as "wrong password"
   * would send them looking for the wrong mistake.
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

  /**
   * Whether the signed-in credential administers fleets rather than acting in one.
   *
   * The two reach disjoint sets of routes — a platform credential is refused by every route that
   * reaches a fleet's hosts or jobs, and an operator credential by every route that administers
   * fleets — so this is not a preference about what to show. Rendering the fleet navigation to a
   * platform administrator would be six links that each answer 403.
   */
  isPlatform(): boolean {
    return this.who()?.platform === true;
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
   * Ends the session.
   *
   * The local state is cleared without waiting for the server, because the one thing worse than a
   * failed sign-out is a sign-out that appears not to have happened. The server-side row is deleted by
   * the request either way, which is what makes this mean the credential stops working rather than
   * merely stops being sent.
   */
  signOut(): void {
    this.api.signOut().subscribe({
      next: () => undefined,
      error: () => undefined,
    });
    this.forget();
  }

  /**
   * Forgets who this browser was, without asking the control plane anything.
   *
   * It is what "sign out everywhere" needs: that request has already ended every session including
   * this one, so calling signOut() after it would be a second request with nothing left to delete —
   * and one whose failure would look like the sign-out having failed.
   */
  forget(): void {
    this.who.set(null);
    this.failure.set('');
    this.mismatch.set('');
    this.checked.set(true);
  }
}
