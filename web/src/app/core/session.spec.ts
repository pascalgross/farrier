import { TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';

import { ApiService } from './api.service';
import { SessionStore } from './session';
import { Whoami } from './api.models';

/** One identity the control plane can answer `whoami` with. */
function whoami(): Whoami {
  return {
    subject: 'alice@example.org',
    display: 'Alice',
    provider: 'local-account',
    principal: 'local-account:alice@example.org',
    platform: false,
    tenant: {
      id: 'tenant-alpha',
      slug: 'alpha',
      displayName: 'Alpha',
      createdAt: '2026-01-01T00:00:00Z',
      approvalMode: 'none',
      webhookUrl: '',
    },
  };
}

/** An HTTP failure of the shape describeError and describeRefusedCredential duck-type. */
function refusal(status: number, message: string): Observable<never> {
  return throwError(() => ({ status, error: { error: 'refused', message } }));
}

/** What each fake ApiService method should do for one spec. */
interface Answers {
  /** What `whoami` returns, in order, one per call. */
  whoami: Observable<Whoami>[];

  /** What `signIn` returns. */
  signIn?: Observable<unknown>;
}

/** Builds the store over a fake control plane. */
function build(answers: Answers): SessionStore {
  let asked = 0;
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          whoami: () => answers.whoami[Math.min(asked++, answers.whoami.length - 1)],
          signIn: () => answers.signIn ?? of({}),
          signOut: () => of({}),
        } as unknown as ApiService,
      },
    ],
  });
  return TestBed.inject(SessionStore);
}

describe('SessionStore', () => {
  /**
   * The credential is an HttpOnly cookie, so the application cannot look at it — the only way to know
   * whether somebody is signed in is to ask. That makes "not yet answered" a third state, and a shell
   * that treated it as "signed out" would flash the sign-in form at everybody on every reload.
   */
  it('does not claim to know anything until the control plane has answered', () => {
    const session = build({ whoami: [of(whoami())] });

    expect(session.ready()).withContext('before probe()').toBeFalse();

    session.probe();
    expect(session.ready()).toBeTrue();
    expect(session.signedIn()).toBeTrue();
    expect(session.identity()?.principal).toBe('local-account:alice@example.org');
  });

  /**
   * A 401 from `whoami` is the ordinary answer for a browser that has not signed in, not a failure
   * worth putting in front of anybody. Surfacing it would put an error message on the sign-in form of
   * every first visit.
   */
  it('treats a refusal as signed out rather than as an error', () => {
    const session = build({ whoami: [refusal(401, 'a valid operator credential is required')] });

    session.probe();
    expect(session.signedIn()).toBeFalse();
    expect(session.ready()).toBeTrue();
    expect(session.error()).toBe('');
    expect(session.unusable()).toBe('');
  });

  /**
   * A credential that authenticates and reaches nothing the interface renders used to be reported as
   * a wrong one, which sent people to check what they typed rather than to look for the real problem.
   * `whoami` answers a platform administrator, so this is the fallback for whatever else 403 could
   * mean — an API token reaching the account page, say — rather than the platform case itself.
   */
  it('says why a credential that authenticated still reaches nothing here', () => {
    const note = 'this credential reaches nothing here';
    const session = build({ whoami: [refusal(403, note)] });

    session.probe();
    expect(session.signedIn()).toBeFalse();
    expect(session.unusable()).toBe(note);
  });

  /**
   * A platform administrator administers fleets and is refused by every route that reaches a fleet's
   * hosts or jobs. They sign in with an address and a password like anybody else and get a different
   * interface, and this flag is what the shell reads to decide which — so a tenant of null must never
   * be mistaken for "not signed in".
   */
  it('recognises the credential that administers fleets rather than acting in one', () => {
    const platform: Whoami = {
      subject: 'admin@example.org',
      display: 'The Administrator',
      provider: 'local-account',
      principal: 'local-account:admin@example.org',
      platform: true,
      tenant: null,
    };
    const session = build({ whoami: [of(platform)] });

    session.probe();
    expect(session.signedIn()).withContext('a platform credential is signed in').toBeTrue();
    expect(session.isPlatform()).toBeTrue();
    expect(session.identity()?.tenant).toBeNull();
    expect(session.unusable()).withContext('nothing is wrong with it').toBe('');
  });

  /**
   * Signing out settles rather than reopening the question. Clearing the identity without settling
   * `ready` would put the shell back into its checking state, which renders a progress bar — so an
   * operator who pressed sign out would watch a spinner instead of the form they expected.
   */
  it('settles into signed out rather than back into checking', () => {
    const session = build({ whoami: [of(whoami())] });

    session.probe();
    expect(session.signedIn()).toBeTrue();

    session.signOut();
    expect(session.signedIn()).toBeFalse();
    expect(session.ready()).withContext('signing out is an answer, not a question').toBeTrue();
  });

  /**
   * "Sign out everywhere" has already ended every session including this one, so the browser's
   * credential has stopped working before the page hears back. forget() is how the application catches
   * up without a second request — one that would have nothing to delete and whose failure would look
   * like the sign-out having failed.
   */
  it('can forget who it was without asking the control plane', () => {
    const session = build({ whoami: [of(whoami())] });

    session.probe();
    expect(session.signedIn()).toBeTrue();

    session.forget();
    expect(session.signedIn()).toBeFalse();
    expect(session.ready()).toBeTrue();
  });

  /**
   * The identity comes from `whoami` after a sign-in rather than from the sign-in response, because
   * only `whoami` names the fleet — and the toolbar cannot render "which fleet am I in" without it.
   */
  it('asks who it is after signing in with an address and a password', () => {
    const session = build({ whoami: [of(whoami())], signIn: of({}) });

    session.signIn('alice@example.org', 'a password long enough');
    expect(session.signedIn()).toBeTrue();
    expect(session.identity()?.tenant?.displayName).toBe('Alpha');
    expect(session.working()).toBeFalse();
  });

  /**
   * A refused sign-in leaves the form usable and says why. It must not settle into "signed out with no
   * explanation", which is what a caller that only cleared the identity would produce.
   */
  it('reports a refused sign-in without signing anybody in', () => {
    const session = build({
      whoami: [refusal(401, 'nope')],
      signIn: refusal(401, 'that address and password do not match an account'),
    });

    session.signIn('alice@example.org', 'the wrong password');
    expect(session.signedIn()).toBeFalse();
    expect(session.error()).not.toBe('');
    expect(session.working()).toBeFalse();
  });
});
