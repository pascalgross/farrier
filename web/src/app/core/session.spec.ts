import { TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';

import { ApiService } from './api.service';
import { SessionStore } from './session';
import { TokenStore } from './token-store';
import { Whoami } from './api.models';

/** One identity the control plane can answer `whoami` with. */
function whoami(): Whoami {
  return {
    subject: 'alice@example.org',
    display: 'Alice',
    provider: 'local-account',
    principal: 'local-account:alice@example.org',
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

/** The store and the token it shares a browser with, which is what every spec below drives. */
interface Fixture {
  /** The store under test. */
  session: SessionStore;

  /** The bearer token store, so a spec can see whether a refused token was kept. */
  tokens: TokenStore;
}

/** Builds the store over a fake control plane. */
function build(answers: Answers): Fixture {
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
  const tokens = TestBed.inject(TokenStore);
  tokens.clear();
  return { session: TestBed.inject(SessionStore), tokens };
}

describe('SessionStore', () => {
  /**
   * The credential is an HttpOnly cookie, so the application cannot look at it — the only way to know
   * whether somebody is signed in is to ask. That makes "not yet answered" a third state, and a shell
   * that treated it as "signed out" would flash the sign-in form at everybody on every reload.
   */
  it('does not claim to know anything until the control plane has answered', () => {
    const { session } = build({ whoami: [of(whoami())] });

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
    const { session } = build({ whoami: [refusal(401, 'a valid operator credential is required')] });

    session.probe();
    expect(session.signedIn()).toBeFalse();
    expect(session.ready()).toBeTrue();
    expect(session.error()).toBe('');
    expect(session.unusable()).toBe('');
  });

  /**
   * The platform credential administers fleets and reaches no fleet's hosts, so pasting it into the
   * sign-in box authenticates and then reaches nothing. The control plane's 403 says exactly that, and
   * showing it beats "wrong password" — which would send somebody to check what they typed rather
   * than to find their other token.
   */
  it('says why a credential that authenticated still reaches nothing here', () => {
    const note = 'this is a platform credential, which administers tenants and reaches no tenant’s hosts';
    const { session } = build({ whoami: [refusal(403, note)] });

    session.probe();
    expect(session.signedIn()).toBeFalse();
    expect(session.unusable()).toBe(note);
  });

  /**
   * A token that does not work must not be kept. Left in `localStorage` it is attached to every later
   * request, and the next reload retries it silently — so the operator sees a sign-in form that
   * refuses them for a reason that is no longer on screen.
   */
  it('forgets a bearer token the control plane refused', () => {
    const { session, tokens } = build({ whoami: [refusal(401, 'nope')] });

    session.useToken('a-token-that-does-not-work');
    expect(tokens.hasToken()).toBeFalse();
    expect(session.signedIn()).toBeFalse();
    expect(session.error()).not.toBe('');
  });

  /**
   * Signing out has to end both credentials. Keeping either one would bring the operator back signed
   * in on the next reload, for a reason nothing on the page could explain.
   */
  it('clears the token as well as the session when signing out', () => {
    const { session, tokens } = build({ whoami: [of(whoami())] });

    session.useToken('a-token-that-works');
    expect(tokens.hasToken()).toBeTrue();
    expect(session.signedIn()).toBeTrue();

    session.signOut();
    expect(tokens.hasToken()).toBeFalse();
    expect(session.signedIn()).toBeFalse();
    expect(session.ready()).withContext('signing out is an answer, not a question').toBeTrue();
  });

  /**
   * The identity comes from `whoami` after a sign-in rather than from the sign-in response, because
   * only `whoami` names the fleet — and the toolbar cannot render "which fleet am I in" without it.
   */
  it('asks who it is after signing in with an address and a password', () => {
    const { session } = build({ whoami: [of(whoami())], signIn: of({}) });

    session.signIn('alice@example.org', 'a password long enough');
    expect(session.signedIn()).toBeTrue();
    expect(session.identity()?.tenant.displayName).toBe('Alpha');
    expect(session.working()).toBeFalse();
  });

  /**
   * A refused sign-in leaves the form usable and says why. It must not settle into "signed out with no
   * explanation", which is what a caller that only cleared the identity would produce.
   */
  it('reports a refused sign-in without signing anybody in', () => {
    const { session } = build({
      whoami: [refusal(401, 'nope')],
      signIn: refusal(401, 'that address and password do not match an account'),
    });

    session.signIn('alice@example.org', 'the wrong password');
    expect(session.signedIn()).toBeFalse();
    expect(session.error()).not.toBe('');
    expect(session.working()).toBeFalse();
  });
});
