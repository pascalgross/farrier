import { Router, UrlTree } from '@angular/router';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideZonelessChangeDetection, runInInjectionContext, Injector } from '@angular/core';
import { of, throwError } from 'rxjs';

import { ApiService } from './api.service';
import { SessionStore } from './session';
import { Whoami } from './api.models';
import { notOperator, notPlatform } from './platform-guard';

/** One identity the control plane can answer `whoami` with. */
function whoami(platform: boolean): Whoami {
  return {
    subject: platform ? 'admin@example.org' : 'alice@example.org',
    display: platform ? 'The Administrator' : 'Alice',
    provider: 'local-account',
    principal: `local-account:${platform ? 'admin' : 'alice'}@example.org`,
    platform,
    tenant: platform
      ? null
      : {
          id: 'tenant-alpha',
          slug: 'alpha',
          displayName: 'Alpha',
          createdAt: '2026-01-01T00:00:00Z',
          approvalMode: 'none',
          webhookUrl: '',
        },
  };
}

/** How the fake control plane should answer `whoami` for one spec. */
type Answer = 'platform' | 'operator' | 'nobody';

/** The injector the guards run in, and the session they read. */
interface Harness {
  /** The injection context a CanMatchFn needs, because it calls inject(). */
  injector: Injector;

  /** The store the guards ask, already probed. */
  session: SessionStore;
}

/** Builds an injector holding a session that has already answered. */
function build(answer: Answer): Harness {
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      provideRouter([]),
      {
        provide: ApiService,
        useValue: {
          whoami: () =>
            answer === 'nobody'
              ? throwError(() => ({ status: 401, error: { message: 'nope' } }))
              : of(whoami(answer === 'platform')),
        } as unknown as ApiService,
      },
    ],
  });
  const session = TestBed.inject(SessionStore);
  session.probe();
  return { injector: TestBed.inject(Injector), session };
}

/** Runs a guard the way the router would, and reports where it sent us. */
function run(h: Harness, guard: typeof notPlatform): true | string {
  const verdict = runInInjectionContext(h.injector, () =>
    (guard as unknown as () => boolean | UrlTree)(),
  );
  if (verdict === true) {
    return true;
  }
  return TestBed.inject(Router).serializeUrl(verdict as UrlTree);
}

describe('platform-guard', () => {
  /**
   * The bug this replaced: the shell decided with an `effect` that read `Router.url`, which is a plain
   * property and not a signal — so it ran once, when the identity arrived, and on no later navigation.
   * A guard is asked on every navigation by construction, which is the property the effect only looked
   * like it had.
   */
  it('turns a platform administrator away from an operator route', () => {
    const h = build('platform');
    expect(h.session.isPlatform()).withContext('the fixture is signed in as one').toBeTrue();
    expect(run(h, notPlatform)).toBe('/fleets');
  });

  /** The same route, for the credential it is actually for. */
  it('lets an operator through to an operator route', () => {
    expect(run(build('operator'), notPlatform)).toBeTrue();
  });

  /**
   * The other direction, which had no redirect at all before. `/api/v1/tenants` refuses an operator
   * exactly as the fleet routes refuse a platform administrator, so an operator who follows a link to
   * /fleets got a page of 403s.
   */
  it('turns an operator away from the fleets screen', () => {
    expect(run(build('operator'), notOperator)).toBe('/');
  });

  /** And lets the administrator into the one screen they exist for. */
  it('lets a platform administrator through to the fleets screen', () => {
    expect(run(build('platform'), notOperator)).toBeTrue();
  });

  /**
   * Nobody signed in: every route matches, because the shell renders the sign-in form over the top of
   * whatever matched and there is nothing yet to protect. Redirecting here would send somebody to
   * /fleets while the first probe was still in flight, and they would land there after signing in.
   */
  it('does not redirect a browser that has not signed in', () => {
    const h = build('nobody');
    expect(run(h, notPlatform)).toBeTrue();
    expect(run(h, notOperator)).toBeTrue();
  });
});
