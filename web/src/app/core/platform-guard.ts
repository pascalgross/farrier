import { CanMatchFn, Router, UrlTree } from '@angular/router';
import { inject } from '@angular/core';

import { SessionStore } from './session';

/**
 * Keeps a platform administrator out of the routes that would answer them 403.
 *
 * The two credentials reach disjoint sets of routes by design: a platform administrator administers
 * fleets and is refused by every route that reaches a fleet's hosts or jobs. Landing on one of those
 * pages renders a console full of refusals rather than an interface, which is the failure
 * [#68](https://github.com/pascalgross/farrier/issues/68) was about in the first place.
 *
 * A guard rather than an `effect` in the shell, and that is a correction rather than a preference. The
 * shell's effect read `Router.url`, which is a plain property and not a signal — so it re-ran when the
 * identity changed and never again. Every later navigation was unguarded, and the always-visible logo
 * links to `/`: one click put a platform administrator on the fleet page and left them there. A guard
 * is asked on every navigation by construction, which is the property the effect only appeared to have.
 *
 * `CanMatch` rather than `CanActivate` so the lazy chunk is not fetched before the answer is known.
 * There is no reason to download the fleet page to decide not to show it.
 */
export const notPlatform: CanMatchFn = (): boolean | UrlTree => {
  const session = inject(SessionStore);
  const router = inject(Router);

  // Not signed in, or not yet answered: let the route match. The shell renders the sign-in form over
  // the top of whatever matched, so there is nothing to protect here — and redirecting on an unknown
  // identity would send somebody to /fleets while the first probe was still in flight.
  if (!session.signedIn() || !session.isPlatform()) {
    return true;
  }
  return router.parseUrl('/fleets');
};

/**
 * The mirror image: keeps a fleet's operator out of the fleets screen.
 *
 * Written for the same reason and not merely for symmetry. `/api/v1/tenants` refuses an operator
 * exactly as the fleet routes refuse a platform administrator, so an operator who types `/fleets` or
 * follows a link to it gets a page of 403s. There was no redirect in the other direction at all.
 */
export const notOperator: CanMatchFn = (): boolean | UrlTree => {
  const session = inject(SessionStore);
  const router = inject(Router);

  if (!session.signedIn() || session.isPlatform()) {
    return true;
  }
  return router.parseUrl('/');
};
