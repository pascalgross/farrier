import { Injectable, signal } from '@angular/core';

/** Where the operator's token is kept between page loads. */
const STORAGE_KEY = 'farrier.adminToken';

/**
 * Holds the operator's bearer token for the administrative API.
 *
 * Phase 0 authenticates operators with a single bearer token, because the first thing anybody does with
 * a new control plane is start it, and requiring an identity provider to be configured before the fleet
 * list renders is exactly the friction that makes people close the tab. `auth.Provider` on the server
 * is the seam through which OIDC and SAML arrive; when they do, this service is what changes here.
 *
 * The token is kept in `localStorage` rather than memory so a reload does not log the operator out. That
 * is a deliberate trade and worth naming: it is readable by any script running on this origin, which is
 * acceptable only because the control plane serves nothing but its own bundle from it. It would not be
 * acceptable for a page that embedded third-party scripts.
 */
@Injectable({ providedIn: 'root' })
export class TokenStore {
  /** The current token, as a signal so templates re-render when it is set or cleared. */
  private readonly current = signal(readStoredToken());

  /** Returns the current token, or an empty string when none is set. */
  token(): string {
    return this.current();
  }

  /** Reports whether a token has been entered. */
  hasToken(): boolean {
    return this.current().length > 0;
  }

  /** Stores a token and remembers it across reloads. */
  set(token: string): void {
    const trimmed = token.trim();
    this.current.set(trimmed);
    try {
      localStorage.setItem(STORAGE_KEY, trimmed);
    } catch {
      // Private browsing and hardened configurations refuse storage. Losing persistence is a smaller
      // problem than a page that will not render, so the in-memory value stands on its own.
    }
  }

  /** Forgets the token. */
  clear(): void {
    this.current.set('');
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // As above: an unavailable store is not worth failing over.
    }
  }
}

/**
 * Reads the stored token, tolerating a storage API that refuses to answer.
 *
 * It is a module function rather than a method because it runs during field initialisation, before the
 * instance exists.
 */
function readStoredToken(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}
