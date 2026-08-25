import { Injectable, signal } from '@angular/core';

/** Where the operator's token is kept between page loads. */
const STORAGE_KEY = 'farrier.adminToken';

/**
 * Holds the operator's bearer token for the administrative API.
 *
 * It is no longer how an operator usually signs in — an account and a session cookie are, and
 * `SessionStore` is where that lives — but the token has not gone anywhere and should not. It is the
 * credential a fresh control plane prints before anybody has an account, it is what a script uses, and
 * it is still the whole of the platform credential that administers fleets. Removing it would put a
 * database write between `docker compose up` and the fleet list.
 *
 * The token is kept in `localStorage` rather than memory so a reload does not log the operator out. That
 * is a deliberate trade and worth naming: it is readable by any script running on this origin, which is
 * acceptable only because the control plane serves nothing but its own bundle from it. It would not be
 * acceptable for a page that embedded third-party scripts — and it is precisely the trade a session
 * cookie does not make, which is the reason to prefer an account where there is one.
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
