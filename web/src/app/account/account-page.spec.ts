import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';

import { Account, ApiToken, OperatorSession } from '../core/api.models';
import { AccountPage } from './account-page';
import { ApiService } from '../core/api.service';
import { SessionStore } from '../core/session';

/** The account every spec below signs in as, unless it names something different. */
function account(partial: Partial<Account> = {}): Account {
  return {
    email: 'alice@example.org',
    displayName: 'Alice',
    createdAt: '2026-01-01T00:00:00Z',
    lastSignedIn: '2026-08-25T09:00:00Z',
    platform: false,
    principal: 'local-account:alice@example.org',
    ...partial,
  };
}

/** One session, so each spec names only the part it is about. */
function browserSession(partial: Partial<OperatorSession> = {}): OperatorSession {
  return {
    createdAt: '2026-08-25T09:00:00Z',
    expiresAt: '2026-08-25T21:00:00Z',
    lastUsed: '2026-08-25T12:00:00Z',
    userAgent: 'Mozilla/5.0 (Macintosh)',
    source: '203.0.113.7',
    expired: false,
    current: false,
    ...partial,
  };
}

/** One API token, likewise. */
function apiToken(partial: Partial<ApiToken> = {}): ApiToken {
  return {
    id: 'a'.repeat(64),
    label: 'deployment pipeline',
    createdAt: '2026-08-01T00:00:00Z',
    expiresAt: null,
    lastUsed: null,
    usable: true,
    ...partial,
  };
}

/** Collapses whitespace, so an assertion can be written the way the page actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

/** What the fake control plane was asked to do, so a spec can assert on the request. */
interface Recorded {
  /** The password changes the page asked for. */
  passwords: unknown[];

  /** How many times the page asked to sign out everywhere. */
  revokedSessions: number;

  /** The tokens the page asked to mint. */
  minted: unknown[];

  /** The token ids the page asked to revoke. */
  revokedTokens: string[];
}

/** What each fake ApiService method should answer for one spec. */
interface Answers {
  /** What the sessions listing returns. */
  sessions?: OperatorSession[];

  /** What the token listing returns. */
  tokens?: ApiToken[];

  /** What a password change returns, defaulting to success. */
  changePassword?: Observable<unknown>;

  /** What minting a token returns, defaulting to one that is issued. */
  createApiToken?: Observable<unknown>;
}

/**
 * One of the page's writable signals, reached through the cast below.
 *
 * A named type rather than an inline one because there are four of them and each would otherwise be
 * three lines of structural type repeated at every call site.
 */
interface Field {
  /** Reads the current value. */
  (): string;

  /** Sets it, as the template's ngModelChange does. */
  set(value: string): void;
}

/**
 * The parts of AccountPage a spec drives.
 *
 * They are `protected` on the component, which is right — nothing outside the template calls them —
 * and a spec is the one caller that has to. Naming the surface here rather than casting inline at
 * every use is what keeps the casts from quietly disagreeing about what the page offers.
 */
interface Driver {
  /** The current password being typed. */
  currentPassword: Field;

  /** The replacement being typed. */
  newPassword: Field;

  /** The replacement typed a second time. */
  confirmPassword: Field;

  /** What the new token is to be called. */
  tokenLabel: Field;

  /** Whether the change-password form may be submitted. */
  canChangePassword(): boolean;

  /** What is wrong with the replacement as it stands, empty when nothing is. */
  passwordHint(): string;

  /** Why the change failed, empty when it did not. */
  passwordError(): string;

  /** Submits the change. */
  changePassword(): void;

  /** Whether the token form may be submitted. */
  canMintToken(): boolean;

  /** Mints the token. */
  mintToken(): void;

  /** Ends every session, including this browser's. */
  signOutEverywhere(): void;

  /** Revokes one token. */
  revokeToken(token: ApiToken): void;
}

/** The rendered page, and the record of what it asked for. */
interface Rendered {
  /** The fixture, for reading the DOM and driving change detection. */
  fixture: ComponentFixture<AccountPage>;

  /** The page's own surface, for the specs that drive it rather than click it. */
  page: Driver;

  /** What the page asked the control plane to do. */
  recorded: Recorded;

  /** The session store, so a spec can see whether the page dropped the identity. */
  session: SessionStore;
}

/** Renders the page against fixed answers, with the control plane stubbed out. */
function render(answers: Answers = {}): Rendered {
  const recorded: Recorded = { passwords: [], revokedSessions: 0, minted: [], revokedTokens: [] };
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          account: () => of(account()),
          sessions: () => of({ sessions: answers.sessions ?? [] }),
          apiTokens: () => of({ tokens: answers.tokens ?? [] }),
          changePassword: (request: unknown) => {
            recorded.passwords.push(request);
            return answers.changePassword ?? of({});
          },
          revokeSessions: () => {
            recorded.revokedSessions += 1;
            return of({ ended: 3 });
          },
          createApiToken: (request: unknown) => {
            recorded.minted.push(request);
            return (
              answers.createApiToken ??
              of({
                id: 'b'.repeat(64),
                label: 'deployment pipeline',
                createdAt: '2026-08-25T12:00:00Z',
                expiresAt: null,
                token: 'frr_a-freshly-minted-token',
              })
            );
          },
          revokeApiToken: (id: string) => {
            recorded.revokedTokens.push(id);
            return of({});
          },
          whoami: () => of(account()),
          signOut: () => of({}),
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(AccountPage);
  fixture.detectChanges();
  return {
    fixture,
    page: fixture.componentInstance as unknown as Driver,
    recorded,
    session: TestBed.inject(SessionStore),
  };
}

describe('AccountPage', () => {
  /**
   * The value exists in exactly one place after this response, and that place is the screen. Only its
   * SHA-256 is stored, so a page that showed the label and not the token would have thrown away a
   * credential the operator asked for.
   */
  it('shows a freshly minted token once, in full', async () => {
    const { fixture, page, recorded } = render();
    page.tokenLabel.set('deployment pipeline');
    page.mintToken();
    fixture.detectChanges();
    await fixture.whenStable();

    const secret = fixture.nativeElement.querySelector('.farrier-account__secret');
    expect(text(secret)).toBe('frr_a-freshly-minted-token');
    expect(recorded.minted).toEqual([{ label: 'deployment pipeline', expiresInDays: 90 }]);
  });

  /**
   * A label is required because a list of six tokens called "token" is a list nobody revokes from. The
   * page refuses before the request rather than after it, so nobody learns this from a 400.
   */
  it('will not mint a token with no label', () => {
    const { page, recorded } = render();

    expect(page.canMintToken()).withContext('with an empty label').toBeFalse();
    page.mintToken();
    expect(recorded.minted).toEqual([]);
  });

  /**
   * Two fields that must agree, checked here rather than by the control plane, because a round trip to
   * be told "these do not match" is a round trip nobody needed — and because the server never sees the
   * second field at all.
   */
  it('will not change a password until the two copies agree and it is long enough', () => {
    const { page, recorded } = render();
    page.currentPassword.set('the current password');
    page.newPassword.set('short');
    page.confirmPassword.set('short');
    expect(page.canChangePassword()).withContext('five characters').toBeFalse();
    expect(page.passwordHint()).toContain('12 characters');

    page.newPassword.set('a replacement password');
    page.confirmPassword.set('a replacment password');
    expect(page.canChangePassword()).withContext('a typo in the confirmation').toBeFalse();
    expect(page.passwordHint()).toBe('The two do not match.');

    page.confirmPassword.set('a replacement password');
    expect(page.canChangePassword()).toBeTrue();

    page.changePassword();
    expect(recorded.passwords).toEqual([
      { currentPassword: 'the current password', newPassword: 'a replacement password' },
    ]);
  });

  /**
   * The current password is cleared whether the change worked or not. Leaving a refused one in the box
   * is how somebody submits the same wrong thing three times into a rate limit.
   */
  it('empties the password fields after a refusal', () => {
    const { page } = render({
      changePassword: throwError(() => ({ status: 401, error: { message: 'that is not it' } })),
    });
    page.currentPassword.set('the wrong password');
    page.newPassword.set('a replacement password');
    page.confirmPassword.set('a replacement password');
    page.changePassword();

    expect(page.currentPassword()).toBe('');
    expect(page.newPassword()).toBe('');
    expect(page.passwordError()).not.toBe('');
  });

  /**
   * Signing out everywhere ends this browser's session too, so the application has to stop claiming to
   * be signed in. Calling signOut() instead would make a second request with nothing left to delete,
   * and its failure would look like the sign-out having failed.
   */
  it('drops the identity after signing out everywhere', () => {
    const { page, recorded, session } = render({ sessions: [browserSession({ current: true })] });

    page.signOutEverywhere();
    expect(recorded.revokedSessions).toBe(1);
    expect(session.signedIn()).toBeFalse();
    expect(session.ready()).withContext('signed out is an answer, not a question').toBeTrue();
  });

  /**
   * The session list is what makes "that one is not me" a judgement somebody can make. It has to name
   * the browser and mark the one asking, or it is six rows that all say "a session".
   */
  it('marks the session that is asking and names the others', () => {
    const { fixture } = render({
      sessions: [
        browserSession({ current: true, userAgent: 'Mozilla/5.0 (Macintosh)' }),
        browserSession({ userAgent: 'Mozilla/5.0 (Windows)', source: '198.51.100.4' }),
      ],
    });

    const rows = fixture.nativeElement.querySelectorAll('.farrier-account__row');
    expect(rows.length).toBe(2);
    expect(text(rows[0])).toContain('this browser');
    expect(text(rows[1])).toContain('Mozilla/5.0 (Windows)');
    expect(text(rows[1])).toContain('198.51.100.4');
    expect(text(rows[1])).not.toContain('this browser');
  });

  /**
   * An expired token stays in the list, dimmed. Dropping it silently would make somebody count their
   * tokens wrongly, and a token that has expired is still a fact about this account.
   */
  it('keeps an expired token in the listing rather than hiding it', () => {
    const { fixture, page, recorded } = render({
      tokens: [apiToken({ usable: false, expiresAt: '2026-01-01T00:00:00Z', label: 'old runner' })],
    });

    const rows = fixture.nativeElement.querySelectorAll('.farrier-account__row--muted');
    expect(rows.length).toBe(1);
    expect(text(rows[0])).toContain('old runner');
    expect(text(rows[0])).toContain('expired');

    page.revokeToken(apiToken({ id: 'c'.repeat(64) }));
    expect(recorded.revokedTokens).toEqual(['c'.repeat(64)]);
  });
});
