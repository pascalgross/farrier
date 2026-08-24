import { ComponentFixture, TestBed } from '@angular/core/testing';
import { WritableSignal, provideZonelessChangeDetection, signal } from '@angular/core';
import { provideRouter } from '@angular/router';

import { EventStream } from '../core/event-stream';
import { FleetEvent } from '../core/api.models';
import { ToastStack } from './toast-stack';

/** The ids the component asked the feed to dismiss, which is the only call it is allowed to make. */
const dismissed: string[] = [];

/** The toasts on screen, writable so a spec can put an event in front of the component. */
let toasts: WritableSignal<FleetEvent[]>;

/** Builds one event as the live stream delivers it. */
function event(partial: Partial<FleetEvent>): FleetEvent {
  return {
    id: 'e-1',
    kind: 'job.failed',
    hostId: 'h-1',
    hostname: 'web-1',
    summary: 'web-1: updates.apply did not finish',
    at: '2026-08-22T12:00:00Z',
    ...partial,
  };
}

/** Renders the stack over a stubbed feed, so the specs are about the markup and nothing else. */
function render(shown: FleetEvent[]): ComponentFixture<ToastStack> {
  toasts = signal(shown);
  dismissed.length = 0;
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      provideRouter([]),
      {
        provide: EventStream,
        useValue: {
          toasts,
          dismissToast: (id: string) => dismissed.push(id),
        } as unknown as EventStream,
      },
    ],
  });
  const fixture = TestBed.createComponent(ToastStack);
  fixture.detectChanges();
  return fixture;
}

describe('ToastStack', () => {
  /**
   * The constraint issue #4 states, pinned rather than remembered: **a notification is never
   * actionable**. No approve-from-toast and no retry-from-toast — anything that changes state goes
   * through the admin API with its normal authentication, and a destructive job still needs an
   * offline signature this control plane cannot produce and a second person to release it.
   *
   * The spec walks everything interactive the component renders rather than looking for the buttons
   * it knows about, because the failure it guards against is somebody adding a control, not somebody
   * changing one. A toast may carry a link to a host or to the inbox and a dismissal; anything else
   * fails here.
   */
  it('renders nothing actionable: one dismissal, and links that only navigate', () => {
    const fixture = render([
      event({ id: 'e-1' }),
      event({ id: 'e-2', kind: 'job.expired', hostId: undefined, hostname: undefined }),
    ]);

    const interactive = Array.from(
      fixture.nativeElement.querySelectorAll(
        'a, button, input, select, textarea, [role="button"], [role="link"], [role="menuitem"]',
      ),
    ) as HTMLElement[];
    expect(interactive.length).toBeGreaterThan(0);

    for (const element of interactive) {
      if (element.tagName === 'A') {
        // A link may navigate to a host page or to the inbox, and may not be anything else — an
        // href that posted, or that carried a job id into an action route, would fail here.
        expect(element.getAttribute('href')).toMatch(/^\/(hosts\/[^/]+|events)$/);
        continue;
      }
      expect(element.tagName).toBe('BUTTON');
      expect(element.getAttribute('aria-label') ?? '').toContain('Dismiss');
    }
  });

  /** An event with no host still points somewhere: the inbox, which is where the record is. */
  it('links a fleet-wide event to the inbox rather than nowhere', () => {
    const fixture = render([
      event({ id: 'e-2', kind: 'job.expired', hostId: undefined, hostname: undefined }),
    ]);

    const link = fixture.nativeElement.querySelector('a') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/events');
  });

  /** Dismissal is the feed's business: the stack owns no copy of the list it renders. */
  it('asks the feed to dismiss rather than editing what it renders', () => {
    const fixture = render([event({ id: 'e-9' })]);

    (fixture.nativeElement.querySelector('button') as HTMLButtonElement).click();

    expect(dismissed).toEqual(['e-9']);
    expect(toasts().length).toBe(1);
  });

  /**
   * The toast is the one element that draws itself over somebody else's page, so it has to be
   * legible on whichever page that is. It takes its colours from the theme's own tokens, which
   * resolve through `color-scheme: light dark` — so a mistyped token name would not fail the build
   * or the linter, it would just paint an invisible notification in one of the two themes.
   */
  it('paints itself from tokens that resolve, rather than from a name nothing defines', () => {
    const fixture = render([event({ id: 'e-1' })]);

    const toast = fixture.nativeElement.querySelector('.farrier-toast') as HTMLElement;
    const painted = getComputedStyle(toast);

    expect(painted.backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
    expect(painted.backgroundColor).not.toBe('');
    expect(painted.color).not.toBe('');
    expect(painted.backgroundColor).not.toBe(painted.color);
  });

  /** The summary is the whole message: an operator must be able to tell what happened without a click. */
  it('shows the event summary and the kind it belongs to', () => {
    const fixture = render([event({ id: 'e-1' })]);

    const rendered = (fixture.nativeElement.textContent ?? '').replace(/\s+/g, ' ');
    expect(rendered).toContain('web-1: updates.apply did not finish');
    expect(rendered).toContain('Job failed');
  });
});
