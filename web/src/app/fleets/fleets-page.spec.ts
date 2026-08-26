import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { of, throwError } from 'rxjs';

import { ApiService } from '../core/api.service';
import { FleetsPage } from './fleets-page';
import { Tenant } from '../core/api.models';

/** Builds one fleet, so each spec names only the part it is about. */
function fleet(partial: Partial<Tenant>): Tenant {
  return {
    id: '01JALPHA',
    slug: 'alpha',
    displayName: 'Alpha',
    createdAt: '2026-01-01T00:00:00Z',
    approvalMode: 'none',
    webhookUrl: '',
    ...partial,
  };
}

/** Collapses whitespace, so an assertion can be written the way the page actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

/** What the fake control plane did, so a spec can assert on the request rather than only the render. */
interface Recorded {
  /** The create requests the page made. */
  created: unknown[];

  /** The patches the page made, as (id, body) pairs. */
  patched: [string, unknown][];
}

/** The page, and the record of what it asked the control plane to do. */
interface Rendered {
  /** The fixture, for reading the DOM and driving change detection. */
  fixture: ComponentFixture<FleetsPage>;

  /** What the page asked for. */
  recorded: Recorded;
}

/** Renders the page against one fixed answer, with the control plane stubbed out. */
function render(fleets: Tenant[] | 'fails'): Rendered {
  const recorded: Recorded = { created: [], patched: [] };
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          tenants: () =>
            fleets === 'fails'
              ? throwError(() => new Error('the control plane is down'))
              : of({ tenants: fleets }),
          createTenant: (request: unknown) => {
            recorded.created.push(request);
            return of(fleet({}));
          },
          updateTenant: (id: string, request: unknown) => {
            recorded.patched.push([id, request]);
            return of(fleet({}));
          },
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(FleetsPage);
  fixture.detectChanges();
  return { fixture, recorded };
}

/** The writable half of the slug signal, which is all these specs need of it. */
interface SlugSignal {
  /** Sets the slug the form holds. */
  set(value: string): void;
}

/**
 * The three protected members these specs reach for, named so the casts below stay readable.
 *
 * Protected rather than public because they are the template's to call, and a spec that drives the
 * page the way the markup does has to say so out loud rather than widen the component's surface.
 */
interface PageInternals {
  /** Creates a fleet from whatever is on the form. */
  create(): void;

  /** Changes one fleet's approval mode. */
  setApproval(target: Tenant, mode: string): void;

  /** The slug being typed, which the form binds to. */
  newSlug: SlugSignal;
}

describe('FleetsPage', () => {
  /**
   * The page exists because creating a fleet leaves somebody with a fleet nobody can enter, and the
   * step that fixes it is a command on the control plane rather than a button here — there is no route
   * that could mint a credential, deliberately. Saying so at the moment it matters is most of what this
   * screen adds over the `curl` in INSTALL.md, so it is worth a test.
   */
  it('names the command that gives a new fleet its first operator', () => {
    const { fixture } = render([]);

    (fixture.componentInstance as unknown as PageInternals).newSlug.set('acme');
    (fixture.componentInstance as unknown as PageInternals).create();
    fixture.detectChanges();

    const shown = text(fixture.nativeElement);
    expect(shown).toContain('farrier-server accounts add --tenant acme');
    expect(shown).toContain('Nobody can sign in to it yet');
  });

  /**
   * A patch of exactly the field that changed, never the whole record. The API distinguishes "not
   * sent" from "sent empty", so writing a whole tenant back would clear a webhook somebody had set
   * from a form that never showed it to them.
   */
  it('changes one setting at a time', () => {
    const { fixture, recorded } = render([
      fleet({ id: '01JACME', slug: 'acme', webhookUrl: 'https://hooks.example.org/acme' }),
    ]);

    (fixture.componentInstance as unknown as PageInternals).setApproval(
      fleet({ id: '01JACME' }),
      'second_person',
    );

    expect(recorded.patched).toEqual([['01JACME', { approvalMode: 'second_person' }]]);
  });

  /**
   * The three approval modes are the one setting on this page an operator gets wrong by not knowing
   * what it means, so the page explains the one they are looking at rather than linking to a document.
   */
  it('explains the approval mode that is selected', () => {
    const { fixture } = render([]);

    expect(text(fixture.nativeElement)).toContain('The offline signature is the whole of');
  });

  /**
   * A fleet that has been created must appear with its slug, because the slug is what every later
   * command — the account one above included — refers to it by.
   */
  it('lists each fleet by name and by slug', () => {
    const { fixture } = render([
      fleet({ id: '01JACME', slug: 'acme', displayName: 'Acme Ltd', approvalMode: 'second_person' }),
    ]);

    const shown = text(fixture.nativeElement);
    expect(shown).toContain('Acme Ltd');
    expect(shown).toContain('acme');
    expect(shown).toContain('A second person must release it');
  });
});
