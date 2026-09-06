import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { ApiService } from '../core/api.service';
import { FailedServiceHost, FailedServicesResponse, UnitState } from '../core/api.models';
import { ServicesPage } from './services-page';

/** Builds one row of the answer, so each spec names only the part of a host it is about. */
function host(partial: Partial<FailedServiceHost>): FailedServiceHost {
  return {
    hostId: 'h-1',
    hostname: 'web-1',
    online: true,
    failed: [],
    servicesTruncated: false,
    factsUnknown: false,
    ...partial,
  };
}

/** Builds one failed unit as the control plane reports it, load state included. */
function unit(name: string, loadState = 'loaded', subState = 'exited'): UnitState {
  return { name, loadState, activeState: 'failed', subState };
}

/** Renders the page against one fixed answer, with the control plane stubbed out. */
function render(response: FailedServicesResponse): ComponentFixture<ServicesPage> {
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      provideRouter([]),
      {
        provide: ApiService,
        useValue: { failedServices: () => of(response) } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(ServicesPage);
  fixture.detectChanges();
  return fixture;
}

/** Collapses whitespace, so an assertion can be written the way the header actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

describe('ServicesPage counts', () => {
  /**
   * The list holds every host worth listing, which is not the same set as the hosts with a failure:
   * a truncated unit list puts a host here too. Counting the list as failing hosts made a fleet with
   * one failure and five truncations read "1 failed on 6 of 300 hosts" — a number that overstates
   * the fleet's trouble is read once and then discounted for ever.
   */
  it('counts the hosts that are failing, not every host in the list', () => {
    const fixture = render({
      hosts: [
        host({ hostId: 'a', hostname: 'web-1', failed: [unit('nginx.service')] }),
        host({ hostId: 'b', hostname: 'big-1', servicesTruncated: true }),
        host({ hostId: 'c', hostname: 'big-2', servicesTruncated: true }),
        host({ hostId: 'd', hostname: 'big-3', servicesTruncated: true }),
        host({ hostId: 'e', hostname: 'big-4', servicesTruncated: true }),
        host({ hostId: 'f', hostname: 'big-5', servicesTruncated: true }),
      ],
      total: 300,
      serverTime: '2026-08-22T12:00:00Z',
    });

    const header = text(fixture.nativeElement.querySelector('header'));
    expect(header).toContain('1 failed on 1 of 300 hosts');
    expect(header).toContain('5 with a truncated unit list');
  });

  /**
   * A host nothing is known about is a third answer beside clean and failing, and it gets its own
   * number. Folding it into the failing count would claim a failure the host never reported; leaving
   * it out of the header entirely would be the silent unknown the truncation flag exists to prevent.
   */
  it('counts a host with no readable facts as its own thing and never as a failure', () => {
    const fixture = render({
      hosts: [
        host({ hostId: 'a', hostname: 'quiet-1', factsUnknown: true }),
        host({ hostId: 'b', hostname: 'quiet-2', factsUnknown: true }),
      ],
      total: 300,
      serverTime: '2026-08-22T12:00:00Z',
    });

    const header = text(fixture.nativeElement.querySelector('header'));
    expect(header).toContain('Nothing failed across 300 hosts');
    expect(header).toContain('2 with nothing reported');
    expect(text(fixture.nativeElement)).toContain('Nothing is known about this host');
  });

  /** Every failed unit counts, wherever it is, or the headline number is not the fleet's. */
  it('sums failed units across hosts', () => {
    const fixture = render({
      hosts: [
        host({ hostId: 'a', failed: [unit('nginx.service'), unit('cron.service')] }),
        host({ hostId: 'b', failed: [unit('ssh.service')] }),
      ],
      total: 12,
      serverTime: '2026-08-22T12:00:00Z',
    });

    expect(text(fixture.nativeElement.querySelector('header'))).toContain(
      '3 failed on 2 of 12 hosts',
    );
  });
});

describe('ServicesPage unit states', () => {
  /**
   * `loadState` reaches the browser and used to die in a tooltip. A masked unit is a decision
   * somebody took and a crashed unit is a fault; painting the two the same red is what teaches an
   * operator to stop reading the colour.
   */
  it('paints a masked unit differently from a crashed one', () => {
    const fixture = render({
      hosts: [
        host({
          hostId: 'a',
          failed: [unit('nginx.service', 'masked', 'dead'), unit('cron.service')],
        }),
      ],
      total: 1,
      serverTime: '2026-08-22T12:00:00Z',
    });

    // Matched on the unit name rather than on the whole chip: a Material icon renders its ligature
    // as text, so every chip's text begins with the name of its own icon.
    const chips = Array.from(fixture.nativeElement.querySelectorAll('mat-chip')) as Element[];
    const masked = chips.find((chip) => text(chip).includes('nginx.service'));
    const crashed = chips.find((chip) => text(chip).includes('cron.service'));

    expect(text(masked ?? null)).toContain('masked');
    expect(masked?.querySelector('.text-hostseal-warn')).not.toBeNull();
    expect(masked?.querySelector('.text-hostseal-bad')).toBeNull();
    expect(crashed?.querySelector('.text-hostseal-bad')).not.toBeNull();
  });
});
