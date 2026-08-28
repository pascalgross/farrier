import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { of } from 'rxjs';

import { ApiService } from '../core/api.service';
import { EnrolmentInstructions } from '../core/api.models';
import { EnrolPanel } from './enrol-panel';

/** Builds one answer from the control plane, so each spec names only the part it is about. */
function instructions(partial: Partial<EnrolmentInstructions> = {}): EnrolmentInstructions {
  return {
    agentUrl: 'https://agents.example.org',
    agentUrlIsAGuess: false,
    caCertificatePath: '/api/v1/ca.crt',
    aptUrl: 'https://farrier.tools/apt',
    ...partial,
  };
}

/**
 * The three protected members these specs reach for, named so the casts below stay readable.
 *
 * Protected rather than public because they are the template's to call, and a spec that drives the
 * panel the way the markup does has to say so out loud rather than widen the component's surface.
 */
interface PanelInternals {
  /** Reads the instructions, which the disclosure element does on open. */
  load(): void;

  /** Mints one enrolment token. */
  mint(): void;
}

/**
 * Renders the panel with the control plane stubbed out, already opened.
 *
 * The module is reset first so that one spec can render twice — the pair of assertions about a guessed
 * address is one property, and splitting it into two specs would let either half pass alone while the
 * panel said the same thing in both cases.
 */
function render(details: EnrolmentInstructions): ComponentFixture<EnrolPanel> {
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          enrolment: () => of(details),
          createEnrolmentToken: () =>
            of({
              token: 'frr-enrol-abcdef',
              label: 'from the fleet page',
              group: '',
              expiresAt: '2026-08-29T00:00:00Z',
            }),
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(EnrolPanel);
  fixture.detectChanges();
  (fixture.componentInstance as unknown as PanelInternals).load();
  fixture.detectChanges();
  return fixture;
}

/** Collapses whitespace, so an assertion can be written the way the panel actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

describe('EnrolPanel', () => {
  /**
   * The commands carry the address agents actually use, not a placeholder and not the browser's.
   *
   * This is the whole reason the panel reads the address from the control plane rather than assembling
   * it here. The fleet page used to print the literal string `https://this-control-plane`, which every
   * operator replaced by hand with a value the page already knew — and the documented Traefik
   * deployment serves this page on a hostname where the agent API answers 403, so the browser's own
   * address is not a safe substitute either.
   */
  it('builds every command from the configured agent address', () => {
    const rendered = text(render(instructions()).nativeElement);

    expect(rendered).toContain('sudo farrier enroll --server https://agents.example.org');
    expect(rendered).toContain('https://agents.example.org/api/v1/ca.crt');
    expect(rendered).toContain('https://farrier.tools/apt/farrier.sources');
    expect(rendered).not.toContain('this-control-plane');
  });

  /**
   * When nobody configured the address, the panel says the commands may be wrong.
   *
   * A guess is right for the ordinary single-hostname deployment and wrong for the two-hostname one,
   * and the interface cannot tell which it is in. Saying so is what stops the failure being discovered
   * after an agent has been installed on a machine and cannot enrol — which reads as a broken control
   * plane rather than as a missing setting.
   */
  it('says so when the agent address is a guess', () => {
    const guessed = text(
      render(instructions({ agentUrl: 'https://farrier.example.org', agentUrlIsAGuess: true })).nativeElement,
    );
    expect(guessed).toContain('FARRIER_AGENT_URL');

    const configured = text(render(instructions()).nativeElement);
    expect(configured).not.toContain('FARRIER_AGENT_URL');
  });

  /**
   * The token is in the command once it exists, and the panel says it is shown once.
   *
   * Only the SHA-256 is stored, so a token nobody copied is not recoverable. That has to be said at
   * the moment it is on screen rather than in a footnote, because the alternative is an operator who
   * closes the panel expecting to come back for it.
   */
  it('puts a minted token into the command and says it cannot be shown again', () => {
    const fixture = render(instructions());

    expect(text(fixture.nativeElement)).toContain('--token <TOKEN>');

    (fixture.componentInstance as unknown as PanelInternals).mint();
    fixture.detectChanges();

    const rendered = text(fixture.nativeElement);
    expect(rendered).toContain('--token frr-enrol-abcdef');
    expect(rendered).toContain('cannot be shown again');
  });

  /**
   * The certificate is installed by reading it from the control plane, not by hand.
   *
   * A step that spans two machines is the step people improvise around, and the improvisation here is
   * a host that verifies the control plane against the system roots instead of this authority — which
   * works, until the day it matters. The mode and owner are in the command for the same reason: a file
   * the agent cannot read fails enrolment in a way that names neither.
   */
  it('installs the CA certificate with an explicit owner and mode', () => {
    const rendered = text(render(instructions()).nativeElement);
    expect(rendered).toContain('/etc/farrier/server-ca.crt');
    expect(rendered).toContain('-o root -g root -m 0644');
  });
});
