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
    caFingerprint: 'C0:62:73:A0:FD:3C:25:86:BE:F7:7F:0E:08:66:72:C0:F6:E3:AF:3B:A4:94:FB:2A:D9:BF:CC:1D:C5:8E:15:61',
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

  /** The page's own address, which the CA command is built against. */
  pageBase(): string;
}

/**
 * Renders the panel with the control plane stubbed out, already opened.
 *
 * The module is reset first so that one spec can render twice — the pair of assertions about a guessed
 * address is one property, and splitting it into two specs would let either half pass alone while the
 * panel said the same thing in both cases.
 */
function render(
  details: EnrolmentInstructions,
  pageBase = 'https://farrier.example.org/',
): ComponentFixture<EnrolPanel> {
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
  const panel = fixture.componentInstance as unknown as PanelInternals;
  // The page's own address decides where the certificate is fetched from, and under Karma it is the
  // test runner's. Stubbed rather than asserted around, because the two-hostname and single-hostname
  // deployments differ in exactly this value and both have to be exercised.
  panel.pageBase = () => pageBase;
  fixture.detectChanges();
  panel.load();
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
    expect(rendered).toContain('https://farrier.tools/apt/farrier.sources');
    expect(rendered).not.toContain('this-control-plane');
  });

  /**
   * The certificate is fetched from this page's address, not from the agent hostname.
   *
   * `curl` verifies the control plane like every other client, so it can only fetch the certificate
   * over a connection it can already verify — and the agent hostname's certificate is precisely the
   * one it cannot, because the file being fetched is what would establish it. In the documented
   * two-hostname deployment this page is served where Traefik terminates with a publicly trusted
   * certificate, so pointing the command here is the difference between a command that works and one
   * that fails with `unable to get local issuer certificate` for every operator who copies it.
   */
  it('fetches the certificate from the interface address, not the agent address', () => {
    const rendered = text(render(instructions()).nativeElement);

    expect(rendered).toContain('https://farrier.example.org/api/v1/ca.crt');
    expect(rendered).not.toContain('https://agents.example.org/api/v1/ca.crt');
  });

  /**
   * When one hostname serves both, the panel says the fetch cannot be verified.
   *
   * There is no address to point the command at in that deployment: the only name serving the
   * certificate is the one the certificate would authenticate. Printing a command that always fails
   * and saying nothing is how an operator concludes the control plane is broken, so the panel names
   * the error and the two ways round it instead.
   */
  it('warns when the certificate would be fetched from the name it authenticates', () => {
    const shared = text(
      render(instructions({ agentUrl: 'https://farrier.example.org' }), 'https://farrier.example.org/')
        .nativeElement,
    );
    expect(shared).toContain('unable to get local issuer certificate');

    const split = text(render(instructions()).nativeElement);
    expect(split).not.toContain('unable to get local issuer certificate');
  });

  /**
   * The unverified fetch is never offered without the check that makes it safe.
   *
   * `-k` alone accepts whoever answered the hostname, and what it would accept is the authority every
   * later connection from that host is checked against — so a mistake here is not one bad request, it
   * is a permanently wrong trust anchor. The command therefore carries the fingerprint, compares it in
   * the shell rather than asking a person to compare two 64-character strings by eye, and installs
   * nothing on a mismatch. This asserts the three halves travel together.
   */
  it('pairs an unverified fetch with a fingerprint check that fails closed', () => {
    const rendered = text(
      render(instructions({ agentUrl: 'https://farrier.example.org' }), 'https://farrier.example.org/')
        .nativeElement,
    );

    expect(rendered).toContain('curl -fsSLk');
    expect(rendered).toContain('sha256 Fingerprint=C0:62:73:A0');
    expect(rendered).toContain('FINGERPRINT MISMATCH');
  });

  /**
   * The verifiable deployment gets the plain command, with no -k anywhere near it.
   *
   * A panel that printed `-k` unconditionally would teach the habit it exists to avoid, on the
   * majority deployment where the fetch verifies perfectly well.
   */
  it('does not offer an unverified fetch when the fetch can be verified', () => {
    const rendered = text(render(instructions()).nativeElement);

    expect(rendered).not.toContain('curl -fsSLk');
    expect(rendered).toContain('curl -fsSL https://farrier.example.org/api/v1/ca.crt');
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
  /**
   * A failed install is never reported as a fingerprint mismatch.
   *
   * `test && install || echo` reads correctly and is wrong: the `||` binds to the whole list, so a
   * missing sudo or a full disk prints an attack that did not happen and then exits 0, leaving a
   * script free to enrol against a certificate that was never installed. The two outcomes have to be
   * distinguishable, and the install has to keep its own exit status.
   */
  it('separates a fingerprint mismatch from a failed installation', () => {
    const command = text(
      render(instructions({ agentUrl: 'https://farrier.example.org' }), 'https://farrier.example.org/')
        .nativeElement,
    );

    expect(command).not.toContain('|| echo "FINGERPRINT MISMATCH');
    expect(command).toContain('if [');
    expect(command).toContain('else');
  });

  /**
   * A path prefix or a port does not make a single-hostname deployment look like a two-hostname one.
   *
   * The agent URL is a full base URL and the page's is a document address, so comparing them as
   * strings answered "can this fetch be verified?" wrongly whenever the deployment carried either —
   * and wrongly in the unsafe direction, claiming verifiable when it was not. The command it then
   * built dropped the prefix too. Both halves are asserted here because either alone would pass with
   * the other still broken.
   */
  it('compares origins, and keeps the path a control plane is published under', () => {
    const prefixed = text(
      render(
        instructions({ agentUrl: 'https://farrier.example.org/control' }),
        'https://farrier.example.org/control/',
      ).nativeElement,
    );

    expect(prefixed).toContain('unable to get local issuer certificate');
    expect(prefixed).toContain('https://farrier.example.org/control/api/v1/ca.crt');
  });

  /**
   * The verifiable branch keeps the prefix too, for a two-hostname deployment behind a path.
   *
   * The same bug in the other direction: an interface published under a path would have been handed a
   * download URL at the bare origin, which is a 404 rather than a certificate.
   */
  it('keeps the interface path when the fetch can be verified', () => {
    const rendered = text(
      render(instructions(), 'https://farrier.example.org/control/').nativeElement,
    );

    expect(rendered).toContain('curl -fsSL https://farrier.example.org/control/api/v1/ca.crt');
  });
});
