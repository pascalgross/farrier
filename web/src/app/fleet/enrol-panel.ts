import { Component, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';

import { EnrolmentInstructions, MintedEnrolmentToken } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';

/**
 * How to enrol a host, as three steps somebody can follow without leaving the page.
 *
 * It exists because the fleet page's answer to "how do I add a machine" was one line of shell with the
 * literal placeholder `https://this-control-plane` in it, shown only when the fleet was empty. Every
 * other part of the answer — the APT repository, the CA certificate, the fact that a token has to be
 * minted first and is shown once — was in INSTALL.md, which is a different document on a different
 * screen, and the placeholder had to be replaced by hand with a value the page already knows.
 *
 * The three steps are one panel rather than three, and in this order, because enrolment fails in a
 * particular way when they are done out of it: an agent installed before the CA is in place starts,
 * fails to verify the control plane, and retries — so the operator sees a running service and a host
 * that never appears, which reads as a control-plane fault.
 *
 * Nothing here changes what enrolment *is*. The token is the same single-use token the API has always
 * minted, the command is the same command, and the control plane still has no path to a host: every
 * one of these steps is something a person runs on the machine. What the panel removes is the chance
 * to get one of them subtly wrong.
 */
@Component({
  selector: 'farrier-enrol-panel',
  imports: [
    DatePipe,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    MatProgressBarModule,
    MatTooltipModule,
  ],
  templateUrl: './enrol-panel.html',
})
export class EnrolPanel {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** What the control plane says about itself, null until the panel is first opened. */
  protected readonly instructions = signal<EnrolmentInstructions | null>(null);

  /** Why the instructions could not be read, empty when they could. */
  protected readonly error = signal('');

  /** The token minted most recently, null before anybody has asked for one. */
  protected readonly minted = signal<MintedEnrolmentToken | null>(null);

  /** Why minting failed, empty when it did not. */
  protected readonly mintError = signal('');

  /** Whether a request is in flight, so the button can be disabled. */
  protected readonly busy = signal(false);

  /** Which command was copied most recently, so the button can say so. Empty for none. */
  protected readonly copied = signal('');

  /** The commands that add the APT repository and install the agent. */
  protected readonly installCommand = computed(() => {
    const apt = this.instructions()?.aptUrl ?? '';
    return [
      `curl -fsSL ${apt}/farrier-archive-keyring.gpg \\`,
      '  | sudo tee /usr/share/keyrings/farrier-archive-keyring.gpg > /dev/null',
      `curl -fsSL ${apt}/farrier.sources \\`,
      '  | sudo tee /etc/apt/sources.list.d/farrier.sources > /dev/null',
      'sudo apt-get update && sudo apt-get install farrier-agent',
    ].join('\n');
  });

  /**
   * The command that installs the CA certificate, fetching it from this control plane.
   *
   * It reads the certificate over the network rather than telling the operator to download it here and
   * copy it across, because a step that spans two machines is the step people improvise around — and
   * the improvisation is a host that trusts the system roots instead of this authority.
   *
   * `install` rather than `cp`, with the owner, group and mode written out: the file is what the agent
   * checks the control plane against, and one left mode 0600 root-owned in a directory the agent can
   * read is a difference nobody notices until enrolment fails.
   *
   * It fetches from **this page's own origin** rather than from the agent URL, and that is the whole
   * point of the computed rather than a template string. `curl` verifies the control plane like any
   * other client, so it can only fetch the certificate from a name whose certificate is already
   * trusted — and the agent hostname's is precisely the one that is not, since it is what the file
   * being fetched would establish. In the documented two-hostname deployment this origin is the
   * interface, where Traefik terminates with a publicly trusted certificate, so the command works;
   * against the agent hostname it fails with `unable to get local issuer certificate` every time. When
   * the two are the same name it fails either way, which is what the note beside it is for.
   */
  protected readonly caCommand = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    if (this.caFetchIsUnverifiable()) {
      return this.caCommandUnverified();
    }
    return [
      `curl -fsSL ${this.origin()}${details.caCertificatePath} \\`,
      '  | sudo install -D -o root -g root -m 0644 /dev/stdin /etc/farrier/server-ca.crt',
    ].join('\n');
  });

  /** The certificate's SHA-256, shown so an unverified fetch has something to be checked against. */
  protected readonly fingerprint = computed(() => this.instructions()?.caFingerprint ?? '');

  /**
   * The same step for a control plane whose certificate cannot be verified from the host.
   *
   * `-k` is in here and it is not a shortcut: it is one half of a check, and the command fails closed
   * without the other half. The certificate is fetched unverified, its digest is compared against the
   * one this page is showing, and it is installed only on a match — so the bytes are accepted because
   * they match a value that arrived over this authenticated session, not because whoever answered the
   * hostname said so.
   *
   * Written as a `test` rather than as "now compare these two strings by eye", because a comparison of
   * two 64-character hex strings is one people perform by looking at the first four characters. The
   * shell does it exactly, and an operator who pastes this gets an installed certificate or a refusal,
   * with no third outcome where they thought they had checked.
   */
  protected readonly caCommandUnverified = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    return [
      `curl -fsSLk ${details.agentUrl}${details.caCertificatePath} -o /tmp/farrier-ca.crt`,
      `test "$(openssl x509 -in /tmp/farrier-ca.crt -noout -fingerprint -sha256)" \\`,
      `  = "sha256 Fingerprint=${details.caFingerprint}" \\`,
      '  && sudo install -D -o root -g root -m 0644 /tmp/farrier-ca.crt /etc/farrier/server-ca.crt \\',
      '  || echo "FINGERPRINT MISMATCH - do not install this certificate"',
    ].join('\n');
  });

  /**
   * Where this page is served from, as an origin a shell command can be pointed at.
   *
   * Read through a getter so a test can replace it; `window.location` is otherwise a global the
   * component would be pinned to.
   */
  protected origin(): string {
    return window.location.origin;
  }

  /**
   * Whether the certificate has to be fetched from the same name it authenticates.
   *
   * True in the single-hostname deployment, where the interface and the agent API share an origin
   * serving Farrier's own certificate. The step above cannot verify that connection — nothing has told
   * the host to trust this authority yet, which is the reason for the step — so the panel says so and
   * points at the two ways round it, rather than printing a command that always fails and letting the
   * operator conclude the control plane is broken.
   */
  protected readonly caFetchIsUnverifiable = computed(() => {
    const details = this.instructions();
    return !!details && details.agentUrl === this.origin();
  });

  /** The enrolment command, carrying the token when one has been minted. */
  protected readonly enrolCommand = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    const token = this.minted()?.token ?? '<TOKEN>';
    return `sudo farrier enroll --server ${details.agentUrl} --token ${token}`;
  });

  /** Where the CA certificate can be downloaded, for an operator who would rather have the file. */
  protected readonly caDownloadUrl = computed(() => this.instructions()?.caCertificatePath ?? '');

  /**
   * Reads the instructions when the panel is opened, and not before.
   *
   * A native `<details>` rather than a Material expansion panel, and the reason is measurable: the
   * expansion module put the initial bundle over its budget for one disclosure widget on one page.
   * `<details>` is the same control, is keyboard-operable and announced without anything being added
   * for it, and costs nothing.
   *
   * The guard makes the toggle idempotent: `toggle` fires on closing as well as opening, and the
   * answer does not change while the page is open.
   */
  protected load(): void {
    if (this.instructions() !== null) {
      return;
    }
    this.api.enrolment().subscribe({
      next: (details) => {
        this.instructions.set(details);
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }

  /**
   * Mints one single-use enrolment token.
   *
   * The result is shown once and never again — only its SHA-256 is stored — which the panel says at
   * the moment it is shown rather than in a footnote. A token nobody copied is not recoverable and is
   * not a problem: minting another costs one click.
   */
  protected mint(): void {
    this.busy.set(true);
    this.mintError.set('');
    this.api.createEnrolmentToken({ label: 'from the fleet page', group: '' }).subscribe({
      next: (token) => {
        this.busy.set(false);
        this.minted.set(token);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.mintError.set(describeError(err));
      },
    });
  }

  /**
   * Copies one command, and remembers which so the button can confirm it.
   *
   * Best-effort, like the template page's copy: the text is on screen and selectable, and a browser
   * refusing clipboard access — several do without a gesture they recognise — must not look like the
   * command itself is wrong.
   */
  protected async copy(name: string, text: string): Promise<void> {
    if (!text || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(name);
    } catch {
      // Left on screen for a manual copy, which is the fallback that always works.
    }
  }
}
