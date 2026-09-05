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
 * Builds a download URL from a base and the control plane's own path for the certificate.
 *
 * It exists because `caCertificatePath` is server-absolute — `/api/v1/ca.crt` — and concatenating that
 * onto a base silently discards any path the control plane is published under. A deployment behind
 * `https://hostseal.example.org/control` would be handed a command pointing at the bare origin, which
 * is a 404 or, worse, somebody else's route on a shared hostname.
 *
 * The base's own path is kept and the certificate path appended to it, so the prefix survives. An
 * unparseable base falls back to plain concatenation rather than throwing: the panel printing a
 * slightly wrong command is recoverable, and a component that renders nothing at all is not.
 */
function caUrl(base: string, certificatePath: string): string {
  try {
    const parsed = new URL(base);
    return `${parsed.origin}${parsed.pathname.replace(/\/$/, '')}${certificatePath}`;
  } catch {
    return `${base.replace(/\/$/, '')}${certificatePath}`;
  }
}

/**
 * Whether two URLs are served by the same origin, ignoring path and trailing slash.
 *
 * The panel's whole branch — a fetch it can verify against one it cannot — turns on whether the agent
 * API and this page share a host, and that question is about scheme, host and port only. A string
 * comparison answered it wrongly for every deployment carrying a port or a path prefix, and wrongly in
 * the unsafe direction: it claimed the fetch was verifiable when it was not.
 *
 * Either side failing to parse returns false, which sends the panel to the fingerprint-checked command.
 * That is the safe way to be wrong: it prints a check that is unnecessary rather than skipping one that
 * was not.
 */
function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

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
  selector: 'hostseal-enrol-panel',
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
      `curl -fsSL ${apt}/hostseal-archive-keyring.gpg \\`,
      '  | sudo tee /usr/share/keyrings/hostseal-archive-keyring.gpg > /dev/null',
      `curl -fsSL ${apt}/hostseal.sources \\`,
      '  | sudo tee /etc/apt/sources.list.d/hostseal.sources > /dev/null',
      'sudo apt-get update && sudo apt-get install hostseal-agent',
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
   * It fetches from **this page's own address** rather than from the agent URL, and that is the whole
   * point of the computed rather than a template string. `curl` verifies the control plane like any
   * other client, so it can only fetch the certificate from a name whose certificate is already
   * trusted — and the agent hostname's is precisely the one that is not, since it is what the file
   * being fetched would establish. In the documented two-hostname deployment this page is the
   * interface, where Traefik terminates with a publicly trusted certificate, so the command works;
   * against the agent hostname it fails with `unable to get local issuer certificate` every time. When
   * the two are the same host it fails either way, which is what the other command is for.
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
      `curl -fsSL ${caUrl(this.pageBase(), details.caCertificatePath)} \\`,
      '  | sudo install -D -o root -g root -m 0644 /dev/stdin /etc/hostseal/server-ca.crt',
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
   * The comparison is done by the shell rather than by eye, because two 64-character hex strings are
   * compared by looking at the first four characters, and that is not a comparison.
   *
   * `if`/`else` rather than `test && install || echo`, which is the same three commands and is wrong.
   * In that form the `||` binds to the whole list, so a missing `sudo`, a cancelled password prompt or
   * a full disk makes `install` fail and prints `FINGERPRINT MISMATCH` — naming an attack that did not
   * happen, for a digest that matched — and then `echo` succeeds, so the line exits 0 and a script
   * carries on to enrolment with no certificate installed. Here the two failures stay distinct and
   * `install` keeps its own exit status; `false` rather than `exit` because this gets pasted into an
   * interactive shell, and a mismatch should report itself rather than close the operator's session.
   */
  protected readonly caCommandUnverified = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    return [
      `curl -fsSLk ${caUrl(details.agentUrl, details.caCertificatePath)} -o /tmp/hostseal-ca.crt`,
      'if [ "$(openssl x509 -in /tmp/hostseal-ca.crt -noout -fingerprint -sha256)" \\',
      `     = "sha256 Fingerprint=${details.caFingerprint}" ]; then`,
      '  sudo install -D -o root -g root -m 0644 /tmp/hostseal-ca.crt /etc/hostseal/server-ca.crt',
      'else',
      '  echo "FINGERPRINT MISMATCH - do not install this certificate" >&2',
      '  false',
      'fi',
    ].join('\n');
  });

  /**
   * The address this page is served from, including any path the control plane is published under.
   *
   * `document.baseURI` rather than `window.location.origin`, because a control plane behind a proxy
   * path prefix is a supported deployment — the container entrypoint takes a whole HOSTSEAL_AGENT_URL
   * for exactly that case — and an origin alone drops the prefix, producing a download URL that is a
   * 404 on the one deployment that most needs the command to work. Read through a getter so a test can
   * replace it; the document is otherwise a global the component would be pinned to.
   */
  protected pageBase(): string {
    return document.baseURI;
  }

  /**
   * Whether the certificate has to be fetched from the same host it authenticates.
   *
   * True in the single-hostname deployment, where the interface and the agent API share an origin
   * serving HostSeal's own certificate. The plain command cannot verify that connection — nothing has
   * told the host to trust this authority yet, which is the reason for the step — so the panel prints
   * the fingerprint-checked fetch instead of a command that always fails.
   *
   * Origins are compared rather than the strings, because the two values are not the same kind of
   * thing: the agent URL is a full base URL and may carry a port or a path prefix, and the page's is a
   * document address. Comparing them literally made every prefixed or non-default-port deployment look
   * like the two-hostname one — so the panel took the verifiable branch, built the download from the
   * page's address, dropped the prefix, and printed a command that either fetched the wrong route or
   * failed the very TLS verification this whole step exists to establish.
   */
  protected readonly caFetchIsUnverifiable = computed(() => {
    const details = this.instructions();
    return !!details && sameOrigin(details.agentUrl, this.pageBase());
  });

  /** The enrolment command, carrying the token when one has been minted. */
  protected readonly enrolCommand = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    const token = this.minted()?.token ?? '<TOKEN>';
    return `sudo hostseal enroll --server ${details.agentUrl} --token ${token}`;
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
