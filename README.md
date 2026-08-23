# Farrier

**Fleet management for Ubuntu and Debian servers, without a remote shell.** The agent is
outbound-only, runs a closed set of typed operations, and obeys a policy the control plane cannot
change.

By [Pegasus Networks](https://pegasusnetworks.de). Licensed **Apache-2.0**.
Documentation: [farrier.tools](https://farrier.tools).

> [!IMPORTANT]
> Farrier is in **phase 1**, and phase 1 is half done. Nine of the ten catalogue members now have an
> executor: the four read-only operations, and all five destructive ones — apply every update, start,
> stop or restart a unit, and reboot. They enforce the host's own policy as root, over a socket rather
> than through `sudo`, and you can drive them from an administrator's shell on a host today.
>
> **The control plane cannot yet issue any of them.** There is no job-creation API and no
> `farrier sign`, so nothing reaches a host from the server side — for a privileged intent or for a
> read-only one. And `packages.applySecurity` deliberately has no executor at all: it is the one
> *routine* intent, and [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §5.1 says an agent must not run one
> until it verifies a signature by the control plane's online key, which does not exist yet.
>
> So: a fleet that reports, hosts whose privileged operations are real and bounded by a file the
> control plane cannot touch, and no way to ask for one from the browser. Do not expect to patch a
> fleet with this yet.

---

## The guarantee

> An attacker who fully owns the Farrier control plane, its database, and an administrator account
> still cannot run arbitrary code on any **enrolled** host, cannot exceed any host's local policy, and
> cannot reboot or stop services on hosts whose policy forbids it.
>
> A host **being enrolled** applies, at most once, the bootstrap template its operator named on the
> command line — shown in full before it runs, signed by a key from that host's own
> `trusted-signers`, and recorded permanently on the host.

Both paragraphs ship together, always. The second is the price of the bootstrap feature, and a
guarantee with an undisclosed exception is worse than no guarantee — so the first paragraph is never
quoted on its own just because it reads better.

Landscape, Salt, Uyuni and Rudder all ship a remote execution channel. Farrier does not. **That
absence is the product**, and everything below exists to make the absence hold up under a control
plane that has been fully compromised.

## How it holds

Three mechanisms, specified in [`docs/SECURITY.md`](docs/SECURITY.md) and asserted by a required CI
workflow that no maintainer can override:

1. **A closed intent catalogue.** The wire protocol carries an enumerated, typed operation — never a
   command string. No code path leads from a network message to a shell. Every external call is
   `execve` with a fixed argv slice.
2. **Local policy sovereignty.** Each host carries a root-owned `/etc/farrier/policy.toml` that the
   control plane cannot modify and no intent can touch. Effective permission is always
   `min(central request, local policy)` — never the max. The check that matters runs as root in the
   helper, so a *fully compromised agent process* is still bounded.
3. **Offline job signing.** Every destructive operation requires a signature from a key in that host's
   own `/etc/farrier/trusted-signers` — a key the control plane does not hold. The file is empty by
   default, so a fresh agent executes nothing destructive until an administrator puts a key in it.

## What it does

- **Inventory** — OS, kernel, hardware, network, uptime, Ubuntu Pro / ESM status where applicable.
- **systemd service state** — read over D-Bus, not by parsing `systemctl` output.
- **Package update visibility** — security updates separated from the rest, correctly on both Ubuntu
  and Debian, plus `needrestart`'s answer to "which running services still hold the old library".
- **Policy-gated update application** — the host decides what it will accept; the control plane can
  only ask for something within that.
- **Provisioning templates** — cloud-init templates stored, versioned and rendered by Farrier, and
  handed to *you*. Farrier is not in the delivery path.

## What it will never do

No remote shell. No configuration management — this is not Ansible. No metrics platform — Prometheus
does time series properly; this takes a low-frequency state snapshot. No secret distribution — the
control plane never pushes credentials to hosts. No VPN requirement. No runtime plugin loader. No
database abstraction layer for portability.

`shell.exec`, `script.run`, arbitrary `file.write`, `apt.addRepository`, `user.create`,
`ssh.authorizedKeys.add` and `agent.updateFromURL` are **permanently refused**, each with its reason
written down in [`docs/SECURITY.md`](docs/SECURITY.md#permanently-refused). In an open-source project
that request arrives eventually, usually from someone with a real problem, and the answer needs to be
a document rather than an argument.

## Architecture

| | |
| --- | --- |
| **Agent** | Go. A static binary — no runtime on managed hosts, which is what keeps `MemoryDenyWriteExecute=yes` available |
| **Control plane** | Go. **One binary** with the Angular bundle embedded via `embed.FS`, plus PostgreSQL |
| **Database** | PostgreSQL, used deliberately: `JSONB` + GIN for facts, partial indexes for the job claim, `LISTEN`/`NOTIFY` instead of Redis, `SELECT … FOR UPDATE SKIP LOCKED` for atomic claims |
| **Web UI** | Angular + Angular Material + Tailwind v4, standalone components |
| **Queue / pubsub** | None |
| **Transport** | HTTPS long-poll with mTLS. Agent to server, never the reverse |

Open-source software is installed by strangers who close the tab on friction, and a four-service
Compose stack is friction. Sharing one language between both sides also means the intent catalogue and
signature verification are *literally the same code* on the agent and on the server, rather than two
implementations that agree until they don't.

## Supported platforms

Ubuntu 22.04 (jammy), 24.04 (noble), 26.04 (resolute); Debian 12 (bookworm) and 13 (trixie).

The policy is a rule rather than a list: **the Ubuntu LTS releases in standard support, plus Debian
stable and oldstable.** Ubuntu 20.04 is excluded as ESM-only.

## Documentation

| | |
| --- | --- |
| [`docs/`](docs/) | Everything below, plus a note on where the design rationale lives |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Getting a control plane and a host running, and what a fresh host will and will not do |
| [`docs/SECURITY.md`](docs/SECURITY.md) | The guarantee, the three mechanisms, the permanently-refused list, and an honest statement of what Farrier does *not* defend against |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | The agent protocol, specified well enough to reimplement |
| [`docs/EXTENDING.md`](docs/EXTENDING.md) | The seams that are open, and the ones that are closed on purpose |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | DCO sign-off, English, and the comment rule |
| [`TRADEMARK.md`](TRADEMARK.md) | What you may call your fork |

## Building

```bash
make build          # all three binaries into ./dist
make test           # unit tests
make guarantee      # the tests that enforce docs/SECURITY.md §1
make lint           # golangci-lint + doccheck
make web            # the Angular application, embedded into farrier-server
make deb            # the farrier-agent .deb via nfpm
```

Go 1.26 or newer. `make deb` additionally needs [`nfpm`](https://nfpm.goreleaser.com/);
`make web` needs Node and pnpm.

## Licence, and why it will not change

**Apache-2.0 for everything.** Contributions are made under the
[Developer Certificate of Origin](https://developercertificate.org/) — there is no CLA, and Pegasus
Networks holds no special rights over contributed code that you do not also hold.

This is deliberately permanent. Relicensing a DCO project requires the agreement of every contributor,
which means **no future owner of this repository can take it proprietary**, including us. For a
security tool whose entire value is that you can verify its claims yourself, the ability to promise
that is worth more than the option to change our minds.

Apache-2.0 §6 grants no trademark rights. The **Farrier** word mark is reserved; see
[`TRADEMARK.md`](TRADEMARK.md). You may fork the code and ship it; you may not call your fork Farrier.

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Two rules catch most first-time contributors:

- **Everything is in English** — identifiers, comments, docs, commit messages, issues, UI strings. A
  project asking strangers to audit its security claims cannot also ask them to read German first.
- **Every type and function carries a doc comment covering what it does *and why it exists*.**
  Exported or not. If the comment would still be true after you deleted the function, it is not a
  comment about why the function exists.

Security issues go through GitHub's private advisory flow, not the public tracker —
[`docs/SECURITY.md` §9](docs/SECURITY.md#9-reporting-a-vulnerability).
