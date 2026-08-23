# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Farrier is fleet management for Ubuntu and Debian servers whose distinguishing property is the
**absence** of a remote execution channel. Everything below follows from that. Before changing anything
under `internal/intent`, `internal/run`, `internal/policy`, `helpers/`, `internal/signing` or
`packaging/sudoers`, read [`docs/SECURITY.md`](docs/SECURITY.md) — it is the specification, not a
description of one.

The guarantee, stated in `README.md` and `docs/SECURITY.md` §1, is enforced by tests rather than by
convention:

> An attacker who fully owns the Farrier control plane, its database, and an administrator account
> still cannot run arbitrary code on any **enrolled** host, cannot exceed any host's local policy, and
> cannot reboot or stop services on hosts whose policy forbids it.

Both paragraphs of it ship together — the second names the enrolment-time exception — and the
`guarantee` workflow fails if either goes missing from either file.

## Commands

```bash
make ci          # what CI runs, minus the pieces needing extra tooling — run this before pushing
make test        # go test -race ./...
make lint        # vet + doccheck + golangci-lint
make guarantee   # the tests that enforce docs/SECURITY.md §1, plus fuzzing
make site        # render the documentation site into public/
make deb         # build the .deb (needs nfpm)
make web         # build the Angular app into where farrier-server embeds it
```

One test, one package:

```bash
go test ./internal/agent/ -run TestCredentialPromotesTheNewPairInOneStep -v
```

The store tests **skip silently** without a database, which hides real failures. Give them one:

```bash
FARRIER_TEST_DATABASE_URL='postgres://farrier_test:farrier_test@127.0.0.1:5432/farrier_test?sslmode=disable' \
  go test ./internal/store/ -count=1
```

`golangci-lint` is pinned in the Makefile (`GOLANGCI_VERSION`) and CI installs that exact version via
`make golangci-install`. A different local version reports different findings; if CI disagrees with
you, check the version first.

Go 1.26 or newer. Web: pnpm 10, Node 22, run from `web/`.

## The invariants

These are decided. If one looks wrong, say so in one sentence and follow it anyway; changing one is a
conversation, not a commit.

- **The intent catalogue is closed at compile time.** `internal/intent/intent.go` holds an unexported
  map; there is no registry and no plugin loader. Adding a member means editing the catalogue *and*
  the expected-set literal in `guarantee_test.go` in the same commit, plus `docs/SECURITY.md` §3 and
  `docs/PROTOCOL.md`.
- **`internal/run` is the only place that starts a process**, with a closed allowlist of absolute
  paths. `source_guarantee_test.go` walks the AST of `cmd/`, `internal/` and `helpers/` to prove it,
  and `depguard` denies `os/exec` elsewhere. The AST test is the real guard — it cannot be silenced by
  editing a config file.
- **These names are permanently refused** and are named in `docs/SECURITY.md`: `shell.exec`,
  `script.run`, arbitrary `file.write`, `apt.addRepository`, `user.create`,
  `ssh.authorizedKeys.add`, `agent.updateFromURL`.
- **Local policy is enforced in the root helper, not in the agent.** `effective = min(central request,
  local policy)` — never the max. The helpers take no `--policy` flag; the path is a package constant,
  because a helper that reads a caller-supplied policy file is a helper that trusts its caller.
- **The trust anchor is `/etc/farrier/trusted-signers`, not the package**, and it ships empty. A fresh
  agent executes nothing destructive until an administrator puts a key there.
- **Clock skew is a security boundary.** Signature validity windows are checked against the **local**
  clock only. `serverTime` is used solely to compute an offset for display.
- **Never `apt`; always `apt-get`**, and wrap `unattended-upgrade` with `--force-confdef`,
  `--force-confold` and `DPkg::Lock::Timeout`.
- **Never add `farrier` to the `docker` group** — Docker socket access is root equivalence.
- **`store.Store` is not a portability seam.** JSONB + GIN, a partial index for the job claim,
  `LISTEN`/`NOTIFY`, and `SELECT … FOR UPDATE SKIP LOCKED` are load-bearing. Do not abstract for
  another database.
- **Tier 3 — pushing configuration to an already-enrolled host — is never built.**

## Architecture

Agent → server only, over HTTPS with mTLS, five endpoints. There is no path from the server to a host.

- `internal/agent` — enrolment, heartbeat, job acceptance, result spooling. The credential is one file
  (`agent.pem`, key and certificate together) promoted by one rename, so a renewal interrupted at any
  point leaves a matching pair. Results are fsynced *before* an operation that may not return.
- `internal/server` — the control plane: five agent endpoints plus an admin API and the embedded UI.
  Authentication is a certificate-fingerprint lookup on every request, which is also the whole
  revocation mechanism — no CRL, no OCSP.
- `internal/intent` + `internal/run` — what may happen, and the only place it happens.
- `internal/policy` + `internal/helper` + `helpers/` — three root helpers behind a pinned sudoers
  entry. Each re-reads the local policy itself.
- `internal/signing` + `internal/canonical` — offline signature verification over canonical JSON
  (sorted keys, no HTML escaping, integers only). Every authorisation decision is downstream of these.
- `internal/collect` — facts, with a `Platform` seam for the four distribution differences that
  otherwise produce silent wrong answers (security origins, the reboot marker, Ubuntu Pro, `apt-check`).
- `internal/store` — PostgreSQL, plus an in-memory implementation for tests only.
- `web/` — Angular 20 standalone, built into where `farrier-server` embeds it.
- `tools/doccheck`, `tools/docsite` — the doc-comment checker and the documentation site generator.
- `testfleet/` — LXD scenarios; `docs/MAINTAINING.md` covers repository settings and releases.

## House rules that linters enforce

- **Every type and function, exported or not, has a doc comment saying what it does *and why it
  exists*.** `revive` covers exported, `tools/doccheck` covers unexported, ESLint covers TypeScript.
  None of them can check the "why" — that is review's job, and it is the half that matters.
- Everything in English: identifiers, comments, commit messages, UI strings.
- Every commit is signed off (`git commit -s`). There is no CLA; the DCO is what keeps the licence
  permanent, and CI checks the whole range.
- A `//nolint` carries a written reason for *this* case, never a bare directive.
- `tools/docsite` fails the build on a broken internal documentation link, so a renamed heading breaks
  a pull request rather than rotting quietly.
