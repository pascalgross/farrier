# Contributing to Farrier

Thank you for considering it. This document is short, and every rule in it has a reason attached,
because rules without reasons get argued with.

Please read [`docs/SECURITY.md`](docs/SECURITY.md) before proposing anything that touches the agent,
the intent catalogue, the root helpers, or the policy file. It is not long, and it will save you from
writing a pull request that has to be declined on principle.

---

## The three rules

### 1. Sign off every commit (DCO)

Farrier uses the [Developer Certificate of Origin](https://developercertificate.org/). There is **no
CLA**. Pegasus Networks holds no rights over your contribution that you do not also hold.

Add a sign-off line to every commit:

```
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` does it for you. The name and email must be real and must match the commit author.

This is checked in CI and the check is not overridable. Not because we enjoy blocking pull requests,
but because it is the mechanism that makes the licence permanent: under DCO, relicensing Farrier would
require the agreement of every contributor, which means **no future owner of this repository can take
it proprietary** — including us. For a security tool whose whole value is that you can verify its
claims yourself, that permanence is worth more than the flexibility it costs.

To fix a missing sign-off:

```bash
git commit --amend -s --no-edit          # the last commit
git rebase --signoff origin/main         # a whole branch
```

### 2. English, everywhere

Identifiers, comments, documentation, commit messages, issue titles, pull request descriptions, UI
strings, log messages, error text. All of it.

Pegasus Networks is a German company and this rule costs us something. We keep it because a project
that asks strangers to audit its security claims cannot also ask them to read German first. If the
argument for a mechanism is only comprehensible to people who speak the maintainers' language, it is
not really an open claim.

### 3. Every type and every function carries a doc comment saying what it does **and why it exists**

Exported or not. Yes, unexported helper functions too.

The rule of thumb, and the thing reviewers actually check:

> **If the comment would still be true after you deleted the function, it is not a comment about why
> the function exists.**

```go
// BAD — restates the signature. Deleting the function would not make this false.
// Sign signs the payload.
func (s *fileSigner) Sign(ctx context.Context, payload []byte) ([]byte, error)
```

```go
// GOOD — what it does, then why this code is here at all.
//
// Sign produces a detached Ed25519 signature over the canonical job payload.
//
// It exists as a backend separate from pkcs11Signer because most operators start with
// a key file and only move to hardware once the fleet justifies the ceremony. Refusing
// that path would not make anyone buy a token; it would push them to keep the key on
// the control plane instead, which is strictly worse.
func (s *fileSigner) Sign(ctx context.Context, payload []byte) ([]byte, error)
```

Enforcement is split honestly between machines and humans:

| Check | Mechanism |
| --- | --- |
| Comments on exported Go declarations | `golangci-lint`, `revive`'s `exported` rule |
| Comments on **unexported** Go declarations | `tools/doccheck`, an AST walker this repository ships, because no off-the-shelf linter does this |
| TypeScript, including private members | ESLint `jsdoc/require-jsdoc` with `checkPrivate` |
| Sentence shape (starts with the name, ends with a period) | `revive` and `godot` |
| **Whether the "why" is real** | Code review. No linter can check it, and reviewers reject `// Sign signs the payload.` the same way they reject an untested branch |

Run `make lint` before you push. In a repository this young the discipline is nearly free; retrofitting
it later is miserable, which is why it is in place before there is much code to comment.

---

## Before you open a pull request

```bash
make lint        # golangci-lint, doccheck, ESLint
make test        # unit tests
make guarantee   # the tests that enforce docs/SECURITY.md §1
```

`make guarantee` is a **required check with no maintainer override**. It is what keeps the guarantee
true across contributors who never read the design brief — including future maintainers, including us
on a bad day.

## Things that will be declined, with the reason written down in advance

None of these are a judgement about you or your use case. They are structural, and the reasoning is in
[`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/EXTENDING.md`](docs/EXTENDING.md):

- **A `shell.exec` intent**, or any of its spellings: `script.run`, arbitrary `file.write`,
  `apt.addRepository`, `user.create`, `ssh.authorizedKeys.add`, `agent.updateFromURL`. This is the one
  thing Farrier exists not to have.
- **Making the intent catalogue a registry**, loadable from config or a plugin.
- **A runtime plugin loader in the agent.** Any mechanism that loads code into the agent at run time
  is remote code execution wearing a plugin API.
- **A fourth root helper**, especially one that runs a configured command.
- **A database backend other than PostgreSQL.** `store.Store` exists so tests need no database, not as
  a portability layer. Farrier depends on `JSONB`, GIN, partial indexes, `LISTEN`/`NOTIFY` and
  `SELECT … FOR UPDATE SKIP LOCKED` on purpose.
- **A server→agent push channel**, in any transport.
- **Weakening the signature requirement for "small" destructive operations.** There is no graded tier
  by blast radius, deliberately: a control plane with two operator accounts could walk the fleet host
  by host, so a tiered design would only weaken the claim, not the risk.

If you have a real operational problem behind one of these, open a **discussion** describing the
problem rather than a pull request implementing the mechanism. The usual outcome is a new *typed*
intent with validated parameters, which is a normal reviewable change. The process for that is in
[`docs/EXTENDING.md`](docs/EXTENDING.md#adding-a-new-intent-if-you-are-sure).

## Adding a platform, a collector, a signing backend, a notification sink

These are the seams that are open by design. See [`docs/EXTENDING.md`](docs/EXTENDING.md). The rule
throughout is **add an implementation, never edit a `switch`** — if your change requires modifying a
type switch in the core, that is a missing seam and a legitimate bug report.

If you add a `collect.Platform`, say explicitly in the pull request what your implementation does about
each of the four known silent-wrong-answer traps listed in `EXTENDING.md`. All four fail quietly rather
than loudly, so "it worked on my machine" does not detect them.

## Style

- `gofmt` (`make fmt`); the CI checks it.
- Prefer the standard library. Every dependency in the agent is a dependency in something that runs as
  a service on other people's servers.
- No `panic` in agent or server request paths.
- Errors are wrapped with `%w` and carry enough context to identify the host and job.
- Never build a command string. Every external invocation is `exec.CommandContext` with a fixed
  program path and an explicit argv slice. Nothing goes through a shell.
- Use `apt-get`, never `apt` — see [`docs/SECURITY.md`](docs/SECURITY.md) and the comments in
  `internal/collect`. `apt` 3.0 reorganised its output into colourised columns and its format is not
  stable; `apt-get` is machine-oriented and stable. A refactor to the "nicer" command breaks update
  detection on the newest release while still passing on the oldest.

## Commits and pull requests

- Small, reviewable commits. One logical change each.
- Present tense, imperative mood: "Add Debian security-origin patterns", not "Added" or "Adds".
- Explain **why** in the body. The diff already shows what.
- Link the issue or discussion.
- A pull request that changes behaviour needs a test. A pull request that changes anything in
  `docs/SECURITY.md` §1 needs a very good reason and will get a slow, careful review.

## Reporting security issues

**Do not open a public issue.** Use GitHub's private advisory flow, described in
[`docs/SECURITY.md` §9](docs/SECURITY.md#9-reporting-a-vulnerability).

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
