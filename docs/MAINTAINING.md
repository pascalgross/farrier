# Maintaining the repository

Everything here is a setting somebody has to make once, in GitHub's interface or on their own machine,
and that no file in this repository can make for them. It is written down because a security-relevant
setting that lives only in somebody's memory is a setting that will be wrong after the first holiday.

> [!IMPORTANT]
> One decision on this page is irreversible: the URL of the APT repository. It is written into
> `/etc/apt/sources.list.d/farrier.sources` on every host that ever installs the agent, including
> fleets that will later be unreachable. Read [§4](#4-the-apt-repository-url) before the first release,
> not after it.

## 1. Repository basics

**The default branch must be `main`.** Every workflow keyed to a push — `ci`, `guarantee`, `security`
and `pages` — names it, so a repository whose default branch is something else looks healthy and runs
none of them. This is worth checking rather than assuming: a repository created empty takes its default
from the name of the first branch pushed to it, which is rarely the one anybody intended.

**Settings → General.**

| Setting | Value |
| --- | --- |
| Description | Fleet management for Ubuntu and Debian servers, without a remote shell. The agent is outbound-only, runs a closed set of typed operations, and obeys a policy the control plane cannot change. |
| Website | `https://farrier.tools` |
| Topics | `ubuntu` `debian` `fleet-management` `patch-management` `unattended-upgrades` `systemd` `golang` `devops` `sysadmin` `security` |
| Issues | On |
| Discussions | On — the issue templates link to it for proposals |
| Wiki | Off. The documents in `docs/` are reviewed with the code; a wiki is not |
| Projects | Off unless you actually use one |
| Allow merge commits | Off |
| Allow squash merging | On, with the default message set to *pull request title and description* |
| Allow rebase merging | Off |
| Automatically delete head branches | On |
| Require contributors to sign off on web-based commits | On |

Web-based sign-off matters because the DCO check is not advisory: without it, a typo fixed through
GitHub's editor produces a commit with no `Signed-off-by` line, and the contributor discovers this from
a red required check rather than from the editor that could have prevented it.

Squash-only is not a style preference. Every commit on `main` has to carry a `Signed-off-by` line, and
a squash merge whose message is composed from the pull request is the one merge mode where the DCO
trailer is preserved deterministically rather than depending on what the contributor wrote in each of
eleven commits.

**Settings → Security.** Turn on private vulnerability reporting; the issue templates and
`docs/SECURITY.md` §9 both send people to it. Turn on Dependabot alerts and security updates —
`.github/dependabot.yml` already configures the version updates.

## 2. Branch protection

**Settings → Rules → Rulesets**, targeting the default branch. Rulesets rather than the older branch
protection because they can be set to apply to administrators too, which is the entire point here.

- Require a pull request before merging, with **1** approval.
- Dismiss stale approvals when new commits are pushed.
- Require review from Code Owners — `.github/CODEOWNERS` names the paths where that matters.
- Require status checks to pass, and require branches to be up to date first.
- Block force pushes, and block deletions.
- **Do not** add a bypass list. An administrator who can merge past the guarantee check is an
  administrator who will, at 23:00, on the change that most needed it.

Required checks, by the name each job reports:

| Check | Workflow | Why it is required |
| --- | --- | --- |
| `guarantee` | `guarantee.yml` | The catalogue is the expected set and nothing reaches a shell. This is the one that must never be bypassable |
| `DCO sign-off` | `ci.yml` | There is no CLA; the DCO is what keeps the licence permanent |
| `Go` | `ci.yml` | Unit tests, against a real PostgreSQL |
| `golangci-lint` | `ci.yml` | Linters and the doc-comment check |
| `Web` | `ci.yml` | Lint, tests and build of the interface |
| `Packaging` | `ci.yml` | The `.deb` installs, survives a reinstall, and purges cleanly |
| `APT repository` | `ci.yml` | A signed repository builds and `apt-get` installs from it |

Do not require the `integration` workflow. Its jobs are named from a matrix, so their names change when
the supported releases change, and a required check whose name no longer exists blocks every pull
request until somebody edits the ruleset.

## 3. GitHub Pages

**Settings → Pages → Source: GitHub Actions.** Not a branch — `pages.yml` deploys the site, and a
branch source would ignore it.

The workflow passes `enablement: true` to `actions/configure-pages`, so the first successful run on
`main` will turn Pages on by itself if it has not been turned on by hand. Setting it explicitly is
still worth doing, because the failure mode when it is off is a red deploy at the end of a release.

**Custom domain: `farrier.tools`.**

- Apex: four `A` records to `185.199.108.153`, `185.199.109.153`, `185.199.110.153`,
  `185.199.111.153`, and the four matching `AAAA` records for `2606:50c0:8000::153` through
  `2606:50c0:8003::153`. **Those eight and nothing else.** A leftover record for some other server
  stays in the rotation, so roughly one request in five reaches the wrong machine — including one
  `apt-get update` in five. An intermittent repository failure is considerably harder to diagnose than
  a total one, and it also blocks GitHub from issuing the certificate.
- `www.farrier.tools`: a `CNAME` to `pascalgross.github.io`.
- Enter `farrier.tools` in the Pages settings, wait for the certificate, then tick *Enforce HTTPS*.

GitHub Pages accepts exactly one custom domain per site, so the domain configured here is also the
domain under which `/apt` is served. That makes `farrier.tools` permanently load-bearing, which is a
real obligation and worth naming rather than discovering: see §4.

The site is laid out as:

| Path | What |
| --- | --- |
| `/` | This documentation |
| `/apt/` | The signed APT repository |

Two workflows would normally fight over this, because a Pages deployment replaces the entire site.
They do not, because only `pages.yml` deploys: `release.yml` signs the repository and attaches it to
the release as `apt-repository.tar.gz`, and `pages.yml` unpacks that beside the documentation. The
practical benefit is that the archive signing key is absent from every documentation change.

## 4. The APT repository URL

Set the repository variable **`FARRIER_APT_URL`** (Settings → Secrets and variables → Actions →
Variables) to:

```
https://farrier.tools/apt
```

The release workflow refuses to publish without it, deliberately, rather than defaulting to something
somebody would have to live with.

This URL cannot be migrated. It is written into `/etc/apt/sources.list.d/farrier.sources` on every
host that installs the agent, and a host forgotten in a rack somewhere is exactly the one that most
needs to keep receiving updates. `pascalgross.github.io/farrier/apt` was the alternative and is worse:
it would tie a permanent URL to an account name and a repository name, either of which may change if
the project ever moves to an organisation.

**`farrier.tools` must therefore never be allowed to lapse.** It is not a marketing asset that can be
dropped when the project's attention moves elsewhere; it is infrastructure that hosts depend on.
Concretely:

- Turn on auto-renew, and register for the longest term the registrar offers rather than a year.
- Put the renewal on a billing account that outlives one person's credit card, and make sure the
  registrar's notification address is read by more than one person.
- Enable the registrar's transfer lock.
- Treat losing the domain as an incident with the same severity as losing the signing key.

The consolation, if it is ever lost anyway: hosts pin `Signed-By:` to an explicit keyring, so whoever
comes to control the name cannot serve packages those hosts will accept. They can stop the updates.
They cannot replace the agent.

## 5. The archive signing key

This key signs the repository that installs and updates the agent on every host. Whoever holds it
controls that binary — a different adversary from the one the guarantee in `docs/SECURITY.md` §1 is
about, and §7 says so plainly. Treat it accordingly.

**Generate it on a machine you trust, not in CI.** A key generated in a runner has already been handled
by a third party.

```bash
gpg --batch --full-generate-key <<'KEY'
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: Farrier Archive Signing Key
Name-Email: farrier@pegasusnetworks.de
Expire-Date: 0
%commit
KEY

gpg --list-secret-keys --keyid-format=long
```

RSA 4096 rather than an elliptic curve: this key has to be verifiable by the `gpgv` on the oldest
release Farrier supports, and RSA is the one algorithm no version of it has ever been without.

No expiry, because an expired archive key breaks `apt-get update` on every host at once, and the repair
is a person visiting each of them. The mitigation for a key that never expires is that it lives
offline: back the private key up somewhere that is not the machine you use, and delete it from the
machine you generated it on once it is in the secret and the backup.

`%no-protection` — no passphrase — is deliberate and is the reason for the storage rules below. A
passphrase that also has to be in CI to be usable protects nothing; it just doubles the number of
secrets.

**Store it as an environment secret, not a repository secret.**

1. Settings → Environments → `github-pages`.
2. Add required reviewers (yourself is enough). A release then waits for a human before the job that
   can use the key runs.
3. Add the environment secret `APT_SIGNING_KEY` with the armoured private key:

```bash
gpg --armor --export-secret-keys <KEY-ID>
```

An environment secret with a reviewer means a compromised workflow file on a branch cannot reach the
key, because the branch's job never gets to the environment without an approval. A repository secret
has no such gate.

The public half needs no configuration: `mkapt.sh` exports it into the published repository as
`farrier-archive-keyring.gpg`, which is what hosts install.

## 6. Cutting a release

```bash
git tag -s v0.1.0 -m "Farrier 0.1.0"
git push origin v0.1.0
```

The tag starts `release.yml`, which:

1. re-runs `make guarantee` on the tag — deliberately, rather than trusting the last CI run;
2. builds `amd64` and `arm64` binaries with `-trimpath` and a pinned `SOURCE_DATE_EPOCH`, and the
   `.deb` packages;
3. waits for the environment approval, imports the signing key, and builds the signed repository;
4. publishes the repository as a release asset and creates the GitHub release;
5. triggers `pages.yml`, which republishes the site with the new repository under `/apt`.

`workflow_dispatch` accepts a version for a rehearsal. It must look like a version; the input is passed
through the environment rather than interpolated into a shell, and is checked against a pattern.

## 7. What is deliberately not automated

- **Nothing merges itself.** No auto-merge, no bots with write access. The catalogue being closed is
  worth very little if a dependency bot can widen it while nobody is looking.
- **The signing key is never rotated automatically.** Rotation means publishing a new public key,
  signing the repository with both for a transition period, and only then retiring the old one — hosts
  that update rarely are the ones that would be cut off by anything faster.
- **Hosts are never contacted.** There is no step anywhere in this repository that reaches a managed
  machine. That is the product.
