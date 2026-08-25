# Independent security audit — Farrier

**Date:** 2026-08-25
**Scope of code reviewed:** commit on `claude/security-audit-independent-yyeczm` (branched from `main` at
`9916db7`).
**Auditor:** independent review by Claude Code, commissioned by the maintainer. This document is an
external assessment; it is not part of the enforced specification. The specification is
[`docs/SECURITY.md`](docs/SECURITY.md), and where this audit and that document disagree, that document
is authoritative until a maintainer changes it.

---

## 1. Summary

**No violation of the [`docs/SECURITY.md`](docs/SECURITY.md) §1 guarantee was found.** The three
load-bearing mechanisms — a closed compile-time intent catalogue with a single audited `execve`
chokepoint, local policy sovereignty re-enforced as root in the helpers, and offline job signing against
a host-held trust anchor — hold in the code as written, not merely in the tests that assert them. Tenant
isolation is enforced by PostgreSQL row-level security that is both `ENABLE`d and `FORCE`d on every
tenant table, and the server refuses to start on a role that could see through it.

The audit produced **21 findings, none of which breaks the §1 guarantee**. Their severity is bounded by
a structural fact worth stating plainly: §1 already grants the attacker full ownership of the control
plane, its database and an administrator account. An issue that lets *that* attacker read data, forge an
outbound request, or exhaust a resource on the control plane grants them nothing they do not already
have. Consequently every finding is a **defense-in-depth, hardening, supply-chain, or information-
disclosure** issue, and the single medium-severity finding concerns the *release* supply chain — a
different adversary that the project's own documents ([`docs/SECURITY.md`](docs/SECURITY.md) §9,
`CODEOWNERS`) already name as out of §1's scope.

| Severity | Count |
| --- | --- |
| Critical (breaks §1) | 0 |
| High | 0 |
| Medium | 1 |
| Low | 16 |
| Informational | 4 |

The recurring theme across the low-severity findings is **enforcement that lives in one place where the
design's own principles would put it in two**: a signature checked only in the least-trusted process, an
invariant held by a Go `if` rather than a database `CHECK`, a guardrail test that recognises four spellings
of `execve` but not the fifth. None of these is currently exploitable. Each is a place where a single
future edit could remove a protection with no failing test to signal it — which, for a project whose
distinguishing claim is that its guarantees are mechanically enforced rather than conventionally observed,
is the class of issue most worth closing.

---

## 2. Method

Two independent passes were run and then reconciled:

1. **Direct review of the crown-jewel code paths** — the single `execve` site (`internal/run`), the
   policy decision (`internal/policy`, `internal/helper`), canonical encoding (`internal/canonical`),
   signature verification and the acceptance sequence (`internal/signing`, `internal/agent/execute.go`),
   the NoCloud bootstrap seed (`internal/agent/bootstrap.go`), the row-level-security migrations and the
   startup role check (`internal/store`, `cmd/farrier-server`), and the agent's systemd hardening.

2. **A ten-dimension fan-out audit**, one auditor per subsystem, each instructed to verify the
   `docs/SECURITY.md` claims against the actual code and to hunt for gaps the guarantee tests do not
   cover. Every finding was then handed to an independent **adversarial verifier** that re-read the cited
   code and tried to refute it; findings that did not survive were dropped (one auditor's output was
   degenerate and its verifier correctly discarded it). A final **completeness critic** re-read the
   subsystem left uncovered and looked for cross-cutting gaps that no single auditor could see end to end.

Severity is rated by impact on the §1 guarantee first, and every finding below carries a concrete failure
scenario and a `file:line` anchor that was read, not inferred.

**What this audit did _not_ do:** it did not run the test suite, fuzzers, or `libsofthsm2`-backed PKCS#11
tests; it did not perform dynamic testing, live exploitation, or a dependency-CVE sweep; and it did not
audit the Angular front end (`web/`) or the LXD test harness (`testfleet/`). It is a source review, and
its assurances are the assurances of a careful reading.

---

## 3. What was verified to hold

An audit that reports only what is wrong is misleading about a codebase this careful. The following
claims were checked against the code and **confirmed**:

- **The intent catalogue is genuinely closed.** `internal/intent/intent.go` holds an unexported map with
  no `Register` function, no plugin path, and no config that adds a member; `Lookup`/`Decode` are total
  and fail closed on an unknown name. Parameters decode through a strict decoder
  (`DisallowUnknownFields`, trailing-data rejection, 8 KiB bound) into typed structs, each with a
  validator (`internal/intent/params.go`).

- **`internal/run` is the only process-spawning site**, guarded at run time by a closed absolute-path
  allowlist that is checked before `exec` (`run.go:181`), with a replaced environment, a deadline, and
  bounded output. No control-plane value reaches an `argv` slice as a flag: unit operations travel over
  D-Bus as typed method arguments (`helpers/restart-unit/main.go`), the reboot message is refused when it
  begins with `-` and is additionally placed after a `--` separator (`internal/intent/params.go`,
  `helpers/reboot-host/main.go`), and the apt argv is entirely constant (`helpers/apply-updates`).

- **Local policy is re-enforced as root, from a packaged constant path.** `internal/helper/helper.go`
  re-decodes the parameters and re-reads `/etc/farrier/policy.toml` on the helper's own side of the
  boundary; `internal/policy/decide.go` implements `effective = min(central, local)` literally, derives
  the requested level from the intent (so `applyAll` cannot claim to need only security permission),
  re-evaluates a requested follow-up reboot *as a reboot*, and refuses any privileged intent it has no
  rule for. The helpers take no `--policy` flag and the socket request carries no path field.

- **The two signature anchors cannot be interchanged.** `internal/agent/execute.go` verifies a
  destructive job only against `/etc/farrier/trusted-signers` and a routine job only against the online
  key, in two separate functions with no shared parameter that could pass the wrong set. Verification
  dispatches on the *parsed key type* from the root-owned anchor file, not on a wire-supplied algorithm
  tag, so there is no downgrade/confusion vector (`internal/signing/signing.go`). An empty anchor always
  fails closed. The signed payload binds `{jobId, hostId, intent, params, notBefore, notAfter, nonce}`
  (`internal/protocol/protocol.go`), so a signature cannot be transplanted across intents or have its
  parameters or window altered.

- **Clock skew is a boundary, and it fails closed.** The validity window is checked against the local
  clock only; a privileged intent refuses beyond five minutes of measured skew *before* the window check,
  so a wrong clock names itself instead of masquerading as expiry; `serverTime` is used solely for
  display (`internal/agent/execute.go`).

- **Replay is refused, and the nonce is recorded only after the signature verifies** — so a garbage-
  signature job cannot burn a genuine job's nonce — and the record is persisted before the caller acts
  (`internal/agent/nonces.go`).

- **The canonical encoder is unambiguous where it needs to be:** keys sorted by code point, floats
  rejected outright, integers required to fit `int64` (no silent truncation), HTML escaping deliberately
  undone, and non-UTF-8 refused (`internal/canonical/canonical.go`). (See F-05 for a doc/code caveat about
  where this encoder is applied.)

- **The NoCloud seed injection path is closed.** The only control-plane value written into cloud-init's
  `meta-data` is the host id, constrained to `^[0-9A-Za-z]+$` at ≤64 bytes
  (`internal/protocol` `ValidHostID`), so the `public-keys` YAML-injection route into `authorized_keys`
  cannot be reached; the seed body is the signature-covered template, and the seed is removed after
  cloud-init consumes it (`internal/agent/bootstrap.go`).

- **Tenant isolation is enforced by the database.** All ten tenant-owned tables (`hosts`, `jobs`,
  `job_results`, `certificates`, `enrollment_tokens`, `templates`, `events`, `unit_transitions`,
  `alert_rules`, `alert_states`) have row-level security `ENABLE`d **and** `FORCE`d
  (`internal/store/migrations/0004`–`0006`); scoped statements run inside a transaction that
  `SET LOCAL`s `farrier.tenant`; and `farrier-server` refuses to start on a superuser or `BYPASSRLS` role
  (`cmd/farrier-server/main.go` `requireRowLevelSecurity`, `internal/store/postgres_role.go`).

- **The alerting path cannot create a job**, the routine tier cannot express a reboot, no managed-host
  binary links a signing backend, and the root helpers grow no `--policy`/`--exec` flag — each asserted
  by a source-level guarantee test (`internal/intent/source_guarantee_test.go`). See F-02/F-03 for the
  completeness limits of the `execve` guard specifically.

- **The agent's systemd unit** sets all eight directives that imply `NoNewPrivileges`, empties both
  capability sets, and confines writes to two paths (`packaging/farrier-agent.service`).

---

## 4. Findings

Each finding is anchored to code that was read. Unless stated otherwise, none breaches the §1 guarantee,
and the "Impact" line says why.

### Medium

#### F-01 — Release pipeline runs unpinned actions and `nfpm@latest` in the code-signing path
**Area:** packaging / CI · **Location:** `.github/workflows/release.yml:121,218` (also `security.yml:45,72,88`, `ci.yml:186`)

The release workflow's `build` job installs the tool that produces the shipped `.deb` with
`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest` (`release.yml:121`), and the `publish` job that
signs and ships it uses `softprops/action-gh-release@v2` and other third-party actions pinned to mutable
tags rather than commit SHAs. `nfpm`'s output is the artifact the publish job signs with the APT archive
key and every enrolled host installs and runs as root during `apt-get upgrade`.

**Failure scenario.** An attacker who publishes a malicious `nfpm` release — or who force-moves the `v2`
tag of a pinned action to compromised code — gets execution inside the release runner and can inject a
malicious `postinst` maintainer script into the signed `.deb`, which then runs as root on every host.

**Impact.** This is the release supply-chain adversary named in `docs/SECURITY.md` §9 and `CODEOWNERS`,
not the §1 control-plane one; §1 is not breached. But the blast radius (root on the whole fleet, via the
one trusted distribution channel) is why it is the highest-severity finding here.

**Recommendation.** Pin every third-party action to a full commit SHA (version in a trailing comment) and
pin `nfpm` to an exact, checksum-verified version rather than `@latest`.

### Low

#### F-02 — The `execve` guarantee test does not cover `x/sys/unix` or raw `syscall`
**Area:** guardrail-test completeness · **Location:** `internal/intent/source_guarantee_test.go:170-190`, `.golangci.yml:46`

`TestGuaranteeNoCodePathReachesAShell` — the mechanical form of "no expression in the repository can
become the thing that runs" — recognises an exec site only by matching the fixed selectors `exec.Command`,
`exec.CommandContext`, `syscall.Exec`, `syscall.ForkExec`, `os.StartProcess`. It does not match
`golang.org/x/sys/unix.Exec`/`Execve`/`Fexecve` or a raw `syscall.Syscall(SYS_EXECVE, …)`. The `depguard`
backstop denies only the `os/exec` and `x/crypto/openpgp` *imports* — not `golang.org/x/sys/unix` (already
an indirect dependency, `go.mod`) nor `syscall` (already imported in shipped files). The companion text
scan matches only the literal substrings `/bin/sh`, `/bin/bash`, `sh -c`, `bash -c`.

**Failure scenario.** A future or supply-chain-poisoned commit adds, in shipped code,
`unix.Exec(shell, []string{shell, "-c", cmd}, env)` with non-literal `shell`/`cmd`. `make guarantee`
passes green: the AST switch does not match `unix.Exec`, `depguard` does not deny `x/sys/unix`, and the
text scan sees no literal shell fragment. The one check that exists to prove no path reaches a shell
reports success while a general remote-execution primitive has been introduced. (The `&exec.Cmd{…}`
struct-literal route the audit also considered *is* caught, because it still imports `os/exec`.)

**Impact.** No current code does this; introducing it requires a hostile or careless commit that is itself
the breach. Defense-in-depth only.

**Recommendation.** Add `golang.org/x/sys/unix` to the `depguard` deny list (mirroring `os/exec`) so the
import is refused everywhere except an audited file, and extend the AST check to flag `unix.Exec*`, raw
`syscall.Syscall*`/`RawSyscall*`, and `exec.Cmd` composite literals — failing closed on unrecognised exec
shapes.

#### F-03 — The `execve` scan silently skips a scanned root that no longer exists
**Area:** guardrail-test completeness · **Location:** `internal/intent/source_guarantee_test.go:19,101-104`

The scan iterates a hardcoded `scannedRoots = {"cmd","internal","helpers"}` and, per root, `continue`s
when the directory is absent — a missing root is silently skipped, not a test failure. Production code in
any new top-level directory is never scanned, and relocating process-spawning code out of the three roots
loses coverage with nothing red. This is the one guarantee test in the file *without* the loud-failure
tripwire its siblings have (`TestGuaranteeRootHelpersTakeNoPolicyPath` asserts exactly three helper dirs;
the backend and alert tests `t.Fatalf` on a missing listed path).

**Impact.** A refactor moving spawn code to a new package would lose exec-scan coverage silently (though
`depguard`'s module-wide `os/exec` deny still backstops that one route). Defense-in-depth.

**Recommendation.** `t.Fatalf` on a missing root, and derive the scanned set from the actual package
layout (as `moduleImportGraph` already does) rather than a fixed three-element list.

#### F-04 — Agent does not fail closed on a signed privileged job with an unbounded validity window
**Area:** signing / replay · **Location:** `internal/agent/execute.go:102-107,240-245`, `internal/agent/nonces.go:90-92`

Three independent replay defenses each degrade silently to "no bound" when a signed job's times are the
zero value: (1) the window check is guarded by `!job.NotBefore.IsZero()`/`!job.NotAfter.IsZero()`, so a
zero `notAfter` is treated as an open-forever window; (2) `effectiveIssueTime` falls back to the
control-plane-chosen, *unsigned* `issuedAt` when `notBefore` is zero, so `max_job_age_seconds` (checked on
both the agent and, via the forwarded value, the root helper) no longer bounds anything; (3)
`NonceStore.Check` defaults an entry's expiry to `now+24h` when `notAfter` is zero, so the replay record
is forgotten after 24 hours. Nothing in `accept()` requires a signed privileged job to carry a non-zero
window; the agent trusts the signer to have bounded it.

**Failure scenario.** If a genuinely offline-signed `host.reboot`/`service.stop` job with `notAfter = 0`
ever exists, the compromised control plane can capture it and — once the window check passes forever, the
age limit measures from an attacker-chosen `issuedAt`, and the nonce is pruned after 24h — redeliver that
validly-signed destructive job indefinitely, achieving a replayable reboot without holding the offline
key.

**Impact.** Not reachable through the shipped tooling: `cmd/farrier/sign.go` always sets both bounds and
rejects `--valid-for ≤ 0`, and the §1 attacker cannot mint a destructive signature. Defense-in-depth — but
the guarantee then rests on signer discipline the agent does not verify, and the existing test only covers
an *unsigned* read job.

**Recommendation.** In `accept()`, refuse any job that requires a signature but whose signed `notBefore`
or `notAfter` is the zero time; treat a zero expiry in `NonceStore.Check` as an error for a privileged
job; add a guarantee test that a signed destructive job with zero `notAfter` is refused. One check closes
all three degradations at once.

#### F-05 — `canonical.Normalize` is unused; verification runs over a re-encoding of the decoded view
**Area:** signing (cross-cutting) · **Location:** `internal/canonical/canonical.go:58-62`, `internal/agent/execute.go:177,215`, `internal/protocol/protocol.go:361-375`

`canonical.Normalize` is documented as existing "because the agent … must canonicalise exactly what
arrived, not a re-encoding of its own decoded view … the difference is exactly where a signature-
verification bug would live." No production code calls it. Every signer and verifier instead calls
`canonical.Marshal` on a Go value reconstructed from decoded fields (`Job.SignedPayload`), i.e. the very
"decoded view" the doc says must not be trusted.

**Failure scenario.** If a signer's canonicaliser and the agent's JSON decoder ever disagreed on a value
that re-encodes differently (a params integer outside `float64`'s exact range, a non-ASCII string form),
both sides would sign over their own re-encoding rather than over identical arrived bytes, masking the
discrepancy instead of catching it.

**Impact.** Because both signer and verifier share `SignedPayload`, and because destructive jobs require
an offline key the attacker lacks, the only reachable outcome is a *false reject* (fail-closed), never
acceptance of a tampered job — so §1 is not breached. But the documented anti-ambiguity property is not
the property the code provides, and no dedicated auditor covered this subsystem.

**Recommendation.** Either wire `Normalize` into the verification path (verify against the canonical form
of the bytes as they arrived) or correct the `canonical.go` doc to describe what the code actually does,
and add a fuzz test that a payload whose re-encoding differs from its arrived form cannot verify. Remove
`Normalize` if it is genuinely dead.

#### F-06 — Offline signature is enforced only in the unprivileged agent; the root boundary re-checks policy, not signature
**Area:** privilege boundary (cross-cutting) · **Location:** `internal/helper/helper.go:77-119,241-297`, `internal/agent/execute.go:117-126,437-446`

The `privsep.Request` crossing the socket carries `{JobID, Intent, Params, IssuedAt}` and no signature.
The helper re-decodes parameters, re-reads local policy, authenticates the peer by `SO_PEERCRED`, and
checks the intent's endpoint matches the socket — but nothing at the root boundary verifies the offline
`trusted-signers` signature that `docs/SECURITY.md` §1/§2.3 make the sole gate distinguishing a
destructive job *authorised* by an offline key from one merely *requested*. That verification exists at
exactly one place: `verifyOfflineSignature()` in the agent process.

**Failure scenario.** An attacker with code execution as the `farrier` user (or `farrier`-group
membership, which owns the `0660` helper sockets) — a capability §1 assumes absent but §9 discusses — can
connect directly to `reboot-host.sock` and invoke `host.reboot` with no signature; the helper performs it
if local policy permits reboot, because it never asks for one.

**Impact.** This does not exceed local policy (the helper still enforces `min(request, policy)`), so it is
not a §1 violation and is consistent with §2.2's stated position that *policy*, not the signature, is what
survives a compromised agent. But the offline-signature control has a single enforcement point in the
process the design treats as least trusted, and a future refactor that let a job reach the socket without
passing `accept()` would breach §1 with nothing behind it.

**Recommendation.** State this design choice explicitly in `docs/SECURITY.md` §6 and in `internal/helper`
(so it is a reviewed decision, not an unexamined gap), and add a guarantee test asserting the socket
request struct carries no field an agent could use to smuggle authorisation. Consider whether the helper
should attest that it performed no signature check.

#### F-07 — Helper's local `max_job_age` check is caller-controlled; the comment claims it fails closed
**Area:** policy / doc-code mismatch · **Location:** `internal/privsep/privsep.go:185-190`, `internal/policy/decide.go:154`

`decide.go` gates the age check on `if !req.IssuedAt.IsZero()` and measures `env.Now.Sub(req.IssuedAt)`;
the helper takes `IssuedAt` verbatim from the socket. The `Request.IssuedAt` doc comment asserts a lying
caller "could only make a job look older than it is, which fails closed." That is false both ways: a zero
`IssuedAt` skips the check entirely, and `IssuedAt = now` makes an arbitrarily old job pass.

**Impact.** No privilege is gained: `effectiveIssueTime` substitutes the signed `notBefore` for signed
jobs (`execute.go`), so the honest-agent + compromised-control-plane model is defended, and the gap only
matters for a compromised agent, which can already mint an equivalent fresh request. The comment is
nonetheless actively misleading — a future maintainer could rely on an independent age bound that is not
there.

**Recommendation.** Correct the comment to match `execute.go`'s honest account, and consider refusing a
zero `IssuedAt` on a privileged request in the helper.

#### F-08 — Zero-length maintenance window silently expands to a full 24 hours
**Area:** policy / correctness · **Location:** `internal/policy/window.go:89-92`

`ParseWindow` computes `length := end - start` and adds 24h when `length <= 0`. This is correct for
midnight-crossing windows and the intentional always-open idiom, but it also turns any window whose end
equals its start — e.g. a typo `Sun 03:00-03:00` — into a 24-hour window, accepted by `validate()` without
warning.

**Failure scenario.** An operator intending a narrow Sunday reboot slot writes `Sun 03:00-03:00` and gets
a window open Sunday 03:00 through Monday 03:00; combined with `reboot = "window"`, a compromised control
plane holding a validly signed reboot job can execute it any time in that span.

**Impact.** Not a §1 violation — `min(request, policy)` still holds and the file simply says more than the
operator meant. A silent parse edge that matches too much.

**Recommendation.** Reject an equal start/end range at parse time (require the always-open case to be
written explicitly), or at minimum document the expansion in the `ParseWindow` doc comment.

#### F-09 — Apply-once bootstrap interlock uses check-then-write, not an atomic `O_EXCL` create
**Area:** bootstrap · **Location:** `internal/agent/bootstrap.go:105`, `internal/agent/enroll.go` (`checkBootstrapInterlock`)

The "exactly once" interlock reads the record file early, then writes it later via `WriteFileAtomic`
(rename-over, last-writer-wins) rather than an exclusive create. Within a single sequential enrolment this
is airtight and crash-safe. It does not defend against two concurrent `farrier enroll --bootstrap X`
processes sharing one `StateDir`: both can read "no record", both pass, and both drive cloud-init.

**Failure scenario.** An automation script launches two enrolments against the same `StateDir` at nearly
the same instant, each holding a distinct single-use token naming template `X`; both pass the interlock
and `X`'s cloud-init `user-data` is applied twice.

**Impact.** Does not breach §1(a–c) — the template is still operator-signed and operator-named — but it
weakens the §7 "applied at most once" guardrail. Requires an unusual concurrent configuration.

**Recommendation.** Write the record with `O_CREATE|O_WRONLY|O_EXCL` (still fsyncing file and directory)
so a second concurrent applier fails deterministically.

#### F-10 — Full bootstrap body is written to the systemd journal at INFO
**Area:** bootstrap / info-disclosure · **Location:** `internal/agent/enroll.go:391-392`

`verifyBootstrap` logs the entire signed template body at `slog` INFO (`"body", bootstrap.Body`), which
persists in journald. This diverges from the `provision` package's own doc (`render.go:13-15`), which
states rendered output is a credential and is "never written to a log line or an audit entry." A bootstrap
template legitimately carries static credentials (a `hashed_passwd` for a break-glass account, an
`ssh_authorized_keys` block — exactly the shapes `provision.Warnings` flags).

**Impact.** Bounded: the journal is root-only, and the same body also reaches
`/var/lib/cloud/…/user-data.txt` on disk, so no new trust boundary is crossed — but it is a longer-lived,
root-readable copy of credential material. Does not affect §1(a–c).

**Recommendation.** Log name/version/signer/body-length (or digest) at INFO and gate the verbatim body
behind DEBUG, or omit it — the fsynced permanent record already holds the verbatim body for audit.

#### F-11 — `enrollment_tokens` RLS `WITH CHECK` keeps the `resolve_key` disjunct the certificates policy dropped
**Area:** tenant isolation · **Location:** `internal/store/migrations/0004_tenants.sql:244,250-251`

The two bootstrap tables carry asymmetric row-level-security write checks. `certificates_tenant_isolation`
restricts `WITH CHECK` to `tenant_id = current_setting('farrier.tenant', true)` only — the `resolve_key`
exemption lives solely in `USING` (reads). `enrollment_tokens_tenant_isolation` keeps the
`OR hash = current_setting('farrier.resolve_key', true)` disjunct in `WITH CHECK` as well, with no comment
explaining the difference. Today this is inert: the only setter of `farrier.resolve_key`
(`withResolveKey`) issues `SELECT`s exclusively.

**Failure scenario.** A later change that adds any `INSERT`/`UPDATE` on `enrollment_tokens` inside a
`withResolveKey` transaction (a "touch last-seen" optimisation, say) would run with `farrier.tenant`
lapsed to `''`; the policy would then admit a row whose `tenant_id` is any value the writer chose as long
as its `hash` equals the resolve key — a cross-tenant write with no database-level refusal.

**Impact.** Latent; no current path reaches it, so §1 is not breached. But `WITH CHECK` is precisely the
guard a future writer would rely on, and here it is weaker than its sibling for no stated reason.

**Recommendation.** Tighten the `enrollment_tokens` `WITH CHECK` to the tenant predicate only, matching
`certificates`, and comment both policies that the `resolve_key` exemption is read-only and must never
appear in `WITH CHECK`.

#### F-12 — The empty-tenant-id invariant is enforced only in Go, not by a schema `CHECK`
**Area:** tenant isolation · **Location:** `internal/store/postgres.go:377-380`, `internal/store/migrations/0004_tenants.sql:34`

`CreateTenant` refuses an empty id in Go, and its own comment explains why this is load-bearing: once a
pooled connection has set and let `farrier.tenant` lapse, `current_setting('farrier.tenant', true)`
returns `''` for the connection's life, so a tenant whose id were `''` would be the single row reachable
by a statement that named no tenant — including every `withResolveKey` lookup. The `tenants` table has no
`CHECK (id <> '')`, so the whole invariant rests on one Go guard, against the codebase's own stated
principle that isolation is "enforced by PostgreSQL, not by remembering."

**Failure scenario.** Any future `INSERT` into `tenants` that bypasses `CreateTenant` — a maintenance
script, a data-import migration, a refactor dropping the check — creates an `id = ''` tenant; from then
on, every `withResolveKey` lookup on a connection whose `farrier.tenant` has lapsed matches that tenant's
whole table via `tenant_id = ''`. The failure is invisible: nothing errors, the wrong rows simply become
readable.

**Impact.** Latent; not a current §1 breach.

**Recommendation.** Add `CONSTRAINT tenants_id_nonempty CHECK (id <> '')` in a migration, so the invariant
is enforced by the database rather than by every future writer remembering.

#### F-13 — Tenant event webhook: no SSRF guard, plaintext `http` allowed, follows redirects
**Area:** control plane / notify · **Location:** `internal/notify/notify.go:76-111`, `internal/server/tenantapi.go:156,214-216`

A tenant's `WebhookURL` is stored verbatim (no `url.Parse`, no scheme allowlist, no target restriction),
and `NewWebhook` uses a default `http.Client` that accepts any scheme and follows up to ten redirects. The
control plane then POSTs event JSON (hostnames, job summaries, operator principals) to it. This directly
contradicts the discipline the sibling SMTP sink enforces for the *same data*: `smtp.go` refuses plaintext
because "an alert email legitimately carries hostnames and failure text," yet the webhook path will POST
that data to an `http://` URL in cleartext, or to an internal address such as `http://169.254.169.254/`,
or follow a `302` from a configured endpoint onward to an internal host. The SSRF is blind (only the
status code is read).

**Failure scenario.** An actor holding a platform token PATCHes a tenant with
`webhookUrl = http://10.0.0.5:8080/…` or a metadata address; every subsequent event drives an outbound
request to the internal target, and a returned redirect steers it onward — a blind internal request-
forgery primitive the SMTP sink was designed to deny. Separately, a benign operator setting an `http://`
webhook silently ships fleet hostnames and failure text in cleartext.

**Impact.** Webhook configuration is platform-operator-only (`requirePlatform`), an actor §1 already grants
full control-plane ownership, so the SSRF adds no capability against §1. The genuine residual risk is
(a) cleartext leakage for a benign operator, and (b) a request-forgery primitive if webhook configuration
is ever exposed at a privilege below full ownership (which `docs/SECURITY.md` §5.1's "a tenant owns … its
own event webhook" language arguably anticipates).

**Recommendation.** Give the webhook the SMTP sink's transport discipline: require `https` at set time,
set `CheckRedirect` to refuse redirects (or re-validate each hop), and optionally block
loopback/link-local/private destinations unless an installation opts in.

#### F-14 — `POST /agent/v1/renew`: no rate limit, no per-host certificate cap, superseded cert never retired
**Area:** control plane / auth · **Location:** `internal/server/agentapi.go:579-612`, `internal/store/postgres.go:751`

`handleRenew` issues a fresh 90-day certificate and inserts a new `certificates` row on every call. Only
`/agent/v1/enroll` is rate-limited; the authenticated agent endpoints, renew included, are not, and there
is no cap on how many live certificates one host may accumulate. The agent rotates keys at renewal, but
the prior certificate is never revoked and remains valid until its natural expiry.

**Failure scenario.** (a) A single valid-cert host loops renew with fresh CSRs, growing the shared
`certificates` table (one physical table for all tenants in hosted deployments) and consuming CA CPU with
no throttle. (b) An attacker who read `agent.pem` at day 10 keeps a fully valid authentication path (to
spoof heartbeats/facts/results for that host, and to consume renewals to extend indefinitely) until the
old cert's day-90 expiry, even after the host has rotated — so key rotation at renewal yields little of
its expected value.

**Impact.** A certificate only lets one impersonate a host *to the server*, never run code *on* a host, so
§1 is not breached (this is the CA-compromise boundary of §4.2/§9). Storage/DoS and a widened leaked-key
window; operator-initiated `RevokeHost` (which revokes all of a host's certificates) remains the intended
mitigation.

**Recommendation.** Apply a modest limiter to the authenticated agent endpoints; cap unexpired
certificates per host and supersede/expire the presented certificate on successful renewal after a short
overlap, so a rotated-away key stops working promptly rather than at day 90.

#### F-15 — Two-person approval silently becomes unsatisfiable under the shipped shared-token auth
**Area:** control plane / correctness · **Location:** `internal/store/postgres.go:872`, `internal/auth/auth.go:74,231-248`

The distinct-operator rule is enforced correctly and race-free in `ApproveJob`'s `UPDATE`
(`… (NOT approval_distinct_operator OR created_by <> $3)`), but distinctness compares
`auth.Identity.Principal()` = `Provider:Subject`. The built-in `StaticToken` is a single shared bearer
token that yields a constant `Principal` for every operator in a tenant. Under `approvalMode =
second_person`, every job's `created_by` therefore equals every would-be approver's principal, and the
`WHERE` clause can never match.

**Failure scenario.** A tenant enables `second_person` on the shipped static-token auth; every destructive
job sits in `awaiting_approval` forever, and `handleApproveJob` returns `self_approval` to whoever tries.
The control fails *closed* (safe), but is unusable — and an operator who enabled it may believe a second
person is enforcing review when the tier is simply unreachable.

**Impact.** No breach (fails closed), but the guarantee's approval story rests on `Principal()` being
genuinely per-person, and any future provider returning a constant subject for a group would degrade it
further.

**Recommendation.** Refuse to enable (or loudly warn on) `second_person` when the active auth provider
cannot furnish distinct per-operator principals; document that `second_person` requires a real identity
provider via the `auth.Provider` seam. Keep the atomic store check as the enforcement point.

#### F-16 — Traefik UI-hostname agent-API deny router uses a fixed priority a long hostname can outrank
**Area:** deploy · **Location:** `deploy/compose.traefik-ui.yaml:62`

On the interface hostname, the `farrier-ui-no-agents` router (`Host(UI) && PathPrefix(/agent)`, which
403s the agent API) is given a fixed `priority: 100` to outrank the general `farrier-ui` router, which
uses Traefik's default rule-length priority. A UI hostname of roughly 90+ characters (legal DNS names go
to 253) makes the general router's computed priority exceed 100, so it wins for `/agent` paths and the 403
middleware silently stops applying.

**Failure scenario.** An operator deploys with a long interface hostname; `https://<long-ui-host>/agent/v1/…`
is routed to `farrier-server` instead of being 403'd at the proxy.

**Impact.** Bounded: Traefik terminates TLS on this hostname and reconnects to the server *without* a
client certificate, so the agent endpoints still return 401 (the fingerprint lookup, not the proxy, is the
real control). §1 is not breached — but the intended belt-and-braces layer fails silently, the exact
"plausible-looking but off" failure the project avoids elsewhere.

**Recommendation.** Set the deny router's priority above any legal-hostname rule length (e.g. the Traefik
maximum), or leave both routers at default priority so the strictly longer rule always wins.

#### F-17 — `release.yml` grants `contents: write` to the build job that only needs read
**Area:** CI / hardening · **Location:** `.github/workflows/release.yml:24`

Permissions are declared once at workflow level as `contents: write` and inherited by both jobs. The
`build` job only checks out, compiles, and uploads an artifact — it needs `contents: read`. Only `publish`
needs write.

**Failure scenario.** A compromised build-time tool in the build job (see F-01) uses the ambient
`GITHUB_TOKEN` to push a tag or alter release assets, widening a build-step compromise into repository
write.

**Impact.** Outside §1; least-privilege hardening.

**Recommendation.** Set `permissions: contents: read` at workflow level and grant `contents: write` only on
the `publish` job.

### Informational

#### F-18 — `run.Systemctl` is in the runtime allowlist with zero callers
**Location:** `internal/run/run.go:77,100`

`/usr/bin/systemctl` is in the executable allowlist but has no call site in shipped code (unit state is
read over D-Bus; start/stop/restart go over D-Bus in `restart-unit`). An allowlisted, flag-rich program
with no user is latent execution surface: the day a caller is added, `systemctl` becomes runnable and that
caller's argv discipline becomes security-relevant. **Recommendation:** remove it from the allowlist until
a concrete D-Bus fallback caller lands in the same commit — `TestGuaranteeTheAllowlistHoldsNoInterpreters`
already pins the set, so shrinking it costs nothing and keeps the executable set equal to the reachable
set.

#### F-19 — Unauthenticated `/healthz` runs a tenant-list query per request and discloses build version
**Location:** `internal/server/server.go:665-681`

`handleHealth` is unauthenticated and, on every hit, runs `ListTenants` against the database and returns
the exact version and git commit, with no rate limit. **Recommendation:** use a cheap liveness probe
(`SELECT 1` or a cached bit), consider dropping version/commit from the unauthenticated body, and
rate-limit the endpoint.

#### F-20 — TLS listener floor is 1.2 with no cipher-suite pinning
**Location:** `internal/server/server.go:342-350`

`MinVersion: tls.VersionTLS12` with `CipherSuites` unset offers Go's default 1.2 suites (including
ECDHE-AES-CBC-SHA) on the listener carrying agent mTLS and the operator UI. Risk is genuinely low — the
connection is mutually authenticated against a private CA, so a downgrade cannot forge a client
certificate the fingerprint lookup accepts. **Recommendation:** raise the agent protocol to TLS 1.3
(agents and server share the codebase, so compatibility is controlled), or pin an AEAD-only suite list;
document the chosen floor in `docs/SECURITY.md` §4.2.

#### F-21 — Invalid event kinds are logged but still delivered
**Location:** `internal/server/eventsapi.go:180-184`, `internal/notify/notify.go:23-24`

`record()` checks `notify.Kind(ev.Kind).Valid()` only to emit `slog.Error` before recording, broadcasting
and delivering the event anyway. The closed vocabulary is enforced by compile-time constant usage and a
source test, not structurally at the emit boundary. A future caller that derived `Kind` from a field would
ship an out-of-vocabulary kind that dashboards and webhook filters miss, with only a log line as evidence.
**Recommendation:** reject (drop or coerce) an event whose kind is not `Valid()` at `record()`, matching
how intents are refused rather than warned about.

---

## 5. Prioritised remediation

1. **F-01 / F-17** — pin CI actions and `nfpm` to SHAs/exact versions and scope the build token to read.
   This is the one finding whose adversary reaches the whole fleet with root.
2. **F-02 / F-04 / F-06** — close the three "single point of enforcement" gaps with the checks each
   recommends (deny `x/sys/unix`; refuse an unbounded signed window; document and test the root boundary's
   signature posture). Each is a one-to-few-line change that makes a protection independent of future
   discipline.
3. **F-11 / F-12** — move two tenant-isolation invariants from Go/asymmetric-policy into database
   constraints, matching the project's own "enforced by PostgreSQL, not by remembering" principle.
4. **F-13 / F-14 / F-15** — give the webhook the SMTP sink's transport discipline; rate-limit and cap
   certificate renewal; guard `second_person` against a shared-principal auth provider.
5. **F-03, F-05, F-07 through F-10, F-16, F-18 through F-21** — correctness, doc/code-mismatch, and
   hardening items; fold into normal maintenance.

---

## 6. Conclusion

Farrier's central claim — that an attacker who owns the control plane cannot run code on an enrolled host,
exceed its local policy, or reboot it against that policy — holds in the code, and the mechanisms that
make it hold are unusually well factored and unusually well tested. The findings here are not cracks in
that guarantee; they are places where a protection sits in one location where the project's own standards
would put it in two, or where a guardrail test recognises the shapes of a threat it has seen but not the
next one. Closing them keeps the guarantee mechanically enforced rather than conventionally observed,
which is the property the whole design is organised around.
