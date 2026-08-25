# Independent security audit — Farrier

**Date:** 2026-08-25
**Reviewed:** commit on `claude/security-audit-independent-yyeczm` (branched from `main` at `9916db7`).
**Auditor:** independent review by Claude Code, commissioned by the maintainer. This is an external
assessment, not part of the enforced specification. The specification is
[`docs/SECURITY.md`](docs/SECURITY.md); where the two disagree, that document is authoritative.

Each finding below is tracked as a GitHub issue carrying its full description, failure scenario, impact
analysis and recommendation. This report is the overview and index.

---

## 1. Summary

**No violation of the [`docs/SECURITY.md`](docs/SECURITY.md) §1 guarantee was found.** The three
load-bearing mechanisms — a closed compile-time intent catalogue with a single audited `execve`
chokepoint, local policy sovereignty re-enforced as root in the helpers, and offline job signing against
a host-held trust anchor — hold in the code as written, not merely in the tests that assert them. Tenant
isolation is enforced by PostgreSQL row-level security that is both `ENABLE`d and `FORCE`d on every
tenant table, and the server refuses to start on a role that could see through it.

The audit produced **21 findings, none of which breaks the §1 guarantee.** Their severity is bounded by a
structural fact: §1 already grants the attacker full ownership of the control plane, its database and an
administrator account, so an issue that lets *that* attacker read data, forge an outbound request, or
exhaust a resource on the control plane grants them nothing they do not already have. Every finding is a
**defense-in-depth, hardening, supply-chain, or information-disclosure** issue; the single medium concerns
the *release* supply chain — an adversary the project's own documents (§9, `CODEOWNERS`) place outside §1.

One finding touches the guarantee's own text and is worth stating precisely. F-09 concerns the
apply-once interlock, and "applied **at most once**" is a clause of §1's *second* (enrolment-time)
paragraph — which ships with the first, always — not merely a §7 implementation detail. The interlock is
check-then-write rather than an atomic `O_EXCL` create, so two concurrent enrolments could each apply.
This is still not a §1 break *reachable by the §1 attacker*: winning that race requires two simultaneous
local `farrier enroll --bootstrap` invocations, and the control-plane / database / administrator attacker
of §1 has no server-to-host channel with which to start a process on the host — the absence of that
channel is the product. Each racing application also still passes every §7 guardrail (offline-signed,
name-matched to `--bootstrap NAME`, shown in full, recorded), so a double-apply re-runs the operator's own
approved template rather than anything the attacker chose. F-09 is therefore a genuine idempotency defect
against *operator* concurrency, rated Low, and the "none breaks §1" conclusion holds because the §1
attacker cannot trigger it — not because bootstrap sits outside §1.

| Severity | Count |
| --- | --- |
| Critical (breaks §1) | 0 |
| High | 0 |
| Medium | 1 |
| Low | 16 |
| Informational | 4 |

The recurring theme is **enforcement that lives in one place where the design's own principles would put
it in two**: a signature checked only in the least-trusted process, an invariant held by a Go `if` rather
than a database `CHECK`, a guardrail test that recognises four spellings of `execve` but not the fifth.
None is currently exploitable; each is a place where a single future edit could remove a protection with
no failing test to signal it — the class of issue most worth closing for a project whose distinguishing
claim is mechanical rather than conventional enforcement.

---

## 2. Method

Two independent passes, reconciled:

1. **Direct review of the crown-jewel paths** — the single `execve` site (`internal/run`), the policy
   decision (`internal/policy`, `internal/helper`), canonical encoding (`internal/canonical`), signature
   verification and the acceptance sequence (`internal/signing`, `internal/agent/execute.go`), the NoCloud
   bootstrap seed (`internal/agent/bootstrap.go`), the row-level-security migrations and startup role
   check (`internal/store`, `cmd/farrier-server`), and the agent's systemd hardening.

2. **A ten-dimension fan-out audit**, one auditor per subsystem, each finding then handed to an
   independent adversarial verifier that re-read the cited code and tried to refute it; findings that did
   not survive were dropped. A final completeness critic re-read the subsystem left uncovered and looked
   for cross-cutting gaps.

Severity is rated by impact on the §1 guarantee first. **Not covered:** the test suite / fuzzers / PKCS#11
tests were not run; no dynamic testing, live exploitation, or dependency-CVE sweep; the Angular front end
(`web/`) and the LXD harness (`testfleet/`) were not audited. This is a source review.

---

## 3. What was verified to hold

An audit that reports only defects misleads about a codebase this careful. The following were checked
against the code and **confirmed**:

- **The intent catalogue is genuinely closed** — an unexported compile-time map, no `Register`/plugin/
  config path, total fail-closed `Lookup`/`Decode`; parameters decode through a strict decoder
  (`DisallowUnknownFields`, trailing-data rejection, 8 KiB bound) into typed, per-member-validated structs
  (`internal/intent`).
- **`internal/run` is the only process-spawning site**, guarded by a closed absolute-path allowlist
  checked before `exec`, with a replaced environment, deadline and bounded output. No control-plane value
  reaches an `argv` slice as a flag: unit ops go over D-Bus as typed arguments, the reboot message is
  refused when it begins with `-` and placed after a `--` separator, and the apt argv is constant.
- **Local policy is re-enforced as root, from a packaged constant path** — `internal/helper` re-decodes
  parameters and re-reads `/etc/farrier/policy.toml`; `internal/policy/decide.go` implements
  `effective = min(central, local)` literally, derives the requested level from the intent, re-evaluates a
  requested follow-up reboot *as a reboot*, and refuses any privileged intent it has no rule for. The
  helpers take no `--policy` flag and the socket request carries no path field.
- **The two signature anchors cannot be interchanged** — destructive jobs verify only against
  `trusted-signers`, routine jobs only against the online key, in two separate functions; verification
  dispatches on the *parsed key type* from the root-owned anchor (no algorithm confusion); an empty anchor
  always fails closed; the signed payload binds `{jobId, hostId, intent, params, notBefore, notAfter,
  nonce}`, so a signature cannot be transplanted across intents or have its parameters or window altered.
- **Clock skew fails closed** — the window is checked against the local clock only; a privileged intent
  refuses beyond five minutes of skew *before* the window check. `serverTime` feeds only that skew guard
  (through the derived offset) and the displayed offset; it never enters the window check, so a lying
  server can at most refuse its own privileged jobs, never widen authorisation.
- **Replay is refused, and the nonce is recorded only after the signature verifies** and persisted before
  the caller acts (`internal/agent/nonces.go`).
- **The canonical encoder is unambiguous** — keys sorted by code point, floats rejected, integers bound to
  `int64`, HTML escaping undone. Its `utf8.ValidString` guard in `writeString` is a defensive check that
  cannot fire through the public API: both `Marshal` and `Normalize` route input through `encoding/json`
  first, which coerces invalid UTF-8 to U+FFFD before any string reaches the guard — so non-UTF-8 is
  deterministically sanitised, not refused, and the canonical form stays unambiguous either way. (See F-05
  for the related `Normalize`/re-encoding caveat.)
- **The NoCloud seed injection path is closed** — the only control-plane value in `meta-data` is the host
  id, constrained to `^[0-9A-Za-z]+$` ≤64 bytes, closing the `public-keys` YAML-injection route.
- **Tenant isolation is enforced by the database** — all ten tenant tables have RLS `ENABLE`d **and**
  `FORCE`d; scoped statements `SET LOCAL farrier.tenant` inside a transaction; `farrier-server` refuses to
  start on a superuser or `BYPASSRLS` role.
- **The alerting path cannot create a job**, the routine tier cannot express a reboot, no managed-host
  binary links a signing backend, and the helpers grow no `--policy`/`--exec` flag — each asserted by a
  source-level guarantee test (see F-02/F-03 for its completeness limits).
- **The agent's systemd unit** sets all eight `NoNewPrivileges`-implying directives and empties both
  capability sets.

---

## 4. Findings

Full detail (description, concrete failure scenario, impact, recommendation, `file:line` anchors) is in
each linked issue. None breaches §1.

| ID | Sev | Area | Finding | Issue |
| --- | --- | --- | --- | --- |
| F-01 | **Med** | packaging / CI | Release pipeline runs unpinned actions and `nfpm@latest` in the code-signing path | [#43](https://github.com/pascalgross/farrier/issues/43) |
| F-02 | Low | guardrail test | `execve` guarantee test does not cover `x/sys/unix` or raw `syscall` | [#44](https://github.com/pascalgross/farrier/issues/44) |
| F-03 | Low | guardrail test | `execve` scan silently skips a scanned root that no longer exists | [#45](https://github.com/pascalgross/farrier/issues/45) |
| F-04 | Low | signing / replay | Agent does not fail closed on a signed privileged job with an unbounded validity window | [#46](https://github.com/pascalgross/farrier/issues/46) |
| F-05 | Low | signing | `canonical.Normalize` is unused; verification runs over a re-encoding of the decoded view | [#47](https://github.com/pascalgross/farrier/issues/47) |
| F-06 | Low | priv boundary | Offline signature is enforced only in the unprivileged agent; the root boundary re-checks policy, not signature | [#48](https://github.com/pascalgross/farrier/issues/48) |
| F-07 | Low | policy | Helper's local `max_job_age` check is caller-controlled; the comment claims it fails closed | [#49](https://github.com/pascalgross/farrier/issues/49) |
| F-08 | Low | policy | Zero-length maintenance window silently expands to a full 24 hours | [#50](https://github.com/pascalgross/farrier/issues/50) |
| F-09 | Low | bootstrap | Apply-once interlock uses check-then-write, not an atomic `O_EXCL` create | [#51](https://github.com/pascalgross/farrier/issues/51) |
| F-10 | Low | bootstrap | Full bootstrap body is written to the systemd journal at INFO | [#52](https://github.com/pascalgross/farrier/issues/52) |
| F-11 | Low | tenant isolation | `enrollment_tokens` RLS `WITH CHECK` keeps the `resolve_key` disjunct the certificates policy dropped | [#53](https://github.com/pascalgross/farrier/issues/53) |
| F-12 | Low | tenant isolation | Empty-tenant-id invariant is enforced only in Go, not by a schema `CHECK` | [#54](https://github.com/pascalgross/farrier/issues/54) |
| F-13 | Low | control plane | Tenant event webhook: no SSRF guard, plaintext `http` allowed, follows redirects | [#55](https://github.com/pascalgross/farrier/issues/55) |
| F-14 | Low | control plane | `POST /agent/v1/renew`: no rate limit, no per-host cert cap, superseded cert never retired | [#56](https://github.com/pascalgross/farrier/issues/56) |
| F-15 | Low | control plane | Two-person approval silently becomes unsatisfiable under the shipped shared-token auth | [#57](https://github.com/pascalgross/farrier/issues/57) |
| F-16 | Low | deploy | Traefik UI-hostname agent-API deny router uses a fixed priority a long hostname can outrank | [#58](https://github.com/pascalgross/farrier/issues/58) |
| F-17 | Low | CI | `release.yml` grants `contents: write` to the build job that only needs read | [#59](https://github.com/pascalgross/farrier/issues/59) |
| F-18 | Info | run | `run.Systemctl` is in the runtime allowlist with zero callers (dormant capability) | [#60](https://github.com/pascalgross/farrier/issues/60) |
| F-19 | Info | control plane | Unauthenticated `/healthz` runs a tenant-list query per request and discloses build version | [#61](https://github.com/pascalgross/farrier/issues/61) |
| F-20 | Info | transport | TLS listener floor is 1.2 with no cipher-suite pinning | [#62](https://github.com/pascalgross/farrier/issues/62) |
| F-21 | Info | observability | Invalid event kinds are logged but still delivered | [#63](https://github.com/pascalgross/farrier/issues/63) |

---

## 5. Prioritised remediation

1. **[#43](https://github.com/pascalgross/farrier/issues/43), [#59](https://github.com/pascalgross/farrier/issues/59)** — pin CI actions and `nfpm` to SHAs/exact versions and scope the build token to read. The one finding whose adversary reaches the whole fleet with root.
2. **[#44](https://github.com/pascalgross/farrier/issues/44), [#46](https://github.com/pascalgross/farrier/issues/46), [#48](https://github.com/pascalgross/farrier/issues/48)** — close the "single point of enforcement" gaps: deny `x/sys/unix`, refuse an unbounded signed window, and document/test the root boundary's signature posture. Each makes a protection independent of future discipline.
3. **[#53](https://github.com/pascalgross/farrier/issues/53), [#54](https://github.com/pascalgross/farrier/issues/54)** — move two tenant-isolation invariants from Go/asymmetric-policy into database constraints, matching the project's own "enforced by PostgreSQL, not by remembering" principle.
4. **[#55](https://github.com/pascalgross/farrier/issues/55), [#56](https://github.com/pascalgross/farrier/issues/56), [#57](https://github.com/pascalgross/farrier/issues/57)** — give the webhook the SMTP sink's transport discipline; rate-limit and cap certificate renewal; guard `second_person` against a shared-principal auth provider.
5. **The remaining low and informational items** ([#45](https://github.com/pascalgross/farrier/issues/45), [#47](https://github.com/pascalgross/farrier/issues/47), [#49](https://github.com/pascalgross/farrier/issues/49)–[#52](https://github.com/pascalgross/farrier/issues/52), [#58](https://github.com/pascalgross/farrier/issues/58), [#60](https://github.com/pascalgross/farrier/issues/60)–[#63](https://github.com/pascalgross/farrier/issues/63)) — correctness, doc/code-mismatch and hardening; fold into normal maintenance.

---

## 6. Conclusion

Farrier's central claim — that an attacker who owns the control plane cannot run code on an enrolled host,
exceed its local policy, or reboot it against that policy — holds in the code, and the mechanisms that
make it hold are unusually well factored and unusually well tested. The findings here are not cracks in
that guarantee; they are places where a protection sits in one location where the project's own standards
would put it in two, or where a guardrail test recognises the shapes of a threat it has seen but not the
next one. Closing them keeps the guarantee mechanically enforced rather than conventionally observed,
which is the property the whole design is organised around.
