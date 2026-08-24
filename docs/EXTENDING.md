# Extending Farrier

Farrier is extensible in specific, named places and closed everywhere else. This document lists both,
because "where can I add things" and "where will my pull request be rejected" are the same question
and it is rude to answer only the first half.

The governing rule: **extension means adding an implementation, never editing a `switch`.** If adding
support for something requires you to modify a type switch, an `if` chain, or a lookup table in the
core, that is a missing seam and a legitimate bug report.

The governing constraint: **nothing added at run time may cause code to run on a managed host.** Every
open seam below either runs on the operator's machine, runs in the server, or is compiled into the
agent from source.

---

## Open seams

### `collect.Platform` — a distribution family

```go
// Platform is the per-distribution-family behaviour that fact collection depends on.
type Platform interface {
    Identify() (Distribution, error)
    UpgradablePackages(ctx context.Context) ([]Package, error)
    SecurityOrigins() []string
    RebootRequired(ctx context.Context) (RebootReport, error)
    SubscriptionStatus(ctx context.Context) (*Subscription, error) // nil where not applicable
}
```

Three of these take a context, because they start a process — `apt-get`, `needrestart`, `pro` — and a
heartbeat that could not be cancelled would hold the agent open behind a hung package manager.
`RebootRequired` returns a `RebootReport` rather than a bare boolean and a list, because the answer has
four parts: whether a reboot is needed, which packages need it, which services still hold replaced
libraries, and whether the scan that produced that last list could see every process.

Add a file under `internal/collect/platform/`, implement the interface, register it in that package's
detection function. Farrier ships `ubuntu` and `debian`.

Four differences between families are already known to produce **silent wrong answers** rather than
errors, so any new implementation must state what it does about each:

| Difference | The silent failure |
| --- | --- |
| Security-origin patterns (`${distro_id}:${distro_codename}-security` on Ubuntu, `origin=Debian,codename=${distro_codename}-security` on Debian) | The security/regular split is quietly wrong — the one number the product exists to show |
| `/var/run/reboot-required` is an Ubuntu `update-notifier` convention, not a Debian one | Reboot-required silently reads as `false` forever. Treat the marker file as one input, never as the answer; on Debian, `needrestart` is the reliable source |
| Ubuntu Pro and Livepatch do not exist on Debian | An empty amber "unknown" badge on every Debian host teaches operators to ignore the dashboard. Render "not applicable" |
| `apt-check` lives in `update-notifier-common`, absent from minimal images of both | Zero upgrades reported on exactly the hosts most likely to be forgotten. The simulation parse is the primary path; `apt-check` is an optimisation |

### `collect.Collector` — a new fact

```go
// Collector produces one named section of a host's fact report.
type Collector interface {
    Name() string
    Collect(ctx context.Context) (any, error)
}
```

Collectors are read-only by construction and run as the unprivileged `farrier` user with no
capabilities. A collector that needs root is not a collector; it is a request for a new intent, which
is a different and much longer conversation.

Add a file under `internal/collect/collector` with a `Register` call in its `init`, and nothing else in
the codebase learns about it. Output appears under the collector's name in the facts document's `extra`
object. Farrier ships two.

`network` is also what justifies `AF_NETLINK` in the systemd unit's `RestrictAddressFamilies`:
`net.Interfaces` uses a netlink socket on Linux and returns nothing without it, silently.

`containers` reports Docker container state from `/proc` and the cgroup tree, and it is the one that
shows what the optional half of this seam is for:

```go
// PolicyGated is the optional half of the Collector seam, for a section a host may refuse to send.
type PolicyGated interface {
    PermittedBy(p policy.Policy) bool
}
```

Implement it when a section is a disclosure a host might reasonably decline, and `Gather` will ask
before collecting. Most facts are not: a unit list and a package count say nothing a hostname does not.
Container state is, which is why `[containers] report` ships `false`. A refused section is **absent**
rather than empty, and the host's policy travels in the same heartbeat, so a client can say "this host
does not report containers" rather than "this host has none".

The policy is asked of, not read by, the collector. A collector that called `policy.Load` itself would
be reading that file a second time on its own schedule, with no guarantee of agreeing with the policy
the rest of the agent is enforcing at that moment — and a fact reported under a permission that was
withdrawn two minutes ago is a permission that was not withdrawn.

Keep the output bounded — see [`PROTOCOL.md` §4.5](PROTOCOL.md#45-bounds) — and stable. The name becomes
a key in a document that is digested, stored and compared, so renaming one makes every host in a fleet
look changed on the same afternoon. A collector that fails leaves its section absent rather than empty:
"no network interfaces" is a very different claim from "the network collector failed".

### `signing.Signer` — a key backend

```go
// Signer produces a detached signature over the canonical job payload.
type Signer interface {
    KeyID() string
    Algorithm() Algorithm
    Public() crypto.PublicKey
    Backend() string
    Sign(ctx context.Context, payload []byte) ([]byte, error)
    Close() error
}
```

Implemented today:

| Backend | What holds the key |
| --- | --- |
| `file` | A passphrase-protected key file: scrypt over the passphrase, NaCl secretbox over a PKCS#8 key |
| `pkcs11` | Any PKCS#11 module — YubiKey PIV, Nitrokey and SoftHSM through one implementation |
| `kms` | AWS KMS, Google Cloud KMS or Azure Key Vault, over their REST APIs and no vendor SDK |

Specified and not yet written: `sshagent` (including FIDO2 `ed25519-sk`) and `gpgagent`. Deliberately
no vendor is hard-coded: a PKCS#11 key is named with an RFC 7512 URI, which is what every other tool
that talks to a token already speaks, and each cloud gets a scheme rather than a flag.

A backend registers itself with `internal/signing/backend` from its `init`, and `farrier` blank-imports
the ones it ships — the shape `database/sql` uses. `--key` takes a reference, and a reference selects a
backend if and only if it begins with a registered scheme and a colon; everything else is a path, so
`--key ~/.config/farrier/ops.key` keeps meaning what it always did. The parser touches no filesystem:
a rule that depended on what happened to exist on disk would mean different things on two machines.

The registry lives one directory below `internal/signing` so that the agent and the control plane, which
import the verifier, link no backend at all — and after `pkcs11`, which loads a shared library an
operator names, that is asserted rather than reviewed for. See
`TestGuaranteeNoManagedHostBinaryLoadsASigningBackend`. It is not the plugin loader this document
refuses below: that refusal is about the agent, and this is the operator's own tool.

**A backend verifies its own signature before returning it.** Every remote key store gets one encoding
detail differently — a PKCS#11 token returns ECDSA as a raw `r‖s` pair, Azure returns it base64url and
raw, AWS needs the whole payload rather than a digest for Ed25519 — and each mistake produces a
well-formed signature that no host accepts, reported days later as a trust anchor that has stopped
working. `signing.SelfCheck` turns the whole class into an error at the terminal of the person who ran
the command.

**This is the seam that is safest to leave open, and it is worth understanding why: the verifier never
changes.** The agent only ever sees a public key and a signature over a canonical payload. It cannot
learn — and does not care — which backend produced the signature. Adding a backend is therefore purely
client-side and cannot widen the agent's attack surface by even one branch.

Two algorithms exist on the wire: `ed25519` (the default) and `ecdsa-p256`. ECDSA is present because
YubiKey PIV before firmware 5.7.0 and several cloud key stores cannot do Ed25519 at all. Carrying one
algorithm tag now is much cheaper than rewriting every host's `trusted-signers` later, and it is not
hypothetical: **Azure Key Vault has no EdDSA algorithm and no `OKP` key type**, so `ecdsa-p256` is the
only thing a Key Vault key can be. AWS KMS and Cloud KMS can do both, and AWS's Ed25519 has a limit
worth knowing about — pure Ed25519 needs `MessageType: RAW`, which caps a payload at 4096 bytes.

A backend reports what a key can do rather than assuming: the algorithm comes from the key itself, and
one this build cannot carry fails when the key is opened, with a message naming what it actually is.

Whatever the backend, the audit log and the UI always record **which** signer authorised a job:
`ops-laptop (file)` must read differently from `ops-yubikey-1 (PKCS#11)`.

### `notify.Sink` — an outbound notification

```go
// Sink delivers an event to something outside Farrier.
type Sink interface {
    Name() string
    Deliver(ctx context.Context, ev Event) error
}
```

This is the one seam the **server** may extend at run time: an operator can configure a webhook
without recompiling. That is safe because of the asymmetry that governs the whole design —
**sinks send data out; nothing sends code in.**

Three sinks exist: the tenant webhook, SMTP for the recipients an alert rule names, and the browser —
which is not a `Sink` at all but a server-sent-events stream held open by an operator's tab, because a
subscription that vanishes when somebody closes a laptop is not something the `Deliver` contract can
describe. What is durable is neither of those: every event is written to the tenant's inbox before any
delivery is attempted, so best-effort delivery *looks* best-effort rather than turning into silence.

What a sink may deliver is **closed at compile time**, like the intent catalogue and for a related
reason. `notify.Kind` is an unexported-in-spirit set of constants with a test that fails when the set
changes, because a kind is a word operators build webhook filters, mail rules and dashboards on: one
handler spelling it `job.fail` and another `job.failed` is two dashboards that each miss half the
events. Adding a member means editing `internal/notify/kinds.go` and the expected set in
`notify_test.go` in the same commit.

Alerting rules sit on top of the sinks and add nothing to what may leave: a rule decides *which*
events are worth interrupting somebody for and *who*, never what may be done. **A rule produces a
notification. A rule never produces a job** — there is deliberately no code path that could, and
"auto-remediate when more than five updates are pending" is a different feature with a different
argument, not a checkbox on this one.

### `auth.Provider` — operator authentication

```go
// Provider authenticates a human operator against the control plane.
type Provider interface {
    Name() string
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
```

Local accounts, OIDC, SAML. This governs access to the *control plane*, and it is worth being clear
that it is not a security boundary for the guarantee: a compromised administrator account is
explicitly inside the threat model of [`SECURITY.md` §1](SECURITY.md#1-the-guarantee) and still cannot
run code on a host.

### The Angular application

Standalone components and lazily loaded routes, in `web/src/app`. There is no panel registry: it would
be indirection without a reader, and it can be introduced when there is a second thing to register.
Adding a page means a component and a route.

One piece of it is worth knowing before you copy it. The live event feed reads the stream with `fetch`
and a `ReadableStream`, not with `EventSource`, because `EventSource` cannot set a request header and
this API authenticates with a bearer token — the usual workaround puts an operator's credential into
the query string, and from there into every access log and proxy trace it passes. The cost is the
reconnect loop in `core/event-stream.ts`, which `EventSource` would otherwise have supplied.

Whatever it grows into, the UI reads the API and can reach no host directly — it has no credential that
any agent would accept, because agents authenticate the *control plane* by certificate and authorise
work by signature.

---

## Closed on purpose

Each of these has its reasoning in [`SECURITY.md`](SECURITY.md). They are listed again here because
this is the document people read *before* opening the pull request.

### The intent catalogue

Not a registry, not configurable, not loadable. New intents arrive as source changes in a reviewed
pull request, and the `guarantee` CI workflow fails until the expected-set literal is updated in the
same commit — so adding one is impossible to do quietly.

That friction **is the feature**. It is what makes "we ship no remote execution" a property a stranger
can verify by reading one file, rather than a promise about our intentions.

The permanently-refused list is in
[`SECURITY.md`](SECURITY.md#permanently-refused): `shell.exec`, `script.run`, arbitrary `file.write`,
`apt.addRepository`, `user.create`, `ssh.authorizedKeys.add`, `agent.updateFromURL`.

### The three root helpers

`apply-updates`, `restart-unit`, `reboot-host`. There is no fourth one that "runs the configured
command", and none of the three will grow a parameter that names a program.

The agent reaches them over one unix socket each, activated by systemd, and never through `sudo` —
nothing in Farrier is setuid. The routing table in `internal/privsep` is the complete statement of which
intent reaches which helper, and it is checked against the catalogue on every build. Adding a socket, or
widening the group on one of the three, is the same request as adding a fourth helper.

### Runtime plugins in the agent

Never. Any mechanism that loads code into the agent at run time is remote code execution wearing a
plugin API — dlopen, a WASM sandbox, an embedded interpreter, a "safe" expression language that grows
a function call syntax in version two. Agent extension is compile-time only.

### `store.Store`

**Not a seam.** The interface exists so that tests do not need a database. It is not a portability
layer and pull requests adding MySQL or SQLite backends will be declined.

Farrier uses Postgres features that are load-bearing rather than incidental: `JSONB` with GIN indexes
for facts that gain fields constantly, partial indexes for the job claim, `LISTEN`/`NOTIFY` to wake
long-polls without Redis, and `SELECT … FOR UPDATE SKIP LOCKED` for atomic job claiming. Abstracting
those away would mean reimplementing a job queue and a pub/sub system badly, and then shipping a
second one as a dependency — which is precisely the four-service Compose stack this project chose not
to be.

---

## Adding a new intent, if you are sure

This is the process, not an invitation.

1. Open a discussion first. Describe the operational problem, not the operation you want.
2. Write the intent as **typed parameters with a validator**, never a string that gets interpreted.
   If your parameter is a path, a command, a URL or a template, stop.
3. Classify it: `read`, `routine`, or `destructive`. If in doubt it is `destructive`; there is no
   graded tier below that, deliberately.
4. Update `internal/intent`, and update the expected-set literal in the guarantee test in the same
   commit — CI will fail until you do.
5. If it needs root, it goes in one of the three existing helpers, and that helper re-reads and
   re-enforces `/etc/farrier/policy.toml` itself. It does not get a new helper, and it does not get a
   new socket: add it to the routing table in `internal/privsep` naming the helper that already
   performs work of that kind, or the guarantee suite fails.
6. Add the policy knob that lets a host refuse it. Every privileged intent must be refusable locally,
   or the guarantee is no longer true.
7. Document it in `SECURITY.md` §3 and `PROTOCOL.md`.

Steps 4 through 6 are where most proposals stop, and that is the process working.
