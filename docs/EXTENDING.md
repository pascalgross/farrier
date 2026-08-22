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
    UpgradablePackages() ([]Package, error)
    SecurityOrigins() []string
    RebootRequired() (bool, []string, error)
    SubscriptionStatus() (*Subscription, error) // Ubuntu Pro / ESM; nil where not applicable
}
```

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

Register in `internal/collect/collector`. Keep the output bounded — see
[`PROTOCOL.md` §4.5](PROTOCOL.md#45-bounds).

### `signing.Signer` — a key backend

```go
// Signer produces a detached signature over the canonical job payload.
type Signer interface {
    KeyID() string
    Algorithm() Algorithm
    Public() crypto.PublicKey
    Sign(ctx context.Context, payload []byte) ([]byte, error)
}
```

Shipped: `file`, `sshagent`, `pkcs11`, `gpgagent`, `kms`. Deliberately no vendor is hard-coded —
`pkcs11` covers YubiKey PIV, Nitrokey and SoftHSM alike, and `kms` covers AWS, GCP and Azure.

**This is the seam that is safest to leave open, and it is worth understanding why: the verifier never
changes.** The agent only ever sees a public key and a signature over a canonical payload. It cannot
learn — and does not care — which backend produced the signature. Adding a backend is therefore purely
client-side and cannot widen the agent's attack surface by even one branch.

Two algorithms exist on the wire: `ed25519` (the default) and `ecdsa-p256`. ECDSA is present because
YubiKey PIV before firmware 5.7.0 and several cloud KMS offerings cannot do Ed25519 at all. Carrying
one algorithm tag now is much cheaper than rewriting every host's `trusted-signers` later.

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

### Angular UI panels

Standalone components registered into the host-detail panel registry. UI extensions read the API; they
cannot reach hosts.

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
   re-enforces `/etc/farrier/policy.toml` itself. It does not get a new helper.
6. Add the policy knob that lets a host refuse it. Every privileged intent must be refusable locally,
   or the guarantee is no longer true.
7. Document it in `SECURITY.md` §3 and `PROTOCOL.md`.

Steps 4 through 6 are where most proposals stop, and that is the process working.
