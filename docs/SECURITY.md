# Security

This document is the specification of Farrier's security posture. It is not marketing copy: every
claim below is either enforced by code with a test in the `guarantee` CI workflow, or explicitly
marked as a boundary that Farrier does **not** defend.

If you find a way to violate the guarantee in [§1](#1-the-guarantee), that is the most serious class
of bug this project can have. See [§10](#10-reporting-a-vulnerability).

---

## 1. The guarantee

> An attacker who fully owns the Farrier control plane, its database, and an administrator account
> still cannot run arbitrary code on any **enrolled** host, cannot exceed any host's local policy, and
> cannot reboot or stop services on hosts whose policy forbids it.
>
> A host **being enrolled** applies, at most once, the bootstrap template its operator named on the
> command line — shown in full before it runs, signed by a key from that host's own
> `trusted-signers`, and recorded permanently on the host.

Both paragraphs ship together, always. The second is the price of the Tier 2 bootstrap feature
([§7](#7-provisioning-and-the-enrolment-time-exception)); a guarantee with an undisclosed exception is
worse than no guarantee, so the first paragraph is never quoted on its own — not in the README, not
in a release announcement, not on a slide — because it reads better that way.

Farrier competes with Landscape, Salt, Uyuni and Rudder on exactly one axis: all of them ship a remote
execution channel, and Farrier does not. That absence is the product.

---

## 2. The three mechanisms

The guarantee is not a policy decision that a future maintainer can quietly relax. It is the emergent
property of three mechanisms, each of which is load-bearing on its own.

### 2.1 A closed intent catalogue

The wire protocol carries an enumerated, typed operation — never a command string. `internal/intent`
defines the complete set of things a Farrier job can be, as Go constants. There is no registry, no
plugin table, no configuration file that adds an intent, and no code path that leads from a network
message to a shell.

Every external process invocation in the agent and in the root helpers is `execve` with a fixed argv
slice built from validated, typed parameters. Nothing anywhere concatenates remote input into a
command string, and nothing passes remote input to `sh -c`, `bash -c`, `os/exec` with a shell, or any
equivalent.

Parameters are typed and constrained at the boundary. A systemd unit name, for example, must match:

```
^[a-zA-Z0-9@._-]+\.(service|socket|timer)$
```

The `guarantee` CI workflow asserts that the catalogue matches an expected literal set, so **adding an
intent fails CI until the expectation is updated in the same commit** — which is the point. It also
asserts that no member's name matches execution-shaped patterns, that every member has a class and a
parameter validator, and that fuzzing the parameter parser never produces a shell invocation or a
string that escapes the unit-name pattern.

### 2.2 Local policy sovereignty

Each host carries `/etc/farrier/policy.toml`, owned `root:root`, mode `0644`, shipped
`config|noreplace` so package upgrades never overwrite a local edit. The agent runs as the unprivileged
`farrier` user and **cannot write it**. No intent modifies it. There is no `policy.set` operation and
there will not be one.

Effective permission is always:

```
effective = min(central request, local policy)
```

Never the maximum, never a union, never "central overrides for emergencies". A host configured with
`allow = "none"` cannot be made to apply updates by anyone in the control plane holding any role, ever,
including the person who installed the control plane.

**Enforcement lives in the root helper, not in the agent.** The agent's own policy check exists to save
a round trip and to give a good error message. The check that matters runs as root, inside
`/usr/libexec/farrier/*`, re-reading the root-owned policy file from disk on every invocation. That
placement is what makes the guarantee survive a *fully compromised agent process*: an attacker with
arbitrary code execution as `farrier` still cannot exceed the policy, because the helper does not
trust its caller.

"Does not trust its caller" includes not taking the policy's location from it. The helpers accept no
`--policy` flag: the path is the packaged constant, always. The agent can write `/var/lib/farrier`, so
a helper that read a caller-supplied path would enforce — carefully, as root — whatever policy the
attacker had just written. Nor is there a field for one in the request that crosses the socket. A test
in `internal/intent` parses each helper's source and fails if one grows such a flag.

`systemctl stop farrier-agent` and the presence of `/etc/farrier/paused` are a kill switch that the
control plane cannot override. There is deliberately **no `agent.resume` intent** — an off switch that
something else can flip back on is not an off switch.

### 2.3 Offline job signing

Destructive operations require a detached signature from a key the control plane does not hold.

The trust anchor is `/etc/farrier/trusted-signers` — **not the package**. It is root-owned,
`config|noreplace`, and **empty by default**, so a freshly installed agent will execute nothing
destructive until an administrator deliberately places a public key in it.

This placement is deliberate and is worth being explicit about. If the signing key shipped in the
`.deb`, the trust chain would be `APT signing key → package → job signing key`, which quietly promotes
whoever controls APT signing to ultimate authority over every host. In a hosted deployment that would
hand the provider a route around the customer's own control plane. So the anchor is established
locally, by the administrator, at enrolment time (see [§7](#7-provisioning-and-the-enrolment-time-exception)).

The signed payload is the canonical JSON encoding of:

```
{jobId, hostId, intent, params, notBefore, notAfter, nonce}
```

Nonces are persisted on the host so a replayed signature is refused. Validity windows are checked
against the **local** clock only (see [§4.3](#43-clock-skew)).

---

## 3. The intent catalogue

The catalogue is closed. Its current contents:

### Read-only — unprivileged, unsigned

mTLS is sufficient authorisation. These run as the `farrier` user with no capabilities and read
nothing an unprivileged local user could not read.

| Intent | What it does |
| --- | --- |
| `facts.collect` | Inventory: OS, kernel, hardware, network, uptime |
| `packages.listUpgradable` | Simulated upgrade parse; splits security from regular |
| `services.list` | systemd unit state over the D-Bus read interface |
| `reboot.checkRequired` | Reboot-required markers and `needrestart` output |

### Routine — signed by the control plane's online key

| Intent | What it does |
| --- | --- |
| `packages.applySecurity` | Applies security-origin updates only, subject to policy |

This is the one privileged operation that does not require an offline signature, because it is the
operation the host would perform on its own timer anyway via `unattended-upgrades`. The control plane
can, at most, make a host do sooner what its own local policy already permits it to do unattended.
A host with `allow = "none"` refuses it.

The control plane signs it with a key it holds itself, generated on first start and kept beside the CA.
The public half reaches agents in the enrolment response and on every heartbeat, so rotation needs no
operator action — see [`PROTOCOL.md` §5.2](PROTOCOL.md#52-the-control-planes-online-key).

**That the control plane distributes the key it signs with is not an oversight, and it does not weaken
[§1](#1-the-guarantee).** An attacker who owns the control plane owns this key, so it defends against
nothing in §1's scenario. What bounds a routine intent is the paragraph above: the host's own policy,
re-read as root by the helper. So why sign at all? Because the alternative is a privileged operation
authorised by mTLS alone, and because it keeps one mechanism instead of two — every privileged job
carries a signature over the same canonical payload, checked in the same place, against the same replay
store. An agent with a second code path for "privileged but unsigned" would have a second place to get
it wrong.

**The same arrangement for the destructive tier would be a backdoor.** An agent therefore verifies the
two tiers against two anchors and never one: a signature by the online key must not authorise a reboot,
and a signature by a key in `trusted-signers` is not an online-key signature. That is asserted
mechanically, in both directions, by `TestGuaranteeTheOnlineKeyCannotAuthoriseADestructiveJob`.

**A reboot must be unreachable from the routine tier by effect, not merely by class.** That distinction
is load-bearing and it was once got wrong here: `packages.applySecurity` shared a parameter decoder with
`packages.applyAll`, so it accepted `rebootIfRequired`, and the root helper acted on the flag without
asking which intent had carried it. The control plane could therefore reboot a host with a key it holds
itself, while a test asserting that the online key cannot sign a *destructive-class* job stayed green —
a reboot reached through a routine intent's parameters is never classified as anything.

`packages.applySecurity` now has its own decoder and takes no parameters at all. The field is unknown to
it rather than accepted and ignored, because a field that is accepted and ignored is one flipped
condition away from being honoured. The root helper refuses the combination a second time, since it runs
as root and the catalogue does not.
`TestGuaranteeTheRoutineTierCannotExpressAReboot` asserts this over the whole catalogue rather than over
one intent, because the defect was a shared decoder and no test naming a single member would have seen
it.

### Destructive — signed by a key in the **host's** `trusted-signers`

| Intent | What it does |
| --- | --- |
| `packages.applyAll` | Applies all available updates, subject to policy |
| `service.start` | Starts a unit on the policy's `restartable` list |
| `service.stop` | Stops a unit on the policy's `restartable` list |
| `service.restart` | Restarts a unit on the policy's `restartable` list |
| `host.reboot` | Reboots the host, subject to the policy's reboot rule |

**Every destructive intent is offline-signed. There is deliberately no graded tier by blast radius.**
A design in which "small" destructive operations took a weaker authorisation would weaken the claim to
"cannot reboot your fleet *in one action*" — and a control plane holding two operator accounts could
simply walk the fleet host by host. One tier, no exceptions.

**Approval** is the other half, and it is a property of the control plane rather than of the host. Each
tenant chooses one of three modes:

| Mode | What it means |
| --- | --- |
| `none` | The signature is the whole of the control-plane-side authorisation. A destructive job is claimable as soon as it is created. **This is the default.** |
| `self` | Somebody must release the job before any host may claim it, and it may be whoever created it. |
| `second_person` | Somebody *other than* the job's creator must release it. |

`POST /api/v1/jobs/{id}/approve` records a release. Under `second_person` the refusal to self-approve
is enforced in the statement that performs the update rather than in the handler — two requests
arriving together would otherwise let one operator release their own job by racing it against itself.

**Which mode applies is decided when the job is created and recorded on its row**, not looked up when
somebody presses approve. That is not an optimisation. A mode read at approval time could be defeated in
two API calls: queue the job while the tenant requires a second person, relax the tenant's setting,
release it yourself. A job records what it required.

The default is `none`, and the reasoning is worth stating plainly because the previous default was the
strictest of the three. What the guarantee in [§1](#1-the-guarantee) rests on for a destructive intent
is the **signature** — made offline, by a key in the host's own `trusted-signers`, which this control
plane does not hold and cannot obtain. Approval sits on top of that and is a different kind of control:
it defends against a careless operator, not a compromised one, because an attacker who owns the control
plane owns the approval mechanism too. It is also the one part of the destructive tier the *host* does
not check. Requiring a second person by default meant that an installation with one operator could not
reach the destructive tier at all — not "with difficulty", but at all — so the strict default was a tier
nobody could use rather than a tier everybody used carefully.

An organisation with more than one operator should turn `second_person` on. It is one field on the
tenant, and it is the setting that makes "nobody reboots production alone" true rather than customary.

**Every destructive intent is offline-signed, in every mode.** No approval setting relaxes that, and
there is no mode in which a destructive job runs on mTLS alone.

### Permanently refused

The following will never be added. In an open-source project the request arrives eventually, usually
from a well-meaning contributor with a real problem, and the answer needs to be a document rather than
an argument. Pull requests adding any of these will be closed with a link to this section.

| Refused | Why |
| --- | --- |
| `shell.exec` | It *is* the thing this product exists not to have. Every other item on this list is a way of spelling it. |
| `script.run` | `shell.exec` with an extra step. Fetching the script from the control plane makes the control plane a code-execution channel by definition. |
| Arbitrary `file.write` | Write to `/etc/sudoers.d/`, `/etc/cron.d/`, `~/.ssh/authorized_keys`, or any systemd unit path and you have code execution. A file-write primitive that is safe requires an allowlist of paths *and* content schemas, at which point it is a set of typed intents, which is what the catalogue already is. |
| `apt.addRepository` | Adding a repository plus a signing key means every future package on the host is chosen by whoever added it. It is remote code execution with a delay. |
| `user.create` | Account creation is privilege creation; with a shell or a password it is direct access, and without one it is a foothold for the next step. |
| `ssh.authorizedKeys.add` | Direct interactive root-adjacent access from the control plane. |
| `agent.updateFromURL` | Self-update from a control-plane-supplied URL replaces the binary that enforces every other rule here. Agent updates come from the signed APT repository through the host's own package manager, on the host's own schedule. |

If you have a use case that seems to require one of these, open a discussion. The likely answer is a
new *typed* intent with validated parameters — which is a normal, reviewable source change — rather
than a general-purpose escape hatch.

### Also closed

- **The intent catalogue is not a registry.** New intents arrive as source changes in a reviewed pull
  request. That friction is a feature, not an oversight.
- **There are exactly three root helpers.** There is no fourth one that "runs the configured command".
- **There is no runtime plugin loader in the agent, ever.** Any mechanism that loads code into the
  agent at run time is remote code execution wearing a plugin API. Agent extension is compile-time
  only.

The asymmetry that keeps this workable: **the server may be extended at run time in the outbound
direction only.** Webhook sinks send data out; nothing sends code in.

---

## 4. Transport and identity

### 4.1 Direction

There is no server→agent direction at all. Every byte moves on a connection the host opened. There is
no listening port on a managed host, and therefore no port to firewall, no inbound ACL to get wrong,
and no benefit to putting the fleet behind a VPN.

The agent makes exactly four calls plus a certificate renewal, documented in
[`PROTOCOL.md`](PROTOCOL.md).

### 4.2 mTLS

A private CA is created at control-plane install time (`farrier-server ca init`). Agent certificates
are host-scoped, valid 90 days, and auto-renewed at two-thirds of lifetime via `POST /agent/v1/renew`
authenticated by the current certificate.

**Revocation is a database fingerprint check on every request**, not CRL and not OCSP. A revoked host
stops being able to talk to the control plane on its next request, with no distribution delay and no
stapling infrastructure.

Revoking a host also releases its machine — the salted `/etc/machine-id` hash a host claims at
enrolment — so the same physical machine can enrol again under a new identity. The revoked row and its
history stay. Without that release, any host row that outlived its certificate would wedge the machine
permanently: unable to authenticate, and refused re-enrolment because a host with that machine id
already exists. `DELETE /api/v1/hosts/{id}` releases it too, and discards the history with it; revoke
is the answer that keeps the audit trail, and is the one to reach for. The agent's private key and
certificate are stored as one file and promoted by one rename, so a renewal interrupted at any point
leaves a matching pair on disk rather than half of a new one.

The CA private key is the control plane's most sensitive secret. Compromising it lets an attacker
impersonate *hosts to the server* — it does **not** let them run code on a host, because the agent
authorises jobs by intent class and signature, not by who asked.

### 4.3 Clock skew

Clock skew is a security boundary, not an operational annoyance.

`notBefore`/`notAfter` on a signed job are validated against the **local** clock only. The agent never
adjusts its notion of time to server-supplied time; a compromised control plane could otherwise extend
a signature's validity window arbitrarily by lying about the current time. The `serverTime` field in
the heartbeat response is used *solely* to compute and report an offset for display.

When the measured offset exceeds five minutes:

- read-only intents still run,
- privileged intents refuse — **fail closed**,
- the UI flags the host.

### 4.4 No VPN requirement

Farrier will never require a VPN. The agent connects outbound, so there is no port to protect; and
tunnel membership cannot prove host identity anyway, which is what mTLS is for. Running Farrier over
an existing Tailscale or WireGuard network already works with zero additional code — the agent talks
to a URL.

For a hosted offering this is not a neutral choice: a provider-operated VPN hub reaching into customer
networks would be a substantially larger backdoor than the remote-exec channel this product removes.

---

## 5. Tenants

One control plane can serve many independent fleets. That is what makes hosting Farrier for other
people possible, and it introduces the only boundary in this document that is *not* enforced on the
host: everything else here is something a machine checks about a job, and this is something the control
plane checks about a request.

So it is worth being precise about what it does and does not add to [§1](#1-the-guarantee). It adds
nothing. The guarantee already assumes an attacker who owns the control plane and its database; against
that attacker, tenancy is not a defence and is not claimed as one. What tenancy defends against is a
*bug* — a query that forgot a predicate, a handler that took an id from a URL without asking whose it
was — and the failure it prevents is one customer seeing another's fleet.

### 5.1 What a tenant is

A tenant owns hosts, enrolment tokens, jobs and results, and it chooses its own approval mode
([§3](#3-the-intent-catalogue)) and its own event webhook. A tenant is not a permission level: there is
no hierarchy of tenants, and no tenant can see into another.

### 5.2 Where the boundary is enforced

Three layers, and the order matters, because only the last of them is a rule rather than a habit.

1. **The credential names the tenant.** An operator credential resolves to exactly one tenant. The
   tenant is not in the URL, not in a header and not in the body, so there is no field of a request an
   operator could edit to reach another fleet. An agent's tenant comes from its certificate's row,
   which the revocation lookup already reads on every request — so an agent never names its own tenant
   and could not name a different one. **This is also why the agent protocol needed no change for any
   of it:** tenancy is a property of the credential, and the credential is a certificate this control
   plane issued.

2. **The handler cannot reach an unscoped store.** Middleware hands a handler a store handle already
   scoped to the request's tenant. A tenant-scoped operation is not a method somebody remembers to pass
   a tenant to; it is a method that cannot be reached without one.

3. **PostgreSQL refuses the row.** Every table holding tenant data has row-level security `ENABLE`d and
   `FORCE`d, with a policy keyed on a session setting the application sets inside the transaction that
   runs the query. A statement that forgets its `WHERE` clause returns nothing rather than everything,
   and a statement issued with no tenant set returns nothing at all — `current_setting(…, true)` is
   NULL when unset, and `tenant_id = NULL` is not true. The failure mode is an empty result, which is
   loud, rather than another customer's fleet, which is silent.

   `FORCE` is the half that is easy to omit and worthless to omit: without it the table's owner — which
   is the role running the application — bypasses every policy.

   The setting is `SET LOCAL`, scoped to the transaction, which is why every scoped statement runs in
   one even when it is a single `SELECT`. A session-level setting on a pooled connection would be
   inherited by the next request that borrowed it.

   Two rows have to be findable before the tenant is known, because finding them is *how* the tenant
   becomes known: the certificate on an agent request and the enrolment token from a machine that is
   not yet a host. Rather than exempting those two tables, their policies admit exactly one row — the
   row whose key the caller can already name, through a second session setting. Naming a SHA-256 you
   already hold is not an enumeration path.

Composite foreign keys carry the tenant alongside every reference, so a row claiming one tenant while
pointing at another's host is refused by the database rather than noticed in review.

**A role that bypasses row-level security removes all of layer 3 with no symptom.** A superuser, or a
role with `BYPASSRLS`, is exempt from every policy: the policies are still in the schema, the predicates
are still in the queries, and every query returns every tenant's rows. `farrier-server` therefore checks
its own role at startup and **refuses to start** rather than serving many customers from one database
with the boundary switched off.

### 5.3 The platform administrator

Running an installation is a different job from reading what runs on it, and Farrier keeps them
separate. A platform credential can create, configure and delete tenants through `/api/v1/tenants`. It
holds no tenant of its own, and every route that reaches a tenant's hosts or jobs refuses it.

It also cannot mint an operator credential. Issuing a fleet's credential belongs to the identity
provider — `auth.Provider` is the seam for it — and a tenant API that handed out tokens would make the
platform administrator able to authenticate as any customer, which is precisely the separation the role
exists to keep.

The honest limit: a platform administrator has the database and the process. Nothing here prevents
somebody with shell access on the control plane from reading a tenant's rows, and this document does
not claim otherwise. What it prevents is *the product* offering that as a feature, and a bug offering
it by accident.

### 5.4 What deleting a tenant does not do

It removes the tenant's hosts, certificates, tokens, jobs and results. It does not reach the machines —
nothing in Farrier does. Their agents keep running, keep applying their own local policy, and are
refused at the next request as an unknown certificate. That is the correct end state for a customer who
has left, and it is worth saying out loud that deleting a tenant does not uninstall anything.

---

## 6. Host privileges

The agent runs as the `farrier` system user with **zero capabilities**, under a systemd unit hardened
as shown in `packaging/farrier-agent.service`. Notably it sets `MemoryDenyWriteExecute=yes`, which is
one of the reasons the agent is written in Go: any JIT runtime is incompatible with that setting, so
choosing a JIT language would have silently cost this mitigation.

Privileged work happens in exactly three root helpers:

```
/usr/libexec/farrier/apply-updates
/usr/libexec/farrier/restart-unit
/usr/libexec/farrier/reboot-host
```

Each helper re-reads and enforces `/etc/farrier/policy.toml` itself, as root, on every invocation. None
of them accepts a command to run, a path to execute, or a shell fragment.

**The agent reaches them over a unix socket, not through `sudo`.** Nothing in Farrier is setuid and
there is no `/etc/sudoers.d/farrier`. That is forced rather than chosen: with `NoNewPrivileges=yes` in
force, `execve` drops the setuid bit, so `sudo` cannot become root at all — and systemd *implies*
`NoNewPrivileges=yes` from `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectClock`,
`RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality` and
`SystemCallFilter`, every one of which the agent's unit sets. Keeping `sudo` would have meant dropping
most of this section.

```
/run/farrier/apply-updates.sock   root:farrier 0660  → farrier-apply-updates@N.service (root)
/run/farrier/restart-unit.sock    root:farrier 0660  → farrier-restart-unit@N.service  (root)
/run/farrier/reboot-host.sock     root:farrier 0660  → farrier-reboot-host@N.service   (root)
```

Each socket is `Accept=yes`: systemd accepts the connection and starts one instance of one helper with
the connection as its standard input. There is no listening socket inside a privileged process, no
accept loop of Farrier's own, and **no resident root daemon** — a helper exists for exactly as long as
one operation does.

The three properties that made the sudoers entry safe are kept, and each is asserted by the guarantee
suite rather than reviewed for:

1. **The set of reachable operations is closed and visible in one place.** It is the routing table in
   `internal/privsep`, checked against the catalogue on every build. An intent that is not in it has no
   route from the agent to root at all, whatever the policy file says and however well the job was
   signed.
2. **A caller names an intent, never a program.** The request carries an intent and a parameter object
   and has no field a path, a command or an argument vector could occupy — and the helper decodes the
   parameters again, itself, with the same catalogue decoder, on its own side of the boundary.
3. **Authorisation is by identity the caller cannot forge.** The socket's mode names the `farrier`
   group; the helper additionally reads the peer's credentials with `SO_PEERCRED`, which the kernel
   records at connect time. Only the agent's own account and root are served.

A helper also refuses an intent it does not serve. systemd routes a connection to exactly one helper,
but the request arriving on it still names an intent, and nothing about the socket would stop a
compromised agent from sending `host.reboot` to the one that restarts units.

The helper units themselves are **not** sandboxed, and that is deliberate rather than an omission: a
program whose job is to install packages cannot be confined against writing to `/usr` and `/etc`. What
bounds them is the root-owned policy file and the closed catalogue, not a systemd directive.

`farrier-agent doctor` checks the whole path from the agent's own account and changes nothing: it sends
an intent that is in no catalogue and on no route, which every helper refuses at its first check. A
refusal is what success looks like, because there is no harmless privileged intent to send instead.

**`farrier` is never added to the `docker` group.** Docker socket access is root equivalence and would
silently undo everything in this section. If you package Farrier for a system where the agent needs to
report container state, that must be done through a read-only path, not group membership.

---

## 7. Provisioning and the enrolment-time exception

This is the exception named in the second paragraph of the guarantee. It is stated plainly here because
it is the only way a Farrier component ever applies operator-authored configuration to a host.

**Tier 1 — implemented first.** Farrier stores, versions and renders cloud-init templates, and **never
delivers them to a host**. The rendered `user-data` goes to a human, or to Terraform / Proxmox / MAAS /
a cloud provider's user-data field; the machine consumes it at first boot from the hypervisor that
created it. Farrier is not in the delivery path at all. This also covers bare metal, since Ubuntu
`autoinstall` for PXE and ISO is delivered as cloud-init user-data.

**Tier 2 — the exception.** `farrier enroll --bootstrap NAME` applies a named template once, on a host
that is being enrolled by hand. Every one of these guardrails is required:

1. Explicit `--bootstrap NAME` on that specific invocation. Never implicit, never a server default,
   never a group setting.
2. The full text is printed to the terminal, written to the journal, and recorded in
   `/var/lib/farrier/bootstrap-applied.json` **before** execution.
3. It is signed by a key already present in that host's `trusted-signers`.
4. It runs exactly once, enforced by an on-disk interlock.
5. **cloud-init does the applying.** Farrier never ships a hand-written YAML-to-shell engine — that
   would be the exec channel wearing a hat.

The chicken-and-egg problem is that `trusted-signers` is empty on a fresh install. It is solved by
establishing the anchor from a local, administrator-chosen file **before** anything is fetched:

```bash
sudo farrier enroll --token XYZ \
     --signers ./trusted-signers \   # local, admin-chosen, written first
     --policy  ./policy.toml \
     --bootstrap standard-server     # fetched, verified against the above, displayed, confirmed
```

Without signers present, `--bootstrap` **refuses**. It never falls back to trusting the server.

**Tier 3 — pushing configuration to an already-enrolled host — is never built.** That is the line
between "fleet management without a remote shell" and "a remote shell with extra steps".

### Templates are not a secret store

cloud-init `user-data` is plaintext in the cloud metadata service and in
`/var/lib/cloud/instance/user-data.txt`, readable by anything with instance or metadata access. Farrier
therefore:

- **warns** (and does not block) on private-key blocks, `password:` fields and API-token shapes in
  template bodies;
- treats rendered output as a credential in its own right, because it carries a live enrolment token;
- encrypts template bodies at rest.

---

## 8. What Farrier does *not* defend against

An honest guarantee needs an honest boundary. Farrier does not protect you from:

- **Anyone with root on the managed host.** They can edit `policy.toml` and `trusted-signers`, or
  simply not run the agent. Local root is above Farrier in the trust hierarchy, by construction.
- **A compromised holder of a key in `trusted-signers`.** That key is the authority for destructive
  operations; this is exactly why the hardware-backed signing backends exist and why the audit log
  records *which* signer authorised each job.
- **The APT repository's signing key.** The agent is installed and updated as a normal Debian package
  from a signed repository. Whoever controls that GPG key controls the agent binary on every host that
  updates from it. This is a different adversary from the one in §1 — it is the ordinary distribution
  trust that applies to every package on the system — but it is real, and the honest statement of the
  guarantee is that it covers *control-plane* compromise, not *package-supply-chain* compromise. Hosts
  use deb822 with `Signed-By:` and an explicit keyring so the Farrier key is trusted for the Farrier
  repository only, never system-wide; `apt-key` is never used.
- **Denial of service by a compromised control plane.** An attacker owning the control plane can stop
  issuing jobs, or issue jobs that fail. They cannot make hosts do anything the policy forbids, but
  they can make the fleet less useful. Note that patching continues regardless: when the control plane
  is unreachable, hosts keep applying updates from their local policy on their own timer, because
  `unattended-upgrades` does not need us. A control-plane outage must never mean an unpatched fleet.
- **Traffic analysis.** The existence, timing and size of heartbeats are visible to anyone on the
  path, even though the contents are not.
- **A host enrolled *during* a control-plane compromise being given somebody else's identity.** The
  signed job payload binds a job to a `hostId`, and a host learns its `hostId` from the enrolment
  response — so a control plane that was already compromised when a host enrolled can hand that host an
  identity belonging to another, and jobs signed for the other host will verify on it. The blast radius
  is bounded by the mechanism that matters: the root helper re-reads the *local* policy of the machine
  it is running on, so nothing exceeds what that host's own operator permitted, and §1 still holds. What
  is lost is targeting — a signed job can reach a host it was not meant for. Binding the signature to
  the certificate would not help, because the adversary in §1 owns the CA. An operator who cares should
  enrol hosts from a control plane they have reason to trust at that moment, which is the same
  requirement the bootstrap exception in §7 already makes.
- **Anyone with the control plane's database or shell.** Tenants are isolated from each other
  ([§5](#5-tenants)), and they are not isolated from whoever runs the installation. A platform
  administrator cannot read a customer's fleet *through the product* — no route they hold reaches one —
  but they have `psql`. What §5 buys is that a bug cannot cross the boundary and that the feature set
  does not offer crossing it as a convenience; it does not turn a hosting provider into a party you do
  not have to trust. If you need that, run your own control plane; the binary is the same one.

  There is deliberately **no support path** across the boundary — no impersonation, no read-only view of
  a customer's hosts, no "open a ticket and we will look". A hosting provider who needs to see a
  customer's fleet asks the customer for a credential. That is inconvenient on purpose, because the
  alternative is a mechanism that exists, is audited by nobody in particular, and is used at three in
  the morning during an incident.

---

## 9. Hardening notes for operators

- Put real keys in `trusted-signers` and use a touch-required hardware token where you can. The
  audit log distinguishes `ops-laptop (file)` from `ops-yubikey-1 (PKCS#11)` precisely so that this is
  visible to reviewers after the fact. File-based keys are fully supported; refusing them would not
  make anyone buy a token, it would push them to keep the key on the control plane instead, which is
  strictly worse.
- Set `policy.toml` to the least permission each host actually needs. It is the only control that
  survives a total control-plane compromise.
- Do not add a socket unit, and do not widen the group on the three that exist. If you find yourself
  wanting a fourth helper, that is a request for a new typed intent upstream.
- Back up the control plane's CA key separately from its database. An attacker with both can
  impersonate hosts; an attacker with the database alone cannot.
- Review `/var/lib/farrier/bootstrap-applied.json` on hosts you did not personally enrol.
- **Connect the control plane to PostgreSQL as an ordinary role that owns its schema — never as a
  superuser, and never as one with `BYPASSRLS`.** Both are exempt from every row-level security policy,
  which is the whole of the tenant boundary ([§5](#5-tenants)), and the exemption has no symptom: the
  policies are still there, the queries still carry their predicates, and every one of them returns
  every tenant's rows. `farrier-server` checks its own role at startup and refuses to run on either, so
  this is a note about what to configure rather than a trap left open — but a `postgres://postgres@…`
  URL in a Compose file is the obvious thing to reach for, and it is the wrong thing.
- If you run one control plane for more than one customer, turn on `second_person` approval for the
  tenants that want it and leave it off for the ones that cannot staff it. It is a per-tenant setting
  precisely so that one fleet's answer does not have to be everybody's.

---

## 10. Reporting a vulnerability

Report security issues privately through GitHub's **Report a vulnerability** button on the repository's
Security tab, which opens a private advisory. Please do not open a public issue for a vulnerability.

Include a description, affected versions, and a reproduction if you have one. We aim to acknowledge
within three working days.

Findings that break the [§1](#1-the-guarantee) guarantee are the highest severity this project
recognises, regardless of how difficult they are to reach. That includes:

- any path from a control-plane-supplied value to a shell, an interpreter, or an unvalidated `execve`;
- any way for the control plane to cause an operation the host's local policy forbids;
- any way to make a root helper act without re-checking policy;
- any way to get a job accepted without a valid signature from the host's own `trusted-signers`, for
  an intent whose class requires one.
