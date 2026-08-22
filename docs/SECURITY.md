# Security

This document is the specification of Farrier's security posture. It is not marketing copy: every
claim below is either enforced by code with a test in the `guarantee` CI workflow, or explicitly
marked as a boundary that Farrier does **not** defend.

If you find a way to violate the guarantee in [§1](#1-the-guarantee), that is the most serious class
of bug this project can have. See [§9](#9-reporting-a-vulnerability).

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
([§6](#6-provisioning-and-the-enrolment-time-exception)); a guarantee with an undisclosed exception is
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
`--policy` flag: the path is the packaged constant, always. The sudoers entry pins the program and not
its arguments, and the agent can write `/var/lib/farrier`, so a helper that read a caller-supplied path
would enforce — carefully, as root — whatever policy the attacker had just written. A test in
`internal/intent` parses each helper's source and fails if one grows such a flag.

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
locally, by the administrator, at enrolment time (see [§6](#6-provisioning-and-the-enrolment-time-exception)).

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

### Destructive — signed by a key in the **host's** `trusted-signers`, plus second-person approval

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

## 5. Host privileges

The agent runs as the `farrier` system user with **zero capabilities**, under a systemd unit hardened
as shown in `packaging/farrier-agent.service`. Notably it sets `MemoryDenyWriteExecute=yes`, which is
one of the reasons the agent is written in Go: any JIT runtime is incompatible with that setting, so
choosing a JIT language would have silently cost this mitigation.

Privileged work happens in exactly three root helpers, invoked through `sudo` with fixed argv:

```
/usr/libexec/farrier/apply-updates
/usr/libexec/farrier/restart-unit
/usr/libexec/farrier/reboot-host
```

Each helper re-reads and enforces `/etc/farrier/policy.toml` itself. None of them accepts a command to
run, a path to execute, or a shell fragment. The sudoers entry is command-specific and resets the
environment.

**`farrier` is never added to the `docker` group.** Docker socket access is root equivalence and would
silently undo everything in this section. If you package Farrier for a system where the agent needs to
report container state, that must be done through a read-only path, not group membership.

---

## 6. Provisioning and the enrolment-time exception

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

## 7. What Farrier does *not* defend against

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
  requirement the bootstrap exception in §6 already makes.

---

## 8. Hardening notes for operators

- Put real keys in `trusted-signers` and use a touch-required hardware token where you can. The
  audit log distinguishes `ops-laptop (file)` from `ops-yubikey-1 (PKCS#11)` precisely so that this is
  visible to reviewers after the fact. File-based keys are fully supported; refusing them would not
  make anyone buy a token, it would push them to keep the key on the control plane instead, which is
  strictly worse.
- Set `policy.toml` to the least permission each host actually needs. It is the only control that
  survives a total control-plane compromise.
- Do not widen the sudoers file. If you find yourself wanting a fourth helper, that is a request for a
  new typed intent upstream.
- Back up the control plane's CA key separately from its database. An attacker with both can
  impersonate hosts; an attacker with the database alone cannot.
- Review `/var/lib/farrier/bootstrap-applied.json` on hosts you did not personally enrol.

---

## 9. Reporting a vulnerability

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
