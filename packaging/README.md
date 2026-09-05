# Packaging

Everything needed to produce the `hostseal-agent` Debian package and the signed APT repository it is
served from.

The **control plane** is packaged separately and elsewhere: a container image and a Compose stack in
[`../deploy`](../deploy/README.md). Nothing in this directory is about it, and no image here carries the
agent — a host managed from inside a container on the control plane would be the control plane.

This is built in phase 0, before there is anything to carry, because packaging is where greenfield
agent projects lose weeks. Proving that the `.deb` installs, the system user is created, the hardened
unit starts, the conffiles survive an upgrade and the repository verifies is much cheaper against a
binary that only reports than against one that also has a protocol to debug.

```
packaging/
├─ nfpm.yaml                the package definition
├─ hostseal-agent.service    the hardened systemd unit
├─ hostseal-*.socket         the privilege boundary: one socket per root helper
├─ hostseal-*@.service       one root helper instance per connection
├─ hostseal-tmpfiles.conf    /run/hostseal, recreated on every boot
├─ apt.conf                 the conffile options unattended-upgrade cannot be given on a command line
├─ policy.toml              conffile, conservative defaults
├─ trusted-signers          conffile, empty on purpose
├─ scripts/                 preinst, postinst, prerm, postrm
└─ apt/                     mkapt.sh and the deb822 sources template
```

## Building

```bash
make deb                        # ./dist/packages/hostseal-agent_<version>_<arch>.deb
make deb VERSION=0.1.0 ARCH=arm64
```

Needs [`nfpm`](https://nfpm.goreleaser.com/install/). `make deb` builds the binaries first and runs
`systemd-analyze verify` over every packaged unit when it is available — `make units` does the same
thing on its own. systemd silently ignores a directive it does not understand, so a typo in a socket
unit is not an error, it is a privilege boundary that quietly is not there.

## What the package contains

| Path | Notes |
| --- | --- |
| `/usr/bin/hostseal-agent` | The agent. Static, no runtime dependencies |
| `/usr/libexec/hostseal/{apply-updates,restart-unit,reboot-host}` | The three root helpers. There is no fourth |
| `/usr/lib/systemd/system/hostseal-agent.service` | Hardened unit, zero capabilities |
| `/etc/hostseal/policy.toml` | **conffile**, `root:root 0644` |
| `/etc/hostseal/trusted-signers` | **conffile**, `root:root 0644`, empty |
| `/usr/lib/systemd/system/hostseal-{apply-updates,restart-unit,reboot-host}.socket` | The privilege boundary. `root:hostseal`, mode `0660` |
| `/usr/lib/systemd/system/hostseal-{apply-updates,restart-unit,reboot-host}@.service` | One root helper instance per connection |
| `/usr/lib/tmpfiles.d/hostseal.conf` | `/run/hostseal`, recreated on every boot |
| `/usr/share/hostseal/apt.conf` | Named by `APT_CONFIG` during an update run. **Not** in `/etc/apt/apt.conf.d` |
| `/var/lib/hostseal`, `/var/lib/hostseal/pending-results`, `/var/log/hostseal` | `hostseal:hostseal 0750` |

There is no `/etc/sudoers.d/hostseal` and no `Depends: sudo`. See below.

Both configuration files ship as `config|noreplace`, so dpkg never overwrites a local edit. There is a
test in `testfleet/` that asserts this across an upgrade. For `trusted-signers` that is a **security**
test rather than a convenience one: a package upgrade that silently reset the trust anchor would
re-open every destructive operation an administrator had deliberately closed.

The maintainer scripts create the `hostseal` system account before unpacking, generate a per-host salt
for hashing `/etc/machine-id` — systemd documents the raw value as confidential, and an unsalted hash
would be correlatable between fleets by anyone who saw both — and enable the unit. On purge they
remove the state directories and the account; on ordinary removal they leave state alone, so that
removing and reinstalling does not lose the host's identity or its pending job results.

## Resolved: `NoNewPrivileges` and `sudo`

Phase 0 shipped with this open, here and in the unit file, as the thing that had to be settled before
the first executor landed. It is settled, and the note is kept rather than deleted because the reasoning
is the reason the packaging looks the way it does.

`hostseal-agent.service` sets `NoNewPrivileges=yes`, and the original design called for the agent to
reach the root helpers through `sudo`. **Those two are mutually exclusive.** With the no-new-privileges
bit set, `execve` silently drops the setuid bit, so `sudo` cannot become root and fails with *"effective
uid is not 0"*. Deleting the `NoNewPrivileges=yes` line is *not* sufficient either: systemd implies it
from `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectClock`, `RestrictNamespaces`,
`RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality` and `SystemCallFilter` — every one of
which this unit sets. Making `sudo` work would have meant dropping most of the hardening.

**The privilege boundary is now a socket per helper, activated by systemd.** `/etc/sudoers.d/hostseal` is
gone, `Depends: sudo` is gone, and nothing in HostSeal is setuid.

```
/run/hostseal/apply-updates.sock   root:hostseal 0660  → hostseal-apply-updates@N.service (root)
/run/hostseal/restart-unit.sock    root:hostseal 0660  → hostseal-restart-unit@N.service  (root)
/run/hostseal/reboot-host.sock     root:hostseal 0660  → hostseal-reboot-host@N.service   (root)
```

Each socket is `Accept=yes`, which is the inetd arrangement: systemd accepts the connection and starts
one instance of one helper with the connection as its standard input. So there is no listening socket
inside a privileged process, no accept loop of HostSeal's own, and **no resident root daemon** — a helper
exists for exactly as long as one operation does.

Every property that made the sudoers entry safe is kept, and each is now asserted by a test rather than
reviewed for:

| The sudoers entry did this | The socket does this |
| --- | --- |
| Named three programs and no others | `internal/privsep`'s routing table, checked against the catalogue by `TestGuaranteeEveryPrivilegedIntentHasExactlyOneEndpoint` |
| Pinned the argv | The request carries an intent and a parameter object, and `TestGuaranteeARequestCannotNameAProgram` asserts there is no field a path could hide in |
| Named the `hostseal` user | The socket's group, **and** the helper's own reading of `SO_PEERCRED` — the one claim about a caller that a caller cannot make |
| Reset the environment | `internal/run` replaces the environment on every invocation, and always did |

The helper also refuses an intent it does not serve. systemd routes a connection to exactly one helper,
but the request arriving on it still names an intent, and nothing about the socket would stop a
compromised agent sending `host.reboot` to the one that restarts units.

`hostseal-agent doctor` checks the whole path from the agent's own account, without changing anything:
it sends an intent that is in no catalogue and on no route, so each helper refuses it at its very first
check. A refusal is what success looks like — there is no harmless privileged intent to send instead,
because every one of them changes the machine.

```bash
sudo -u hostseal hostseal-agent doctor
```

### The helper units are not sandboxed, and that is not an oversight

`hostseal-apply-updates@.service` has no `ProtectSystem`, no `ReadOnlyPaths` and no `NoNewPrivileges`.
Its job is to install packages: a directive that stopped it writing to `/usr` or `/etc` would stop it
doing the thing it exists for, and `NoNewPrivileges` would break any maintainer script that uses a
setuid helper — during a security upgrade, on somebody else's machine. What bounds these programs is
not a sandbox. It is `/etc/hostseal/policy.toml`, re-read as root on every invocation, and a closed
catalogue in which the only thing they can be asked for is one of six named operations.

`restart-unit` and `reboot-host` do set `NoNewPrivileges=yes`, `ProtectHome=yes` and `PrivateTmp=yes`,
because neither has any use for a setuid binary and the line costs them nothing.

All three set `CollectMode=inactive-or-failed`, which is not cosmetic. A per-connection instance that
exits non-zero — a refused peer, a request that would not decode — otherwise stays behind in the
`failed` state and is counted against the socket's `MaxConnections` for ever. Two of those and the
socket stops accepting: a host that reports perfectly and can never be patched again.

## Two additions to the specified unit

`RestrictAddressFamilies` includes `AF_NETLINK` as well as `AF_UNIX`. `AF_UNIX` is required to reach
the systemd D-Bus interface, which is how unit state is read; `AF_NETLINK` is required by
`net.Interfaces()` on Linux. Without it, network fact collection returns nothing **and does so
quietly**, which is precisely the class of failure this project tries not to ship.

`MemoryDenyWriteExecute=yes` is kept, and is one of the reasons the agent is written in Go: it is
incompatible with any JIT runtime, so a JIT language would have silently cost this line.

## The APT repository

An APT repository is a static file tree — `dists/`, `pool/`, `Release`, `InRelease` — so GitHub Pages
serves one perfectly well. GitHub Packages has no APT registry. Pages limits are roughly 1 GB per file
and 100 GB of bandwidth a month, public repositories only, which is ample for a few-megabyte agent.

```bash
HOSTSEAL_APT_URL=https://hostseal.io/apt GPG_KEY_ID=<fingerprint> \
  ./apt/mkapt.sh dist/packages ./public
```

With `GPG_KEY_ID` unset the tree is built and checksummed but left unsigned, which is what CI does on
every pull request: it proves the mechanism without needing the release secret.

The tree root also gets an `index.html`. It is not decoration: the repository URL is printed in
`hostseal.sources` and in every set of install instructions, so somebody eventually pastes it into a
browser — and a static host that does not list directories answers that with a 404, which is
indistinguishable from a repository that is actually broken. The page is self-contained, with no
stylesheet or script of its own, because this tree is also published as a release asset and may be
mirrored somewhere that serves nothing else. It names only what the run actually produced, so an
unsigned tree does not advertise an `InRelease` it does not have.

One suite, `stable`, covers every supported release. The agent is a static Go binary with no
distribution-specific dependencies, so per-codename suites would be five copies of the same file and
five chances for one of them to go stale.

Hosts get a deb822 `.sources` file with `Signed-By:` naming an explicit keyring, so the HostSeal key is
trusted for the HostSeal repository only. **`apt-key` is never used**: it installs a key trusted for
every repository on the system, which turns one compromised project into root on the machine.

### ⚠ Decide the repository URL before the first release

`apt/hostseal.sources.in` contains the placeholder `@@APT_URL@@`, substituted from `HOSTSEAL_APT_URL`.
It is a placeholder rather than a value because the decision has not been made, and leaving it
unmakeable-by-accident is the point.

**Use a custom domain, CNAME'd to GitHub Pages, from the very first release.** This URL is written
into `/etc/apt/sources.list.d/hostseal.sources` on every host that ever installs the agent — including
fleets nobody will be able to contact later.

The project publishes to `https://hostseal.io/apt`, rather than to
`pascalgross.github.io/hostseal/apt`, which would tie a permanent URL to an account name and a
repository name that may both change. The cost of a project domain is that renewing it is now a
permanent obligation; see [`../docs/MAINTAINING.md`](../docs/MAINTAINING.md) §4 for what follows from
that.

## Verifying a build by hand

```bash
make deb VERSION=0.1.0
dpkg-deb --info    dist/packages/hostseal-agent_0.1.0_amd64.deb
dpkg-deb --contents dist/packages/hostseal-agent_0.1.0_amd64.deb

sudo dpkg -i dist/packages/hostseal-agent_0.1.0_amd64.deb

# After the install, not before: systemd-analyze checks that each unit's ExecStart exists, so on a
# machine where the package is not yet unpacked `make units` fails on four missing binaries rather
# than on anything about the units. CI installs /bin/true stubs at those paths for the same reason.
make units

# The privilege boundary, from the agent's own account, changing nothing.
sudo -u hostseal hostseal-agent doctor

sudo /usr/libexec/hostseal/restart-unit --action restart --unit nginx.service
#   -> refused by local policy (unit_not_restartable), exit 3, on a default install
#
# The helper takes no --policy flag. Its path is the packaged constant, because the agent can write
# /var/lib/hostseal — so a caller-supplied path would let a compromised agent choose the policy that
# gets enforced. `--dry-run` evaluates the same decision without needing root.
hostseal-agent policy check
sudo dpkg --purge hostseal-agent
```

The refusal above is the whole product in one command: an operation going through the only privileged
path that exists and being told no by a file the control plane cannot touch. Run as root, deliberately —
if even root going through the helper is refused, the agent certainly is.
