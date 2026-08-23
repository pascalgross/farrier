# Packaging

Everything needed to produce the `farrier-agent` Debian package and the signed APT repository it is
served from.

This is built in phase 0, before there is anything to carry, because packaging is where greenfield
agent projects lose weeks. Proving that the `.deb` installs, the system user is created, the hardened
unit starts, the conffiles survive an upgrade and the repository verifies is much cheaper against a
binary that only reports than against one that also has a protocol to debug.

```
packaging/
├─ nfpm.yaml                the package definition
├─ farrier-agent.service    the hardened systemd unit
├─ farrier-*.socket         the privilege boundary: one socket per root helper
├─ farrier-*@.service       one root helper instance per connection
├─ farrier-tmpfiles.conf    /run/farrier, recreated on every boot
├─ apt.conf                 the conffile options unattended-upgrade cannot be given on a command line
├─ policy.toml              conffile, conservative defaults
├─ trusted-signers          conffile, empty on purpose
├─ scripts/                 preinst, postinst, prerm, postrm
└─ apt/                     mkapt.sh and the deb822 sources template
```

## Building

```bash
make deb                        # ./dist/packages/farrier-agent_<version>_<arch>.deb
make deb VERSION=0.1.0 ARCH=arm64
```

Needs [`nfpm`](https://nfpm.goreleaser.com/install/). `make deb` builds the binaries first and runs
`systemd-analyze verify` over every packaged unit when it is available — `make units` does the same
thing on its own. systemd silently ignores a directive it does not understand, so a typo in a socket
unit is not an error, it is a privilege boundary that quietly is not there.

## What the package contains

| Path | Notes |
| --- | --- |
| `/usr/bin/farrier-agent` | The agent. Static, no runtime dependencies |
| `/usr/libexec/farrier/{apply-updates,restart-unit,reboot-host}` | The three root helpers. There is no fourth |
| `/usr/lib/systemd/system/farrier-agent.service` | Hardened unit, zero capabilities |
| `/etc/farrier/policy.toml` | **conffile**, `root:root 0644` |
| `/etc/farrier/trusted-signers` | **conffile**, `root:root 0644`, empty |
| `/usr/lib/systemd/system/farrier-{apply-updates,restart-unit,reboot-host}.socket` | The privilege boundary. `root:farrier`, mode `0660` |
| `/usr/lib/systemd/system/farrier-{apply-updates,restart-unit,reboot-host}@.service` | One root helper instance per connection |
| `/usr/lib/tmpfiles.d/farrier.conf` | `/run/farrier`, recreated on every boot |
| `/usr/share/farrier/apt.conf` | Named by `APT_CONFIG` during an update run. **Not** in `/etc/apt/apt.conf.d` |
| `/var/lib/farrier`, `/var/lib/farrier/pending-results`, `/var/log/farrier` | `farrier:farrier 0750` |

There is no `/etc/sudoers.d/farrier` and no `Depends: sudo`. See below.

Both configuration files ship as `config|noreplace`, so dpkg never overwrites a local edit. There is a
test in `testfleet/` that asserts this across an upgrade. For `trusted-signers` that is a **security**
test rather than a convenience one: a package upgrade that silently reset the trust anchor would
re-open every destructive operation an administrator had deliberately closed.

The maintainer scripts create the `farrier` system account before unpacking, generate a per-host salt
for hashing `/etc/machine-id` — systemd documents the raw value as confidential, and an unsalted hash
would be correlatable between fleets by anyone who saw both — and enable the unit. On purge they
remove the state directories and the account; on ordinary removal they leave state alone, so that
removing and reinstalling does not lose the host's identity or its pending job results.

## Resolved: `NoNewPrivileges` and `sudo`

Phase 0 shipped with this open, here and in the unit file, as the thing that had to be settled before
the first executor landed. It is settled, and the note is kept rather than deleted because the reasoning
is the reason the packaging looks the way it does.

`farrier-agent.service` sets `NoNewPrivileges=yes`, and the original design called for the agent to
reach the root helpers through `sudo`. **Those two are mutually exclusive.** With the no-new-privileges
bit set, `execve` silently drops the setuid bit, so `sudo` cannot become root and fails with *"effective
uid is not 0"*. Deleting the `NoNewPrivileges=yes` line is *not* sufficient either: systemd implies it
from `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectClock`, `RestrictNamespaces`,
`RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality` and `SystemCallFilter` — every one of
which this unit sets. Making `sudo` work would have meant dropping most of the hardening.

**The privilege boundary is now a socket per helper, activated by systemd.** `/etc/sudoers.d/farrier` is
gone, `Depends: sudo` is gone, and nothing in Farrier is setuid.

```
/run/farrier/apply-updates.sock   root:farrier 0660  → farrier-apply-updates@N.service (root)
/run/farrier/restart-unit.sock    root:farrier 0660  → farrier-restart-unit@N.service  (root)
/run/farrier/reboot-host.sock     root:farrier 0660  → farrier-reboot-host@N.service   (root)
```

Each socket is `Accept=yes`, which is the inetd arrangement: systemd accepts the connection and starts
one instance of one helper with the connection as its standard input. So there is no listening socket
inside a privileged process, no accept loop of Farrier's own, and **no resident root daemon** — a helper
exists for exactly as long as one operation does.

Every property that made the sudoers entry safe is kept, and each is now asserted by a test rather than
reviewed for:

| The sudoers entry did this | The socket does this |
| --- | --- |
| Named three programs and no others | `internal/privsep`'s routing table, checked against the catalogue by `TestGuaranteeEveryPrivilegedIntentHasExactlyOneEndpoint` |
| Pinned the argv | The request carries an intent and a parameter object, and `TestGuaranteeARequestCannotNameAProgram` asserts there is no field a path could hide in |
| Named the `farrier` user | The socket's group, **and** the helper's own reading of `SO_PEERCRED` — the one claim about a caller that a caller cannot make |
| Reset the environment | `internal/run` replaces the environment on every invocation, and always did |

The helper also refuses an intent it does not serve. systemd routes a connection to exactly one helper,
but the request arriving on it still names an intent, and nothing about the socket would stop a
compromised agent sending `host.reboot` to the one that restarts units.

`farrier-agent doctor` checks the whole path from the agent's own account, without changing anything:
it sends an intent that is in no catalogue and on no route, so each helper refuses it at its very first
check. A refusal is what success looks like — there is no harmless privileged intent to send instead,
because every one of them changes the machine.

```bash
sudo -u farrier farrier-agent doctor
```

### The helper units are not sandboxed, and that is not an oversight

`farrier-apply-updates@.service` has no `ProtectSystem`, no `ReadOnlyPaths` and no `NoNewPrivileges`.
Its job is to install packages: a directive that stopped it writing to `/usr` or `/etc` would stop it
doing the thing it exists for, and `NoNewPrivileges` would break any maintainer script that uses a
setuid helper — during a security upgrade, on somebody else's machine. What bounds these programs is
not a sandbox. It is `/etc/farrier/policy.toml`, re-read as root on every invocation, and a closed
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
FARRIER_APT_URL=https://farrier.tools/apt GPG_KEY_ID=<fingerprint> \
  ./apt/mkapt.sh dist/packages ./public
```

With `GPG_KEY_ID` unset the tree is built and checksummed but left unsigned, which is what CI does on
every pull request: it proves the mechanism without needing the release secret.

One suite, `stable`, covers every supported release. The agent is a static Go binary with no
distribution-specific dependencies, so per-codename suites would be five copies of the same file and
five chances for one of them to go stale.

Hosts get a deb822 `.sources` file with `Signed-By:` naming an explicit keyring, so the Farrier key is
trusted for the Farrier repository only. **`apt-key` is never used**: it installs a key trusted for
every repository on the system, which turns one compromised project into root on the machine.

### ⚠ Decide the repository URL before the first release

`apt/farrier.sources.in` contains the placeholder `@@APT_URL@@`, substituted from `FARRIER_APT_URL`.
It is a placeholder rather than a value because the decision has not been made, and leaving it
unmakeable-by-accident is the point.

**Use a custom domain, CNAME'd to GitHub Pages, from the very first release.** This URL is written
into `/etc/apt/sources.list.d/farrier.sources` on every host that ever installs the agent — including
fleets nobody will be able to contact later.

The project publishes to `https://farrier.tools/apt`, rather than to
`pascalgross.github.io/farrier/apt`, which would tie a permanent URL to an account name and a
repository name that may both change. The cost of a project domain is that renewing it is now a
permanent obligation; see [`../docs/MAINTAINING.md`](../docs/MAINTAINING.md) §4 for what follows from
that.

## Verifying a build by hand

```bash
make deb VERSION=0.1.0
dpkg-deb --info    dist/packages/farrier-agent_0.1.0_amd64.deb
dpkg-deb --contents dist/packages/farrier-agent_0.1.0_amd64.deb

sudo dpkg -i dist/packages/farrier-agent_0.1.0_amd64.deb

# After the install, not before: systemd-analyze checks that each unit's ExecStart exists, so on a
# machine where the package is not yet unpacked `make units` fails on four missing binaries rather
# than on anything about the units. CI installs /bin/true stubs at those paths for the same reason.
make units

# The privilege boundary, from the agent's own account, changing nothing.
sudo -u farrier farrier-agent doctor

sudo /usr/libexec/farrier/restart-unit --action restart --unit nginx.service
#   -> refused by local policy (unit_not_restartable), exit 3, on a default install
#
# The helper takes no --policy flag. Its path is the packaged constant, because the agent can write
# /var/lib/farrier — so a caller-supplied path would let a compromised agent choose the policy that
# gets enforced. `--dry-run` evaluates the same decision without needing root.
farrier-agent policy check
sudo dpkg --purge farrier-agent
```

The refusal above is the whole product in one command: an operation going through the only privileged
path that exists and being told no by a file the control plane cannot touch. Run as root, deliberately —
if even root going through the helper is refused, the agent certainly is.
