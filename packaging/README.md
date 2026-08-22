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
├─ sudoers                  the fixed-argv entry for the three root helpers
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

Needs [`nfpm`](https://nfpm.goreleaser.com/install/). `make deb` builds the binaries first and
validates the sudoers file with `visudo` when it is available.

## What the package contains

| Path | Notes |
| --- | --- |
| `/usr/bin/farrier-agent` | The agent. Static, no runtime dependencies |
| `/usr/libexec/farrier/{apply-updates,restart-unit,reboot-host}` | The three root helpers. There is no fourth |
| `/usr/lib/systemd/system/farrier-agent.service` | Hardened unit, zero capabilities |
| `/etc/farrier/policy.toml` | **conffile**, `root:root 0644` |
| `/etc/farrier/trusted-signers` | **conffile**, `root:root 0644`, empty |
| `/etc/sudoers.d/farrier` | **conffile**, `root:root 0440` |
| `/var/lib/farrier`, `/var/lib/farrier/pending-results`, `/var/log/farrier` | `farrier:farrier 0750` |

Both configuration files ship as `config|noreplace`, so dpkg never overwrites a local edit. There is a
test in `testfleet/` that asserts this across an upgrade. For `trusted-signers` that is a **security**
test rather than a convenience one: a package upgrade that silently reset the trust anchor would
re-open every destructive operation an administrator had deliberately closed.

The maintainer scripts create the `farrier` system account before unpacking, generate a per-host salt
for hashing `/etc/machine-id` — systemd documents the raw value as confidential, and an unsalted hash
would be correlatable between fleets by anyone who saw both — and enable the unit. On purge they
remove the state directories and the account; on ordinary removal they leave state alone, so that
removing and reinstalling does not lose the host's identity or its pending job results.

## ⚠ Unresolved before phase 1: `NoNewPrivileges` and `sudo`

`farrier-agent.service` sets `NoNewPrivileges=yes`, and the design calls for the agent to reach the
root helpers through `sudo`. **Those two are mutually exclusive.** With the no-new-privileges bit set,
`execve` silently drops the setuid bit, so `sudo` cannot become root and fails with *"effective uid is
not 0"*.

Phase 0 ships no write capability, so nothing invokes a helper and the conflict is not yet live. It
must be resolved before the first executor lands. The two credible options, both of which keep the
fixed-argv property:

1. **Replace `sudo` with a root-owned helper service** the agent reaches over a unix socket in
   `/run/farrier`, authorised by the socket's peer credentials. More code, and it preserves every
   hardening line while removing setuid from the picture entirely.
2. **Drop enough of the sandbox that `sudo` works.** Note that deleting the `NoNewPrivileges=yes` line
   is *not* sufficient and would be a trap for whoever tries it: systemd implies `NoNewPrivileges=yes`
   from a long list of other directives, including `ProtectKernelTunables`, `ProtectKernelModules`,
   `ProtectClock`, `RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
   `LockPersonality` and `SystemCallFilter` — every one of which this unit sets. Making `sudo` work
   means dropping most of them, which is most of the hardening.

Option 1 is the one to take. Option 2 is listed so that nobody spends an afternoon on the obvious
version of it and concludes that systemd is broken. Whichever is chosen, `docs/SECURITY.md` §5 must be
updated in the same change; the note is repeated in the unit file so nobody meets this for the first
time while debugging a failing helper.

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
FARRIER_APT_URL=https://apt.example.org GPG_KEY_ID=<fingerprint> \
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
fleets nobody will be able to contact later. A bare `*.github.io` URL can never be migrated.

## Verifying a build by hand

```bash
make deb VERSION=0.1.0
dpkg-deb --info    dist/packages/farrier-agent_0.1.0_amd64.deb
dpkg-deb --contents dist/packages/farrier-agent_0.1.0_amd64.deb
visudo -c -f packaging/sudoers
systemd-analyze verify packaging/farrier-agent.service

sudo dpkg -i dist/packages/farrier-agent_0.1.0_amd64.deb
sudo -u farrier sudo -n /usr/libexec/farrier/restart-unit --action restart --unit nginx.service
#   -> refused by local policy (unit_not_restartable), exit 3, on a default install
#
# The helper takes no --policy flag. Its path is the packaged constant, because the sudoers entry pins
# the program and not its arguments and the agent can write /var/lib/farrier — so a caller-supplied
# path would let a compromised agent choose the policy that gets enforced.
farrier-agent policy check
sudo dpkg --purge farrier-agent
```

The refusal above is the whole product in one command: the agent's own account, going through the only
privileged path that exists, being told no by a file the control plane cannot touch.
