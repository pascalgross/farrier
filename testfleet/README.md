# Test fleet

Five real machines — Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13 — running the real `.deb`, driven
by LXD.

It exists because the failures HostSeal most needs to avoid do not reproduce against mocks. A conffile
prompt that hangs, a reboot marker that is an Ubuntu convention rather than a standard, a package
upgrade that quietly replaces a trust anchor, a job result lost because the machine went away before it
was sent: every one of those is a property of a real machine running a real package manager, and a test
double would confirm whatever its author believed rather than what dpkg does.

```bash
./fleet.sh up            # launch and install
./fleet.sh test          # every scenario on every release
./fleet.sh test 040-upgrade
./fleet.sh shell ubuntu/24.04
./fleet.sh down
./fleet.sh ci            # up, test, down — what the integration workflow runs
```

Needs LXD: `sudo snap install lxd && sudo lxd init --auto`.

| Variable | |
| --- | --- |
| `HOSTSEAL_RELEASES` | Which releases to cover, space-separated. Defaults to all five |
| `HOSTSEAL_VM=0` | Use system containers instead of virtual machines. Faster, and the reboot scenarios then test rather less than they claim to, so they skip |

## The scenarios

| | |
| --- | --- |
| `010-install` | The package installs, the account cannot log in and is not in the `docker` group, the conffiles are root-owned and unwritable by the agent, `trusted-signers` ships empty, the three helper sockets are listening as `root:hostseal 0660` with no sudoers entry beside them, and the helper refuses a restart the local policy does not permit |
| `020-hardening` | The hardening the unit file claims is actually in force, read back from systemd — which silently ignores directives it does not understand — and the agent can write its state and cannot write its policy |
| `030-facts` | The security/regular split, the reboot marker and Ubuntu Pro give the right answer *for this family*. All four of these differences fail quietly rather than loudly, so the answers are checked rather than the absence of an error |
| `040-upgrade` | A locally edited `policy.toml` and `trusted-signers` survive a package upgrade untouched. The second half is a **security** test: an upgrade that reset the trust anchor would re-open every destructive operation an administrator had closed |
| `050-conffile-prompt` | An update run with a changed conffile completes rather than hanging. `DEBIAN_FRONTEND=noninteractive` alone is not enough, and the run that hangs holds the apt lock until somebody notices days later |
| `060-kill-switch` | `/etc/hostseal/paused` and `systemctl stop` both stop the host acting, the agent cannot remove the marker itself, and nothing flips it back on |
| `070-reboot-result` | A job result fsynced to the spool survives a **hard** reset and is still there afterwards. A result that only survives an orderly shutdown is not surviving anything |
| `080-write-capability` | The write capability exists and is bounded by the policy file. The shipped policy refuses every privileged operation; a permissive one permits exactly what it names, and a unit it names is actually restarted; a unit it does not name is still refused; the pause marker outranks both. There are exactly three root helpers, none accepts a program to run, and there is no sudoers entry |

## What is pending

`080-write-capability` was written to *stop passing* when phase 1 began, so that the failure would be
the notification. Phase 1 has begun and it has been rewritten, deliberately and visibly, to assert the
harder half: not that a host can be changed, but that the shipped policy refuses everything, that a
permissive one permits exactly what it names, and that the answer comes from the file rather than from
anything the caller said.

Two operations are still never carried out for real. Applying updates would dist-upgrade the instance
and make every later assertion a measurement of a different machine, so it is exercised through
`--dry-run`, which evaluates the same decision through the same code; `050-conffile-prompt` covers the
dpkg options against real dpkg separately. Rebooting is `070-reboot-result`'s job and is not repeated.

`packages.applySecurity` has no executor yet, and that is not an oversight — it is the one **routine**
intent, and `docs/PROTOCOL.md` §5.1 says an agent MUST NOT execute one until it verifies a signature by
the control plane's online key. No such key exists yet. Every scenario here drives the destructive tier,
whose signature path is complete.

## Why shell

The harness drives real machines over LXD, which is an inherently shell-shaped job, and it may use a
shell freely — `internal/intent`'s source-level check that no shipped code reaches a shell deliberately
excludes this directory. Holding a test harness to that rule would only teach people to add exemptions.
